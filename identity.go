package nebula

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"code.d7z.net/d7z-team/nebula/meshwire"
	"code.d7z.net/d7z-team/nebula/pki"
)

// LocalCertificates holds leaf-first chains for clientAuth, serverAuth and codeSigning.
// Empty Server and Object credentials reuse Client.
type LocalCertificates struct{ Client, Server, Object tls.Certificate }

type credentials struct {
	LocalCertificates
	chains [3][]*x509.Certificate
	until  time.Time
}

// ChainCheck describes one PKIX-verified candidate path. Certificates are read-only.
type ChainCheck struct {
	Member PeerID
	Local  bool
	Usage  x509.ExtKeyUsage
	Chain  []*x509.Certificate
}

func prepareCertificates(c LocalCertificates) (*credentials, error) {
	out := &credentials{LocalCertificates: c}
	for i, pair := range []*tls.Certificate{&out.Client, &out.Server, &out.Object} {
		if i != 0 && len(pair.Certificate) == 0 && pair.PrivateKey == nil {
			*pair = out.Client
			out.chains[i] = out.chains[0]
			continue
		}
		pair.Certificate = cloneBytesList(pair.Certificate)
		chain, err := pki.ParseChain(pair.Certificate)
		if err != nil {
			return nil, err
		}
		pair.Leaf = chain[0]
		if !pki.MatchesKey(pair.PrivateKey, pair.Leaf) {
			return nil, errors.New("certificate and private key differ")
		}
		pair.OCSPStaple = bytes.Clone(pair.OCSPStaple)
		pair.SignedCertificateTimestamps = cloneBytesList(pair.SignedCertificateTimestamps)
		pair.SupportedSignatureAlgorithms = slices.Clone(pair.SupportedSignatureAlgorithms)
		out.chains[i] = chain
	}
	// Signed introductions also travel inside JSON discovery frames.
	size := len(out.Object.Leaf.RawIssuer)
	for _, b := range out.Object.Certificate {
		size += len(b)
	}
	if size > 24<<10 {
		return nil, errors.New("object signer chain exceeds frame budget")
	}
	return out, nil
}

func cloneBytesList(list [][]byte) [][]byte {
	out := slices.Clone(list)
	for i, b := range out {
		out[i] = bytes.Clone(b)
	}
	return out
}

func (n *Node) authorizeChain(ctx context.Context, p *topologyView, peer PeerID, chain []*x509.Certificate, usage x509.ExtKeyUsage) (time.Time, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	if _, local := p.members[n.id]; !local || !p.acceptsIdentity(peer) {
		return time.Time{}, ErrPathPolicy
	}
	paths, err := pki.VerifyChain(chain, n.o.Auth.Roots, p.cluster, peer, usage, time.Now())
	if err != nil {
		return time.Time{}, err
	}
	return n.chainDeadline(ctx, ChainCheck{Member: peer, Local: peer == n.id, Usage: usage}, paths)
}

// A hook can shorten a PKIX path's lifetime or deny that particular path.
func (n *Node) chainDeadline(ctx context.Context, check ChainCheck, paths [][]*x509.Certificate) (time.Time, error) {
	var best time.Time
	var denied error
	for _, path := range paths {
		end := path[0].NotAfter
		for _, c := range path {
			if c.NotAfter.Before(end) {
				end = c.NotAfter
			}
		}
		if n.o.Auth.CheckChain != nil {
			check.Chain = path
			limit, err := n.o.Auth.CheckChain(ctx, check)
			if err != nil {
				denied = err
				continue
			}
			if !limit.IsZero() && limit.Before(end) {
				end = limit
			}
		}
		if end.After(best) {
			best = end
		}
	}
	if !time.Now().Before(best) {
		return time.Time{}, errors.Join(ErrPathPolicy, denied, ctx.Err())
	}
	return best, ctx.Err()
}

func (n *Node) credentialDeadline(ctx context.Context, p *topologyView, c *credentials) (time.Time, error) {
	var end time.Time
	for i, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning} {
		d, err := n.authorizeChain(ctx, p, n.id, c.chains[i], usage)
		if err != nil {
			return time.Time{}, err
		}
		if end.IsZero() || d.Before(end) {
			end = d
		}
	}
	return end, nil
}

// ReloadCertificates verifies and atomically installs a complete credential set
// for the same member. An error leaves the current set in place. New handshakes
// and signatures use the new credentials. Paths reports the certificates
// actually used by established sessions.
func (n *Node) ReloadCertificates(ctx context.Context, in LocalCertificates) error {
	c, err := prepareCertificates(in)
	if err != nil {
		return err
	}
	for {
		p := n.policy.Load()
		end, err := n.credentialDeadline(ctx, p, c)
		if err != nil {
			return err
		}
		if err := n.validateIntroduction(p, c.Object); err != nil {
			return err
		}
		n.mu.Lock()
		if n.state == closed || n.ctx.Err() != nil {
			n.mu.Unlock()
			return ErrNodeClosed
		}
		if err := ctx.Err(); err != nil {
			n.mu.Unlock()
			return err
		}
		if n.policy.Load() != p {
			n.mu.Unlock()
			continue
		}
		if !time.Now().Before(end) {
			n.mu.Unlock()
			return ErrPathPolicy
		}
		c.until = end
		n.cred.Store(c)
		n.mu.Unlock()
		return nil
	}
}

func (n *Node) memberOf(p *topologyView) bool {
	if p == nil || p != n.policy.Load() {
		return false
	}
	_, ok := p.members[n.id]
	return ok
}

func (n *Node) ready(p *topologyView) bool {
	return n.memberOf(p) && time.Now().Before(n.cred.Load().until)
}

func handshakeUsages(outgoing bool) (local, remote x509.ExtKeyUsage) {
	if outgoing {
		return x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth
	}
	return x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth
}

func (n *Node) tlsConfig(peer PeerID, server bool) *tls.Config {
	cfg := &tls.Config{
		RootCAs: n.o.Auth.Roots, ClientCAs: n.o.Auth.Roots, ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{meshwire.ALPN}, SessionTicketsDisabled: true, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	}
	if server {
		cfg.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &n.cred.Load().Server, nil }
	} else {
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &n.cred.Load().Client, nil }
		if peer == (PeerID{}) {
			// An endpoint dial learns the certified address pair from the peer.
			// VerifyConnection builds the PKIX chain against our explicit roots.
			cfg.InsecureSkipVerify = true
		} else {
			cfg.ServerName = peer.IPv4().String()
		}
	}
	cfg.VerifyConnection = func(st tls.ConnectionState) error {
		p := n.policy.Load()
		if st.NegotiatedProtocol != meshwire.ALPN || len(st.PeerCertificates) == 0 || !n.memberOf(p) {
			return ErrPathPolicy
		}
		_, usage := handshakeUsages(!server)
		ctx, cancel := context.WithTimeout(n.ctx, n.o.DialTimeout)
		defer cancel()
		var id pki.Identity
		var paths [][]*x509.Certificate
		var err error
		if !server && peer == (PeerID{}) {
			id, err = pki.ReadIdentity(st.PeerCertificates[0])
			if err == nil {
				paths, err = pki.VerifyChain(st.PeerCertificates, n.o.Auth.Roots, p.cluster, id.ID, usage, time.Now())
			}
		} else {
			id, paths, err = pki.VerifiedPeer(st.VerifiedChains, p.cluster, usage)
		}
		if err != nil {
			return err
		}
		if _, err = n.chainDeadline(ctx, ChainCheck{Member: id.ID, Usage: usage}, paths); err != nil {
			return err
		}
		if !p.acceptsIdentity(id.ID) || id.ID == n.id {
			n.mu.Lock()
			if n.policy.Load() == p {
				n.recordObservationLocked(certificateObservation(id.ID, InstanceID{}, st.PeerCertificates[0], usage, "certificate", "address conflict"), nil)
			}
			n.mu.Unlock()
			return ErrPathPolicy
		}
		if peer != (PeerID{}) && peer != id.ID {
			return ErrPathPolicy
		}
		return nil
	}
	return cfg
}

type (
	statement                 []byte
	publishedStatement[T any] struct {
		Publisher PeerID `json:"publisher"`
		Value     T      `json:"value"`
	}
)

func (n *Node) signStatement(kind string, value any, signer tls.Certificate) (statement, error) {
	b, err := n.statementBody(value)
	if err != nil {
		return nil, err
	}
	return pki.SignObject(n.Cluster().Network(), kind, b, signer)
}

func (n *Node) statementBody(value any) ([]byte, error) {
	return json.Marshal(publishedStatement[any]{n.id, value})
}

type statementSigner struct {
	pki.Identity
	leaf *x509.Certificate
}

func (n *Node) verifyStatement(ctx context.Context, kind string, s statement, p *topologyView) (statementSigner, []byte, time.Time, error) {
	var signer statementSigner
	b, chain, err := pki.VerifyObjectSignature(s, p.cluster.Network(), kind)
	if err != nil {
		return signer, nil, time.Time{}, err
	}
	signer.Identity, err = pki.ReadIdentity(chain[0])
	if err != nil {
		return signer, nil, time.Time{}, err
	}
	signer.leaf = chain[0]
	if _, ok := p.members[n.id]; !ok || kind != "introduction" && !p.acceptsIdentity(signer.ID) {
		return signer, nil, time.Time{}, ErrPathPolicy
	}
	paths, err := pki.VerifyChain(chain, n.o.Auth.Roots, p.cluster, signer.ID, x509.ExtKeyUsageCodeSigning, time.Now())
	if err != nil {
		return signer, nil, time.Time{}, err
	}
	end, err := n.chainDeadline(ctx, ChainCheck{Member: signer.ID, Local: kind != "introduction" && signer.ID == n.id, Usage: x509.ExtKeyUsageCodeSigning}, paths)
	if err != nil {
		return signer, nil, time.Time{}, err
	}
	var obj publishedStatement[json.RawMessage]
	if json.Unmarshal(b, &obj) != nil || obj.Publisher != signer.ID {
		return signer, nil, time.Time{}, ErrPathPolicy
	}
	return signer, obj.Value, end, nil
}
