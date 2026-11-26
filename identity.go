package nebula

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"code.d7z.net/d7z-team/nebula/pki"
)

// LocalCertificates contains a root-issued TLS identity and its cluster grant.
// Grant is leaf-first, followed by site issuers and the cluster CA.
type LocalCertificates struct {
	Node  tls.Certificate
	Grant [][]byte
}

type credentials struct {
	LocalCertificates
	cmsSigner  tls.Certificate // Grant leaf and membership evidence for CMS.
	grantChain []*x509.Certificate
	identity   pki.Identity
	until      time.Time
}

// CertificatePurpose distinguishes authentication from network authorization.
type CertificatePurpose uint8

const (
	NodeIdentity CertificatePurpose = iota + 1
	ClusterGrant
)

// ChainCheck describes one verified candidate path. Certificates are read-only.
type ChainCheck struct {
	Purpose CertificatePurpose
	Member  PeerID
	Local   bool
	Usage   x509.ExtKeyUsage
	Chain   []*x509.Certificate
}

func prepareCertificates(c LocalCertificates) (*credentials, error) {
	if len(c.Node.Certificate) != 1 {
		return nil, errors.New("one node identity leaf required")
	}
	c.Node.Certificate = cloneBytesList(c.Node.Certificate)
	leaf, err := x509.ParseCertificate(c.Node.Certificate[0])
	if err != nil {
		return nil, err
	}
	c.Node = tls.Certificate{Certificate: c.Node.Certificate, PrivateKey: c.Node.PrivateKey, Leaf: leaf, SupportedSignatureAlgorithms: slices.Clone(c.Node.SupportedSignatureAlgorithms)}
	c.Grant = cloneBytesList(c.Grant)
	chain, err := pki.ParseChain(c.Grant)
	if err != nil {
		return nil, err
	}
	for i := 1; i < len(chain); i++ {
		if err := chain[i-1].CheckSignatureFrom(chain[i]); err != nil {
			return nil, err
		}
	}
	if !pki.MatchesKey(c.Node.PrivateKey, leaf) || !pki.MatchesKey(c.Node.PrivateKey, chain[0]) {
		return nil, errors.New("grant, node and private key must match")
	}
	id, err := pki.ReadIdentity(chain[0])
	if err != nil {
		return nil, err
	}
	signer := tls.Certificate{PrivateKey: c.Node.PrivateKey, Leaf: chain[0], Certificate: slices.Concat(c.Grant, c.Node.Certificate)}
	size := len(chain[0].RawIssuer)
	for _, der := range signer.Certificate {
		size += len(der)
	}
	if size > maxCredentialBytes {
		return nil, errors.New("credential set exceeds frame budget")
	}
	return &credentials{LocalCertificates: c, cmsSigner: signer, grantChain: chain, identity: id}, nil
}

func cloneBytesList(list [][]byte) [][]byte {
	out := slices.Clone(list)
	for i, b := range out {
		out[i] = bytes.Clone(b)
	}
	return out
}

func (n *Node) authorizeGrant(ctx context.Context, p *topologyView, peer PeerID, chain []*x509.Certificate) (time.Time, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	if _, local := p.members[n.id]; !local || peer == (PeerID{}) {
		return time.Time{}, ErrPathPolicy
	}
	paths, err := pki.VerifyGrant(chain, n.roots, p.cluster, peer, time.Now())
	if err != nil {
		return time.Time{}, err
	}
	return n.chainDeadline(ctx, ChainCheck{Purpose: ClusterGrant, Member: peer, Local: peer == n.id, Usage: x509.ExtKeyUsageCodeSigning}, paths)
}

func earlierDeadline(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// A hook can shorten a PKIX path's lifetime or deny that particular path.
func (n *Node) chainDeadline(ctx context.Context, check ChainCheck, paths [][]*x509.Certificate) (time.Time, error) {
	var best time.Time
	var denied error
	for _, path := range paths {
		end := path[0].NotAfter
		for _, c := range path[1:] {
			end = earlierDeadline(c.NotAfter, end)
		}
		if n.o.Auth.CheckChain != nil {
			check.Chain = path
			limit, err := n.o.Auth.CheckChain(ctx, check)
			if err != nil {
				denied = err
				continue
			}
			if !limit.IsZero() {
				end = earlierDeadline(limit, end)
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
	if sha256.Sum256(c.grantChain[len(c.grantChain)-1].Raw) != n.clusterFingerprint || c.identity.ID != n.id || !p.acceptsIdentity(c.identity) {
		return time.Time{}, ErrPathPolicy
	}
	grant, err := n.authorizeGrant(ctx, p, n.id, c.grantChain)
	if err != nil {
		return time.Time{}, err
	}
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth} {
		_, end, err := n.authorizeNode(ctx, c.Node.Leaf, usage, true)
		if err != nil {
			return time.Time{}, err
		}
		grant = earlierDeadline(end, grant)
	}
	return grant, nil
}

func (n *Node) authorizeNode(ctx context.Context, leaf *x509.Certificate, usage x509.ExtKeyUsage, local bool) (PeerID, time.Time, error) {
	id, err := pki.VerifyNode(leaf, n.o.Auth.RootCA, usage, time.Now())
	if err != nil {
		return PeerID{}, time.Time{}, err
	}
	end, err := n.chainDeadline(ctx, ChainCheck{Purpose: NodeIdentity, Member: id, Usage: usage, Local: local}, [][]*x509.Certificate{{leaf, n.o.Auth.RootCA}})
	return id, end, err
}

// memberDeadline verifies the node certificate and grant used by one side of a session.
func (n *Node) memberDeadline(ctx context.Context, p *topologyView, peer PeerID, node *x509.Certificate, grant []*x509.Certificate, usage x509.ExtKeyUsage) (time.Time, error) {
	id, nodeEnd, err := n.authorizeNode(ctx, node, usage, peer == n.id)
	if err != nil || id != peer {
		return time.Time{}, errors.Join(ErrPathPolicy, err)
	}
	grantEnd, err := n.authorizeGrant(ctx, p, peer, grant)
	if err != nil {
		return time.Time{}, err
	}
	return earlierDeadline(nodeEnd, grantEnd), nil
}

// authorizationDeadline uses the credentials actually presented by both sides.
func (s *session) authorizationDeadline(ctx context.Context, p *topologyView) (time.Time, error) {
	if !p.acceptsIdentity(s.localIdentity) {
		return time.Time{}, ErrPathPolicy
	}
	local, remote := handshakeUsages(s.outgoing)
	localEnd, err := s.n.memberDeadline(ctx, p, s.n.id, s.localNode, s.localGrant, local)
	if err != nil {
		return time.Time{}, err
	}
	remoteEnd, err := s.n.memberDeadline(ctx, p, s.peer, s.state.PeerCertificates[0], s.remoteGrant, remote)
	if err != nil {
		return time.Time{}, err
	}
	return earlierDeadline(localEnd, remoteEnd), nil
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
		if err := n.validateIntroduction(p, c); err != nil {
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
	leaf, node *x509.Certificate
}

func (n *Node) verifyStatement(ctx context.Context, kind string, s statement, p *topologyView) (statementSigner, []byte, time.Time, error) {
	var signer statementSigner
	b, chain, err := pki.VerifyObjectSignature(s, p.cluster.Network(), kind)
	if err != nil {
		return signer, nil, time.Time{}, err
	}
	id, nodePath, grantPaths, err := pki.VerifyObjectSigner(chain, n.o.Auth.RootCA, p.cluster, time.Now())
	if err != nil {
		return signer, nil, time.Time{}, err
	}
	signer = statementSigner{id, chain[0], nodePath[0]}
	if _, ok := p.members[n.id]; !ok || kind != "introduction" && !p.acceptsIdentity(id) {
		return signer, nil, time.Time{}, ErrPathPolicy
	}
	check := ChainCheck{Member: id.ID, Local: id.ID == n.id, Purpose: NodeIdentity, Usage: x509.ExtKeyUsageClientAuth}
	nodeEnd, err := n.chainDeadline(ctx, check, [][]*x509.Certificate{nodePath})
	if err != nil {
		return signer, nil, time.Time{}, err
	}
	check.Purpose, check.Usage = ClusterGrant, x509.ExtKeyUsageCodeSigning
	end, err := n.chainDeadline(ctx, check, grantPaths)
	if err != nil {
		return signer, nil, time.Time{}, err
	}
	var obj publishedStatement[json.RawMessage]
	if json.Unmarshal(b, &obj) != nil || obj.Publisher != signer.ID {
		return signer, nil, time.Time{}, ErrPathPolicy
	}
	return signer, obj.Value, earlierDeadline(nodeEnd, end), nil
}
