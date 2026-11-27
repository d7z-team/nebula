package nebula

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"time"

	"gopkg.d7z.net/nebula/pki"
)

type credentialContextKey struct{}

const (
	maxCredentialBytes = 24 << 10
	grantHeaderBytes   = 2 + len(InstanceID{})
)

func handshakeUsages(outgoing bool) (local, remote x509.ExtKeyUsage) {
	if outgoing {
		return x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth
	}
	return x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth
}

func (n *Node) tlsConfig(peer PeerID, outgoing bool, c *credentials) *tls.Config {
	cfg := &tls.Config{
		RootCAs: n.roots, ClientCAs: n.roots, ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{n.o.Transport.ALPN}, CurvePreferences: n.o.Transport.CurvePreferences,
		SessionTicketsDisabled: true,
	}
	if c != nil {
		cfg.Certificates = []tls.Certificate{c.Node}
	} else {
		cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			snapshot, ok := hello.Context().Value(credentialContextKey{}).(*credentials)
			if !ok {
				return nil, ErrPathPolicy
			}
			return n.tlsConfig(peer, false, snapshot), nil
		}
	}
	// The node profile uses an explicit root and public key rather than a DNS name.
	cfg.InsecureSkipVerify = outgoing
	cfg.VerifyConnection = func(st tls.ConnectionState) error {
		if st.NegotiatedProtocol != n.o.Transport.ALPN || len(st.PeerCertificates) != 1 || !n.ready(n.policy.Load()) {
			return ErrPathPolicy
		}
		_, usage := handshakeUsages(outgoing)
		ctx, cancel := context.WithTimeout(n.ctx, n.o.DialTimeout)
		defer cancel()
		id, _, err := n.authorizeNode(ctx, st.PeerCertificates[0], usage, false)
		if err != nil {
			return err
		}
		if id == n.id || peer != (PeerID{}) && peer != id {
			return ErrPathPolicy
		}
		n.mu.Lock()
		blocked := n.modeLocked(id) == Blocked
		n.mu.Unlock()
		if blocked {
			return ErrPathPolicy
		}
		return nil
	}
	return cfg
}

// writeGrant registers the disclosure under the same lock that commits a policy review.
func (s *session) writeGrant(ctx context.Context, w io.Writer, local *credentials) error {
	n := s.n
	_, usage := handshakeUsages(s.outgoing)
	var done chan struct{}
	for {
		p := n.policy.Load()
		until, err := n.credentialDeadline(ctx, p, local)
		if err != nil {
			return err
		}
		var remoteEnd time.Time
		leaf := s.state.PeerCertificates[0]
		if s.outgoing {
			_, remoteEnd, err = n.authorizeNode(ctx, leaf, usage, false)
		} else {
			remoteEnd, err = n.memberDeadline(ctx, p, s.peer, leaf, s.remoteGrant, usage)
		}
		if err != nil {
			return err
		}
		until = earlierDeadline(remoteEnd, until)
		n.mu.Lock()
		if p != n.policy.Load() {
			n.mu.Unlock()
			continue
		}
		now := time.Now()
		allowed := now.Before(until) && n.state == running && n.pathAllowedLocked(s)
		if s.outgoing {
			_, configured := p.members[s.peer]
			allowed = allowed && (configured || slices.Contains(n.o.Auth.TrustedEntrypoints, s.peer) || now.Before(n.discovered[s.peer].authorizedUntil))
		} else if n.addressConflictLocked(s.remoteIdentity) {
			n.recordObservationLocked(s.observation("address conflict"), nil)
			allowed = false
		}
		if !allowed {
			n.mu.Unlock()
			return ErrPathPolicy
		}
		done = make(chan struct{})
		n.grantWrites[done] = struct{}{}
		n.mu.Unlock()
		break
	}
	defer func() {
		n.mu.Lock()
		delete(n.grantWrites, done)
		close(done)
		n.mu.Unlock()
	}()
	size := grantHeaderBytes
	for _, der := range local.Grant {
		size += len(der)
	}
	body := make([]byte, grantHeaderBytes, size)
	binary.BigEndian.PutUint16(body, uint16(n.o.MaxIPSize))
	copy(body[2:], n.instance[:])
	for _, der := range local.Grant {
		body = append(body, der...)
	}
	return writeFrame(w, body)
}

// Both roles confirm the pinned cluster on this TLS connection before exchanging grants.
// The exporter is a scope check. Only the verified grant establishes membership.
func (s *session) exchangeGrants(ctx context.Context, c io.ReadWriter, local *credentials) error {
	if len(s.state.PeerCertificates) != 1 {
		return ErrPathPolicy
	}
	id, err := pki.NewPeerID(s.state.PeerCertificates[0].PublicKey)
	if err != nil || id == s.n.id || s.peer != (PeerID{}) && s.peer != id {
		return ErrPathPolicy
	}
	s.peer = id
	s.localGrant, s.localNode, s.localIdentity = local.grantChain, local.Node.Leaf, local.identity
	tags, err := s.state.ExportKeyingMaterial("EXPORTER-nebula-cluster", s.n.clusterFingerprint[:], 64)
	if err != nil {
		return err
	}
	tx, rx := tags[:32], tags[32:]
	if s.outgoing {
		if _, err = c.Write(tx); err != nil {
			return err
		}
	} else {
		tx, rx = rx, tx
	}
	var token [32]byte
	if _, err = io.ReadFull(c, token[:]); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(token[:], rx) != 1 {
		return ErrPathPolicy
	}
	if s.outgoing {
		if err := s.writeGrant(ctx, c, local); err != nil {
			return err
		}
	} else if _, err = c.Write(tx); err != nil {
		return err
	}
	body, err := readFrame(c, maxCredentialBytes+grantHeaderBytes)
	if err != nil {
		return err
	}
	if len(body) <= grantHeaderBytes {
		return errors.New("missing session grant")
	}
	s.remoteIPLimit = int(binary.BigEndian.Uint16(body))
	copy(s.instance[:], body[2:grantHeaderBytes])
	if s.remoteIPLimit < 1280 || s.instance == (InstanceID{}) {
		return errors.New("invalid session parameters")
	}
	s.remoteGrant, err = x509.ParseCertificates(body[grantHeaderBytes:])
	if err != nil {
		return err
	}
	s.remoteIdentity, err = pki.ReadIdentity(s.remoteGrant[0])
	if err != nil || s.remoteIdentity.ID != id {
		return errors.Join(ErrPathPolicy, err)
	}
	if !s.outgoing {
		return s.writeGrant(ctx, c, local)
	}
	return nil
}
