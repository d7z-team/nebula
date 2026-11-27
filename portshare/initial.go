package portshare

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/quic-go/quic-go/quicvarint"
)

var (
	errInitial  = errors.New("invalid QUIC v1 Initial")
	errAssembly = errors.New("invalid ClientHello assembly")
)

// RFC 9001 sections 5.2-5.4. Initial keys are public and only identify valid
// Initial packets. All subsequent encryption levels belong to the endpoints.
type initialKeys struct {
	header  cipher.Block
	payload cipher.AEAD
	iv      []byte
	largest int64
}

func clientInitialKeys(dcid []byte) (keys initialKeys, err error) {
	fips140.WithoutEnforcement(func() {
		salt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
		var secret []byte
		secret, err = hkdf.Extract(sha256.New, dcid, salt)
		if err != nil {
			return
		}
		expand := func(label string, size int) []byte {
			if err != nil {
				return nil
			}
			label = "tls13 " + label
			info := append([]byte{0, byte(size), byte(len(label))}, label...)
			var out []byte
			out, err = hkdf.Expand(sha256.New, secret, string(append(info, 0)), size)
			return out
		}
		secret = expand("client in", 32)
		key, hp := expand("quic key", 16), expand("quic hp", 16)
		keys.iv = expand("quic iv", 12)
		if err != nil {
			return
		}
		keys.header, err = aes.NewCipher(hp)
		if err != nil {
			return
		}
		var block cipher.Block
		block, err = aes.NewCipher(key)
		if err != nil {
			return
		}
		keys.payload, err = cipher.NewGCM(block)
		keys.largest = -1
	})
	return keys, err
}

type varints []byte

func (b *varints) next() (uint64, error) {
	v, n, err := quicvarint.Parse(*b)
	if err == nil {
		*b = (*b)[n:]
	}
	return v, err
}

func (b *varints) take(n uint64) ([]byte, error) {
	if n > uint64(len(*b)) {
		return nil, errInitial
	}
	v := (*b)[:n]
	*b = (*b)[n:]
	return v, nil
}

// readInitial extracts CRYPTO from coalesced client Initials. It never edits a datagram.
func (k *initialKeys) readInitial(b, dcid []byte, consume func(uint64, []byte) error) error {
	parsed := false
	for len(b) > 0 && b[0]&0xf0 == 0xc0 {
		plain, rest, err := k.openInitial(b, dcid)
		if err != nil {
			// A malformed trailing packet cannot reroute an earlier valid Initial.
			if parsed && errors.Is(err, errInitial) {
				break
			}
			return err
		}
		if err := initialFrames(plain, consume); err != nil {
			return err
		}
		parsed = true
		b = rest
	}
	return nil
}

func (k *initialKeys) openInitial(b, dcid []byte) ([]byte, []byte, error) {
	if len(b) < 7+len(dcid) || binary.BigEndian.Uint32(b[1:5]) != 1 ||
		int(b[5]) != len(dcid) || !bytes.Equal(b[6:6+len(dcid)], dcid) {
		return nil, nil, errInitial
	}
	scid := int(b[6+len(dcid)])
	pos := 7 + len(dcid) + scid
	if scid > 20 || pos > len(b) {
		return nil, nil, errInitial
	}
	fields := varints(b[pos:])
	n, e := fields.next()
	if e != nil {
		return nil, nil, errInitial
	}
	if _, e = fields.take(n); e != nil {
		return nil, nil, e
	}
	n, e = fields.next()
	if e != nil {
		return nil, nil, errInitial
	}
	offset := len(b) - len(fields)
	packet, e := fields.take(n)
	if e != nil || len(packet) < 20 {
		return nil, nil, errInitial
	}
	var mask [16]byte
	k.header.Encrypt(mask[:], packet[4:20])
	first := b[0] ^ mask[0]&0x0f
	pnLen := int(first&3) + 1
	ad := make([]byte, offset+pnLen)
	copy(ad, b)
	ad[0] = first
	var pn int64
	for i := range pnLen {
		ad[offset+i] ^= mask[1+i]
		pn = pn<<8 | int64(ad[offset+i])
	}
	window := int64(1) << (8 * pnLen)
	expected := k.largest + 1
	pn = expected & ^(window-1) | pn
	switch {
	case pn <= expected-window/2 && pn < (1<<62)-window:
		pn += window
	case pn > expected+window/2 && pn >= window:
		pn -= window
	}
	nonce := [12]byte(k.iv)
	binary.BigEndian.PutUint64(nonce[4:], binary.BigEndian.Uint64(nonce[4:])^uint64(pn))
	plain, e := k.payload.Open(nil, nonce[:], packet[pnLen:], ad)
	if e != nil {
		return nil, nil, errInitial
	}
	if first&0x0c != 0 {
		return nil, nil, errAssembly
	}
	k.largest = max(k.largest, pn)
	return plain, fields, nil
}

func initialFrames(payload varints, consume func(uint64, []byte) error) error {
	for len(payload) > 0 {
		kind, e := payload.next()
		if e != nil {
			return errAssembly
		}
		switch kind {
		case 0, 1: // PADDING, PING
		case 2, 3: // ACK, ACK_ECN
			var ranges uint64
			for i := range 4 {
				v, e := payload.next()
				if e != nil {
					return errAssembly
				}
				if i == 2 {
					ranges = v
				}
			}
			fields := 2 * ranges
			if kind == 3 {
				fields += 3
			}
			if fields > uint64(len(payload)) {
				return errAssembly
			}
			for range fields {
				if _, e := payload.next(); e != nil {
					return errAssembly
				}
			}
		case 6: // CRYPTO
			offset, e := payload.next()
			if e != nil {
				return errAssembly
			}
			n, e := payload.next()
			if e != nil {
				return errAssembly
			}
			data, e := payload.take(n)
			if e != nil {
				return errAssembly
			}
			if e = consume(offset, data); e != nil {
				return e
			}
		case 0x1c: // transport CONNECTION_CLOSE
			for range 2 {
				if _, e := payload.next(); e != nil {
					return errAssembly
				}
			}
			n, e := payload.next()
			if e != nil {
				return errAssembly
			}
			if _, e = payload.take(n); e != nil {
				return errAssembly
			}
		default:
			return errAssembly
		}
	}
	return nil
}
