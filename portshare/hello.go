package portshare

import (
	"bytes"
	"time"

	"code.d7z.net/d7z-team/nebula/meshwire"

	"golang.org/x/crypto/cryptobyte"
)

const (
	helloLimit      = 64 << 10
	classifyTimeout = 2 * time.Second
	maxPending      = 128
)

// meshHello inspects a complete TLS ClientHello, including its handshake header.
// Classification selects a recipient; TLS still authenticates the original bytes.
func meshHello(b []byte) bool {
	msg := cryptobyte.String(b)
	var body, field, extensions cryptobyte.String
	var typ uint8
	if !msg.ReadUint8(&typ) || typ != 1 || !msg.ReadUint24LengthPrefixed(&body) || !msg.Empty() ||
		!body.Skip(34) || !body.ReadUint8LengthPrefixed(&field) ||
		!body.ReadUint16LengthPrefixed(&field) || !body.ReadUint8LengthPrefixed(&field) ||
		!body.ReadUint16LengthPrefixed(&extensions) || !body.Empty() {
		return false
	}
	var mesh bool
	for !extensions.Empty() {
		var id uint16
		if !extensions.ReadUint16(&id) || !extensions.ReadUint16LengthPrefixed(&field) {
			return false
		}
		if id == 16 {
			var list, name cryptobyte.String
			if mesh || !field.ReadUint16LengthPrefixed(&list) || !field.Empty() ||
				!list.ReadUint8LengthPrefixed(&name) || !list.Empty() || !bytes.Equal(name, []byte(meshwire.ALPN)) {
				return false
			}
			mesh = true
		}
	}
	return mesh
}

// helloSize includes the handshake type and its three-byte length.
func helloSize(header []byte) int { return 4 + int(header[1])<<16 + int(header[2])<<8 + int(header[3]) }
