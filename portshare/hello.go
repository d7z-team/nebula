package portshare

import (
	"time"

	"golang.org/x/crypto/cryptobyte"
)

const (
	helloLimit      = 64 << 10
	classifyTimeout = 2 * time.Second
	maxPending      = 128
)

// offersOnlyALPN inspects the body of one complete ClientHello.
func offersOnlyALPN(body cryptobyte.String, alpn string) bool {
	var field, extensions cryptobyte.String
	if !body.Skip(34) || !body.ReadUint8LengthPrefixed(&field) ||
		!body.ReadUint16LengthPrefixed(&field) || !body.ReadUint8LengthPrefixed(&field) ||
		!body.ReadUint16LengthPrefixed(&extensions) || !body.Empty() {
		return false
	}
	var matched bool
	for !extensions.Empty() {
		var id uint16
		if !extensions.ReadUint16(&id) || !extensions.ReadUint16LengthPrefixed(&field) {
			return false
		}
		if id != 16 { // application_layer_protocol_negotiation
			continue
		}
		var list, name cryptobyte.String
		if matched || !field.ReadUint16LengthPrefixed(&list) || !field.Empty() ||
			!list.ReadUint8LengthPrefixed(&name) || !list.Empty() || string(name) != alpn {
			return false
		}
		matched = true
	}
	return matched
}

// helloSize includes the handshake type and its three-byte length.
func helloSize(header []byte) int { return 4 + int(header[1])<<16 + int(header[2])<<8 + int(header[3]) }
