package pki_test

import (
	"fmt"
	"net/netip"

	"code.d7z.net/d7z-team/nebula/pki"
)

func ExampleNewPeerID() {
	id, err := pki.NewPeerID(netip.MustParseAddr("10.13.0.1"), netip.MustParseAddr("fd13::1"))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(id)
	// Output: 10.13.0.1@fd13::1
}
