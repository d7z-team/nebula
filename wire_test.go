package nebula

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestControlFrameBudget(t *testing.T) {
	for _, delta := range []int{-1, 0, 1} {
		var wire bytes.Buffer
		payload := bytes.Repeat([]byte{42}, maxControlFrame+delta)
		require.NoError(t, writeFrame(&wire, payload))
		got, err := readFrame(&wire, maxControlFrame)
		if delta > 0 {
			require.ErrorIs(t, err, errFrameTooLarge)
			require.Equal(t, len(payload), wire.Len())
		} else {
			require.NoError(t, err)
			require.Equal(t, payload, got)
		}
	}
}

func TestWireStreams(t *testing.T) {
	require.Equal(t, []byte{1, 2, 3, 4, 5}, []byte{
		opPing, opHello, opLookup, opCircuit, opIP,
	})
	f := newFixture(t, "tcp", "tcp", "tcp")
	f.link(0, 1)
	f.link(1, 2)
	f.cfg.Members[1].Transit = true
	f.opts[1].MaxIPSize = 1280
	f.start()
	client, relay := f.nodes[0], f.nodes[1]
	require.NoError(t, client.ConnectPeerID(t.Context(), relay.ID()))
	session := client.preferredSession(relay.ID(), true)
	open := func(t *testing.T) net.Conn {
		t.Helper()
		c, err := session.open(t.Context())
		require.NoError(t, err)
		t.Cleanup(func() { c.Close() })
		require.NoError(t, c.SetDeadline(time.Now().Add(4*time.Second)))
		return c
	}
	t.Run("ping", func(t *testing.T) {
		c := open(t)
		_, err := c.Write([]byte{0x01, 0, 0, 0, 3, 'p', '2', 'p'})
		require.NoError(t, err)
		response, err := io.ReadAll(c)
		require.NoError(t, err)
		require.Equal(t, []byte{0, 0, 0, 3, 'p', '2', 'p'}, response)
	})
	t.Run("IP receive limit and stream reuse", func(t *testing.T) {
		packets := make(chan []byte, 2)
		port, err := relay.OpenIPPort(IPPortOptions{Deliver: func(_ PeerID, b []byte) { packets <- bytes.Clone(b) }})
		require.NoError(t, err)
		defer port.Close()
		// The receiver decides at the header, before waiting for any payload.
		overLimit := open(t)
		_, err = overLimit.Write(binary.BigEndian.AppendUint32([]byte{opIP}, uint32(relay.MaxIPSize()+1)))
		require.NoError(t, err)
		_, err = overLimit.Read(make([]byte, 1))
		require.ErrorIs(t, err, io.EOF)
		stats := port.Stats()
		require.EqualValues(t, 1, stats.RejectedInbound)
		require.Equal(t, ErrPacketTooLarge.Error(), stats.LastDrop)

		// A fresh data stream on the same session can carry multiple packets.
		const first = "450000150000000040fd65d00a0d00010a0d000261"
		const second = "450000160000000040fd65cf0a0d00010a0d00026263"
		wire, err := hex.DecodeString("05" + "00000015" + first + "00000016" + second)
		require.NoError(t, err)
		_, err = open(t).Write(wire)
		require.NoError(t, err)
		for _, want := range []string{first, second} {
			select {
			case b := <-packets:
				require.Equal(t, want, hex.EncodeToString(b))
			case <-time.After(3 * time.Second):
				t.Fatal("missing IP frame")
			}
		}
		require.EqualValues(t, 2, port.Stats().ReceivedPackets)
	})
	t.Run("circuit acknowledgement", func(t *testing.T) {
		pathJSON, err := json.Marshal(map[string][]string{"path": {client.ID().String(), relay.ID().String(), f.nodes[2].ID().String()}})
		require.NoError(t, err)
		c := open(t)
		_, err = c.Write([]byte{opCircuit})
		require.NoError(t, err)
		require.NoError(t, writeFrame(c, pathJSON))
		var ack [1]byte
		_, err = io.ReadFull(c, ack[:])
		require.NoError(t, err)
		require.Equal(t, byte(0x01), ack[0])
	})
}

func TestQUICStreamCloseDuringWrite(t *testing.T) {
	f := newFixture(t, "udp", "udp")
	f.start()
	a, b := f.nodes[0], f.nodes[1]
	require.NoError(t, a.ConnectPeerID(t.Context(), b.ID()))
	s := a.preferredSession(b.ID(), true)

	received, resume := make(chan struct{}), make(chan struct{})
	defer close(resume)
	pause := sync.OnceFunc(func() {
		close(received)
		<-resume
	})
	_, err := b.OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) { pause() }})
	require.NoError(t, err)
	c, err := s.open(t.Context())
	require.NoError(t, err)
	// The receiver stops reading after the first frame of this single write.
	// The remaining bytes exceed the initial QUIC stream window.
	var frame bytes.Buffer
	require.NoError(t, writeFrame(&frame, testIPv4(a.Addresses().IPv4, b.Addresses().IPv4, "state")))
	batch := append([]byte{opIP}, bytes.Repeat(frame.Bytes(), (1<<20)/frame.Len())...)
	written := make(chan error, 1)
	go func() {
		_, err := c.Write(batch)
		written <- err
	}()
	select {
	case <-received:
	case <-time.After(3 * time.Second):
		t.Fatal("peer did not receive the first frame")
	}
	require.NoError(t, c.Close())
	select {
	case err := <-written:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("stream close left the writer blocked")
	}

	// A sibling stream on the same connection delivers its final response and FIN.
	payload := []byte("still connected")
	ping, err := s.openRequest(t.Context(), opPing, payload)
	require.NoError(t, err)
	defer ping.Close()
	reply, err := io.ReadAll(ping)
	require.NoError(t, err)
	require.Equal(t, append(binary.BigEndian.AppendUint32(nil, uint32(len(payload))), payload...), reply)
}

func TestWireJSON(t *testing.T) {
	addresses := labAddresses(netip.MustParseAddr("10.13.0.1"))
	id := labPeer(addresses.IPv4)
	expiry := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)
	ep := Endpoint{"udp", netip.MustParseAddrPort("[2001:db8::1]:4242")}
	token := "0123456789abcdef0123456789abcdef"
	intro := introduction{Addresses: addresses, Instance: InstanceID{1}, Endpoints: []Endpoint{ep}, RoutedPrefixes: []netip.Prefix{netip.MustParsePrefix("172.16.1.0/24")}, Expires: expiry}
	q := query{ID: token, IP: addresses.IPv4, Origin: signedIntroduction{0xfb, 0xff}, Visited: []PeerID{id}, Budget: 1234 * time.Millisecond}

	// Compare JSON values without rounding integers or depending on object key order.
	decode := func(t *testing.T, r io.Reader) any {
		t.Helper()
		d := json.NewDecoder(r)
		d.UseNumber()
		var v any
		require.NoError(t, d.Decode(&v))
		return v
	}
	for _, tc := range []struct {
		name  string
		value any
		want  string
	}{
		{
			"hello",
			advert{ep.Address, signedIntroduction{0xfb, 0xff}, 1700000000000000001},
			`{"seen":1700000000000000001,"observed":"[2001:db8::1]:4242","record":"+/8="}`,
		},
		{"empty hello", advert{}, `{"observed":"","record":null}`},
		{"introduction", intro, `{"ipv4":"10.13.0.1","ipv6":"fd42::1","instance":"01000000000000000000000000000000","endpoints":[{"network":"udp","address":"[2001:db8::1]:4242"}],"routedPrefixes":["172.16.1.0/24"],"expires":"2026-01-02T03:04:05.123456789Z"}`},
		{"member introduction", introduction{Addresses: addresses, Instance: InstanceID{1}, Expires: expiry}, `{"ipv4":"10.13.0.1","ipv6":"fd42::1","instance":"01000000000000000000000000000000","endpoints":null,"expires":"2026-01-02T03:04:05.123456789Z"}`},
		{"lookup", q, `{"id":"0123456789abcdef0123456789abcdef","ip":"10.13.0.1","origin":"+/8=","visited":["` + id.String() + `"],"budget":1234000000}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := json.Marshal(tc.value)
			require.NoError(t, err)
			require.Equal(t, decode(t, strings.NewReader(tc.want)), decode(t, bytes.NewReader(got)))
		})
	}
	q.Target = &id
	got, err := json.Marshal(q)
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(got, &fields))
	require.Equal(t, `"`+id.String()+`"`, string(fields["target"]))
}
