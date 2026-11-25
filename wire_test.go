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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWireStreams(t *testing.T) {
	require.Equal(t, []byte{1, 2, 3, 4, 5, 6, 7}, []byte{
		opPing, opHello, opLookup, opCircuit, opIP, opPushPublication, opGetPublication,
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
		const pathJSON = `{"path":["10.13.0.1@fd42::1","10.13.0.2@fd42::2","10.13.0.3@fd42::3"]}`
		b, err := json.Marshal(circuitRequest{[]PeerID{client.ID(), relay.ID(), f.nodes[2].ID()}})
		require.NoError(t, err)
		require.JSONEq(t, pathJSON, string(b))
		c := open(t)
		_, err = io.WriteString(c, "\x04\x00\x00\x00\x46"+pathJSON)
		require.NoError(t, err)
		var ack [1]byte
		_, err = io.ReadFull(c, ack[:])
		require.NoError(t, err)
		require.Equal(t, byte(0x01), ack[0])
	})
}

func TestWireJSON(t *testing.T) {
	id := labPeer(netip.MustParseAddr("10.13.0.1"))
	expiry := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)
	ep := Endpoint{"udp", netip.MustParseAddrPort("[2001:db8::1]:4242")}
	token := "0123456789abcdef0123456789abcdef"
	intro := introduction{Instance: InstanceID{1}, Endpoints: []Endpoint{ep}, RoutedPrefixes: []netip.Prefix{netip.MustParsePrefix("172.16.1.0/24")}, Expires: expiry}
	q := query{ID: token, IP: id.IPv4(), Origin: statement{0xfb, 0xff}, Visited: []PeerID{id}, Budget: 1234 * time.Millisecond}
	pub := Publication{id, "app/test", token, []byte{0xfb, 0xff}, expiry}

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
			advert{ep.Address, statement{0xfb, 0xff}, 1700000000000000001, nil},
			`{"seen":1700000000000000001,"inventory":null,"observed":"[2001:db8::1]:4242","record":"+/8="}`,
		},
		{"empty hello", advert{}, `{"observed":"","record":null,"inventory":null}`},
		{"introduction", intro, `{"instance":"01000000000000000000000000000000","endpoints":[{"network":"udp","address":"[2001:db8::1]:4242"}],"routedPrefixes":["172.16.1.0/24"],"expires":"2026-01-02T03:04:05.123456789Z"}`},
		{"member introduction", introduction{Instance: InstanceID{1}, Expires: expiry}, `{"instance":"01000000000000000000000000000000","endpoints":null,"expires":"2026-01-02T03:04:05.123456789Z"}`},
		{"lookup", q, `{"id":"0123456789abcdef0123456789abcdef","ip":"10.13.0.1","origin":"+/8=","visited":["10.13.0.1@fd42::1"],"budget":1234000000}`},
		{"publication", publishedStatement[Publication]{id, pub}, `{"publisher":"10.13.0.1@fd42::1","value":{"origin":"10.13.0.1@fd42::1","topic":"app/test","nonce":"0123456789abcdef0123456789abcdef","payload":"+/8=","expires":"2026-01-02T03:04:05.123456789Z"}}`},
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
	require.Equal(t, `"10.13.0.1@fd42::1"`, string(fields["target"]))
}

func TestWireSessionParameters(t *testing.T) {
	local, remote := InstanceID{1}, InstanceID{2}
	wire := append([]byte{0x05, 0x00}, remote[:]...)
	for _, outgoing := range []bool{false, true} {
		s := session{n: &Node{o: Options{MaxIPSize: 65535}, instance: local}, outgoing: outgoing}
		rw := bytes.NewBuffer(bytes.Clone(wire))
		require.NoError(t, s.exchangeParameters(rw))
		require.Equal(t, remote, s.instance)
		require.Equal(t, 1280, s.remoteIPLimit)
		require.Equal(t, append([]byte{0xff, 0xff}, local[:]...), rw.Bytes())
	}
	for _, invalid := range [][]byte{wire[:17], append([]byte{0xff, 0xff}, make([]byte, 16)...), append([]byte{0, 1}, remote[:]...)} {
		s := session{n: &Node{o: Options{MaxIPSize: 1280}, instance: local}}
		require.Error(t, s.exchangeParameters(bytes.NewBuffer(invalid)))
	}
}
