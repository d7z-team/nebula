package nebula

import (
	"bytes"
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
	t.Run("two IP packets on one stream", func(t *testing.T) {
		packets := make(chan []byte, 2)
		port, err := relay.OpenIPPort(IPPortOptions{Deliver: func(_ PeerID, b []byte) { packets <- bytes.Clone(b) }})
		require.NoError(t, err)
		defer port.Close()
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
	intro := introduction{[]Endpoint{ep}, []netip.Prefix{netip.MustParsePrefix("172.16.1.0/24")}, expiry}
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
		{"introduction", intro, `{"endpoints":[{"network":"udp","address":"[2001:db8::1]:4242"}],"routedPrefixes":["172.16.1.0/24"],"expires":"2026-01-02T03:04:05.123456789Z"}`},
		{"member introduction", introduction{Expires: expiry}, `{"endpoints":null,"expires":"2026-01-02T03:04:05.123456789Z"}`},
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
