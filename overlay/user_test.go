package overlay

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/slackhq/nebula/overlay/tio"
	"gvisor.dev/gvisor/pkg/buffer"
)

// newTestUserDevice returns the concrete *UserDevice so tests can reach Pipe()
// and the internal queue plumbing.
func newTestUserDevice(t *testing.T) *UserDevice {
	t.Helper()
	dev, err := NewUserDevice([]netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	if err != nil {
		t.Fatalf("NewUserDevice: %v", err)
	}
	return dev
}

// TestUserDeviceReadersDistinctBuffers ensures each Queue is actually different
func TestUserDeviceReadersDistinctBuffers(t *testing.T) {
	d := newTestUserDevice(t)

	readers, err := d.Queues(2)
	if err != nil {
		t.Fatalf("Queues: %v", err)
	}
	if len(readers) != 2 {
		t.Fatalf("Queues(2) returned %d queues, want 2", len(readers))
	}

	// Distinct queue objects.
	if readers[0] == readers[1] {
		t.Fatal("Queues(2) returned the same queue object twice")
	}

	// Drive one packet through each queue and confirm the borrowed bytes from
	// the first read are NOT clobbered by the second read. With a shared
	// buffer, reading pkt1 into q1 would corrupt q0's still-borrowed slice.
	_, ow := d.Pipe()

	pkt0 := []byte("packet-zero-aaaaaaaa")
	pkt1 := []byte("packet-one-bbbbbbbbb")

	// Serialize: write pkt0 (read on q0), then write pkt1 (read on q1).
	go func() {
		ow <- buffer.NewViewWithData(pkt0)
		ow <- buffer.NewViewWithData(pkt1)
	}()

	got0, err := readers[0].Read()
	if err != nil {
		t.Fatalf("q0.Read: %v", err)
	}
	if len(got0) != 1 || string(got0[0].Bytes) != string(pkt0) {
		t.Fatalf("q0 first read = %q, want %q", firstBytes(got0), pkt0)
	}
	// Hold onto q0's borrowed slice across q1's read.
	borrowed := got0[0].Bytes

	got1, err := readers[1].Read()
	if err != nil {
		t.Fatalf("q1.Read: %v", err)
	}
	if len(got1) != 1 || string(got1[0].Bytes) != string(pkt1) {
		t.Fatalf("q1 read = %q, want %q", firstBytes(got1), pkt1)
	}

	// q0's borrowed bytes must still hold pkt0 - a shared buffer would now
	// show pkt1's contents.
	if string(borrowed) != string(pkt0) {
		t.Fatalf("q0 borrowed bytes were clobbered by q1's read: got %q, want %q", borrowed, pkt0)
	}
}

// TestUserDeviceReadersConcurrentRace exercises two queues reading distinct
// packets concurrently. Run it under `go test -race`: with the old
// shared-buffer implementation the concurrent Reads raced on readBuf/batchRet
// and corrupted each other's returned slices.
func TestUserDeviceReadersConcurrentRace(t *testing.T) {
	d := newTestUserDevice(t)
	readers, err := d.Queues(2)
	if err != nil {
		t.Fatalf("Queues: %v", err)
	}
	_, ow := d.Pipe()

	const iterations = 200

	errs := make(chan error, 3)

	// Each reader parks in Read on the shared outbound channel. We only care that
	// concurrent Reads into distinct buffers are race-free, so any parked
	// reader may serve any packet.
	var wg sync.WaitGroup
	run := func(idx int) {
		defer wg.Done()
		for range iterations {
			pkts, err := readers[idx].Read()
			if err != nil {
				errs <- err
				return
			}
			if len(pkts) != 1 {
				errs <- fmt.Errorf("reader %d: got %d packets, want 1", idx, len(pkts))
				return
			}
			// Touch every byte of the borrowed slice while the other reader
			// may be mid-Read; a shared buffer would race here.
			total := 0
			for _, c := range pkts[0].Bytes {
				total += int(c)
			}
			_ = total
		}
	}

	wg.Add(2)
	go run(0)
	go run(1)

	// Feed 2*iterations packets.
	go func() {
		buf := make([]byte, 32)
		for i := range 2 * iterations {
			for j := range buf {
				buf[j] = byte(i + j)
			}
			ow <- buffer.NewViewWithData(buf)
		}
	}()

	wg.Wait()
	select {
	case err := <-errs:
		t.Fatalf("concurrent reader failed: %v", err)
	default:
	}
}

func firstBytes(p []tio.Packet) []byte {
	if len(p) == 0 {
		return nil
	}
	return p[0].Bytes
}
