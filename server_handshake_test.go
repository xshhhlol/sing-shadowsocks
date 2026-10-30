package shadowsocks

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-shadowsocks/internal/testutil"
	M "github.com/sagernet/sing/common/metadata"
)

func TestHandshakeAdmissionRejectsBeforeParsing(t *testing.T) {
	if atomic.LoadInt32(&pendingHandshakes) != 0 {
		t.Fatal("previous handshake leaked a slot")
	}
	for i := 0; i < maxPendingHandshakes; i++ {
		if !reserveHandshake() {
			t.Fatal("admission rejected below capacity")
		}
	}
	defer atomic.AddInt32(&pendingHandshakes, -maxPendingHandshakes)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		err = HandleServerConnection(context.Background(), conn, M.Metadata{}, func(func() error) error {
			t.Error("saturated listener parsed a request")
			return nil
		})
		if closer, ok := err.(*ServerConnError); ok {
			closer.Close()
		}
		done <- err
	}()
	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		// An immediate server reset can reach Darwin's dialer before Dial
		// returns. It is the same observable reset as the read path below.
		if !testutil.IsConnectionReset(err) {
			t.Fatal(err)
		}
	} else {
		defer client.Close()
		client.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := client.Read(make([]byte, 1)); !testutil.IsConnectionReset(err) {
			t.Fatalf("overload close differed: %v", err)
		}
	}
	if err := <-done; !errors.Is(err, ErrHandshakeCapacity) {
		t.Fatalf("wrong admission result: %v", err)
	}
}
