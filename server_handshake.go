package shadowsocks

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

const DefaultHandshakeTimeout = 30 * time.Second

const maxPendingHandshakes = 4096

var (
	pendingHandshakes    int32
	ErrHandshakeCapacity = errors.New("shadowsocks handshake capacity reached")
)

func reserveHandshake() bool {
	for {
		current := atomic.LoadInt32(&pendingHandshakes)
		if current >= maxPendingHandshakes {
			return false
		}
		if atomic.CompareAndSwapInt32(&pendingHandshakes, current, current+1) {
			return true
		}
	}
}

// HandleServerConnection bounds unauthenticated reads. A failed handshake
// drains until the original deadline or peer EOF, rather than closing at a
// cipher-specific byte count. Complete must be called before handing a valid
// stream to the application, so application reads have no handshake deadline.
// Connections without read deadlines retain their previous behavior.
func HandleServerConnection(ctx context.Context, conn net.Conn, metadata M.Metadata, serve func(complete func() error) error) error {
	if !reserveHandshake() {
		return &ServerConnError{Conn: conn, Source: metadata.Source, Cause: ErrHandshakeCapacity}
	}
	held := true
	release := func() {
		if held {
			atomic.AddInt32(&pendingHandshakes, -1)
			held = false
		}
	}
	defer release()
	deadline := time.Now().Add(ServerOptionsFromContext(ctx).HandshakeTimeout)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	bounded := conn.SetReadDeadline(deadline) == nil
	complete := false
	err := serve(func() error {
		if bounded {
			if err := conn.SetReadDeadline(time.Time{}); err != nil {
				return err
			}
		}
		complete = true
		release()
		return nil
	})
	if err != nil {
		if !complete && bounded {
			io.Copy(io.Discard, conn)
		}
		return &ServerConnError{Conn: conn, Source: metadata.Source, Cause: err}
	}
	return nil
}
