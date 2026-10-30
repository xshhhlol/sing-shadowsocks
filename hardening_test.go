package shadowsocks_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ss "github.com/sagernet/sing-shadowsocks"
	old "github.com/sagernet/sing-shadowsocks/shadowaead"
	modern "github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"lukechampine.com/blake3"
)

type memoryConn struct {
	net.Conn
	input    *bytes.Reader
	output   bytes.Buffer
	deadline time.Time
	writes   []int
}

func (c *memoryConn) Read(p []byte) (int, error) { return c.input.Read(p) }
func (c *memoryConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, len(p))
	return c.output.Write(p)
}
func (c *memoryConn) Close() error                      { return nil }
func (c *memoryConn) SetReadDeadline(t time.Time) error { c.deadline = t; return nil }

type reviewHandler struct {
	accepted     int32
	payload      []byte
	onConnection func(net.Conn) error
	onPacket     func(context.Context, N.PacketConn, M.Metadata) error
}

func (h *reviewHandler) NewConnection(ctx context.Context, c net.Conn, m M.Metadata) error {
	atomic.AddInt32(&h.accepted, 1)
	if h.onConnection != nil {
		return h.onConnection(c)
	}
	if len(h.payload) > 0 {
		got := make([]byte, len(h.payload))
		if _, err := io.ReadFull(c, got); err != nil {
			return err
		}
		if !bytes.Equal(got, h.payload) {
			return errors.New("corrupt request")
		}
		_, err := c.Write(got)
		return err
	}
	return nil
}

func (h *reviewHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	if h.onPacket != nil {
		return h.onPacket(ctx, conn, metadata)
	}
	p := buf.NewPacket()
	defer p.Release()
	_, err := conn.ReadPacket(p)
	return err
}
func (h *reviewHandler) NewError(context.Context, error) {}

type fixture struct {
	method     ss.Method
	service    N.TCPConnectionHandler
	packet     N.UDPHandler
	update     func() error
	h          *reviewHandler
	saltLength int
	modern     bool
}

func newFixture(t *testing.T, name string, multi bool, clock func() time.Time) *fixture {
	t.Helper()
	f := &fixture{h: &reviewHandler{}}
	var err error
	if len(name) > 4 && name[:4] == "2022" {
		f.modern = true
		f.saltLength = 32
		if name == "2022-blake3-aes-128-gcm" {
			f.saltLength = 16
		}
		psk := bytes.Repeat([]byte{1}, f.saltLength)
		user := bytes.Repeat([]byte{2}, f.saltLength)
		if multi {
			s, e := modern.NewMultiService[string](name, psk, 300, f.h, clock)
			err = e
			if err == nil {
				f.update = func() error { return s.UpdateUsers([]string{"user"}, [][]byte{user}) }
				err = f.update()
				f.service = s
				f.packet = s
			}
			f.method, _ = modern.New(name, [][]byte{psk, user}, clock)
		} else {
			var s ss.Service
			s, err = modern.NewService(name, psk, 300, f.h, clock)
			f.service = s
			f.packet = s
			f.method, _ = modern.New(name, [][]byte{psk}, clock)
		}
	} else {
		f.saltLength = 32
		if name == "aes-128-gcm" {
			f.saltLength = 16
		}
		if name == "aes-192-gcm" {
			f.saltLength = 24
		}
		password := "test-only-high-entropy-password"
		if multi {
			s, e := old.NewMultiService[string](name, 300, f.h)
			err = e
			if err == nil {
				f.update = func() error { return s.UpdateUsersWithPasswords([]string{"user"}, []string{password}) }
				err = f.update()
				f.service = s
				f.packet = s
			}
		} else {
			s, e := old.NewService(name, nil, password, 300, f.h)
			err = e
			f.service = s
			f.packet = s
		}
		f.method, _ = old.New(name, nil, password)
	}
	if err != nil {
		t.Fatal(err)
	}
	if f.method == nil {
		t.Fatal("missing client")
	}
	return f
}

func (f *fixture) capture(t *testing.T, payload []byte) ([]byte, net.Conn, *memoryConn) {
	t.Helper()
	wire := &memoryConn{}
	c := f.method.DialEarlyConn(wire, M.ParseSocksaddr("example.com:443"))
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), wire.output.Bytes()...), c, wire
}

func (f *fixture) serve(data []byte) (*memoryConn, error) {
	wire := &memoryConn{input: bytes.NewReader(data)}
	err := f.service.NewConnection(context.Background(), wire, M.Metadata{})
	return wire, err
}

func (f *fixture) isReplay(err error) bool {
	if f.modern {
		return errors.Is(err, modern.ErrSaltNotUnique)
	}
	return errors.Is(err, old.ErrReplay)
}

var methods = []string{"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"}

func eachFixture(t *testing.T, run func(*testing.T, *fixture)) {
	for _, name := range methods {
		for _, multi := range []bool{false, true} {
			if multi && name == "2022-blake3-chacha20-poly1305" {
				continue
			}
			t.Run(fmt.Sprintf("%s/multi=%v", name, multi), func(t *testing.T) { run(t, newFixture(t, name, multi, nil)) })
		}
	}
}

func TestClientCompatibilityAndReplay(t *testing.T) {
	eachFixture(t, func(t *testing.T, f *fixture) {
		payload := bytes.Repeat([]byte("ss compatibility"), 5000)
		f.h.payload = payload
		packet, c, clientWire := f.capture(t, payload)
		serverWire, err := f.serve(packet)
		if err != nil {
			t.Fatal(err)
		}
		if !serverWire.deadline.IsZero() {
			t.Fatal("handshake deadline leaked into application")
		}
		clientWire.input = bytes.NewReader(serverWire.output.Bytes())
		got := make([]byte, len(payload))
		if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(payload, got) {
			t.Fatalf("reply corrupted: %v", err)
		}
		if _, err = f.serve(packet); !f.isReplay(err) {
			t.Fatalf("duplicate accepted or wrong error: %v", err)
		}
		if f.update != nil {
			if err = f.update(); err != nil {
				t.Fatal(err)
			}
			if _, err = f.serve(packet); !f.isReplay(err) {
				t.Fatalf("user refresh erased history: %v", err)
			}
		}
	})
}

func TestInvalidHeaderDoesNotConsumeSalt(t *testing.T) {
	eachFixture(t, func(t *testing.T, f *fixture) {
		for _, variableChunk := range []bool{false, true} {
			packet, _, _ := f.capture(t, []byte("hello"))
			bad := append([]byte(nil), packet...)
			index := f.saltLength
			if variableChunk {
				index = len(bad) - 1
			}
			bad[index] ^= 1
			if _, err := f.serve(bad); err == nil {
				t.Fatal("tampered header accepted")
			}
			if _, err := f.serve(packet); err != nil {
				t.Fatalf("genuine request rejected after tampering at %d: %v", index, err)
			}
		}
	})
}

func TestConcurrentReplaysAcceptOnce(t *testing.T) {
	for _, name := range []string{"aes-128-gcm", "2022-blake3-aes-128-gcm"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, name, true, nil)
			packet, _, _ := f.capture(t, []byte("hello"))
			var wg sync.WaitGroup
			for i := 0; i < 32; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, err := f.serve(packet)
					if err != nil && !f.isReplay(err) {
						t.Errorf("unexpected error: %v", err)
					}
				}()
			}
			wg.Wait()
			if n := atomic.LoadInt32(&f.h.accepted); n != 1 {
				t.Fatalf("accepted %d copies", n)
			}
		})
	}
}

func TestAEADReflectedResponseRejected(t *testing.T) {
	f := newFixture(t, "aes-128-gcm", true, nil)
	// The reflected payload is itself a valid destination, so address parsing
	// alone cannot reject it. The server must recognize its outgoing salt.
	f.h.payload = append([]byte{1, 127, 0, 0, 1, 0, 80}, []byte("reflected")...)
	packet, _, _ := f.capture(t, f.h.payload)
	wire, err := f.serve(packet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.serve(wire.output.Bytes()); !f.isReplay(err) {
		t.Fatalf("reflected response: %v", err)
	}
}

func TestFailedHandshakeUsesOriginalDeadline(t *testing.T) {
	for _, name := range []string{"aes-128-gcm", "2022-blake3-aes-128-gcm"} {
		for _, size := range []int{1, 34, 50, 128} {
			t.Run(fmt.Sprintf("%s/%d", name, size), func(t *testing.T) {
				f := newFixture(t, name, true, nil)
				server, client := net.Pipe()
				defer server.Close()
				defer client.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
				done := make(chan error, 1)
				start := time.Now()
				go func() { done <- f.service.NewConnection(ctx, server, M.Metadata{}) }()
				go client.Write(bytes.Repeat([]byte{0x83}, size))
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("probe accepted")
					}
					if elapsed := time.Since(start); elapsed < 70*time.Millisecond || elapsed > 500*time.Millisecond {
						t.Fatalf("failure after %v", elapsed)
					}
				case <-time.After(time.Second):
					t.Fatal("handshake unbounded")
				}
			})
		}
	}
}

type sinkPacketConn struct{ N.PacketConn }

func (c *sinkPacketConn) WritePacket(b *buf.Buffer, _ M.Socksaddr) error { b.Release(); return nil }
func (c *sinkPacketConn) Close() error                                   { return nil }
func (f *fixture) servePacket(packet []byte) error {
	b := buf.NewSize(len(packet))
	b.Write(packet)
	err := f.packet.NewPacket(context.Background(), &sinkPacketConn{}, b, M.Metadata{Source: M.ParseSocksaddr("192.0.2.1:12345")})
	if err != nil {
		b.Release()
	}
	return err
}

func packetBytes(t *testing.T, c N.NetPacketConn, wire *memoryConn) []byte {
	t.Helper()
	wire.output.Reset()
	if _, err := c.WriteTo([]byte("udp payload"), M.ParseSocksaddr("1.1.1.1:53").UDPAddr()); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), wire.output.Bytes()...)
}

func TestUDPSaltReplay(t *testing.T) {
	eachFixture(t, func(t *testing.T, f *fixture) {
		wire := &memoryConn{}
		c := f.method.DialPacketConn(wire)
		defer c.Close()
		packet := packetBytes(t, c, wire)
		if err := f.servePacket(packet); err != nil {
			t.Fatal(err)
		}
		if err := f.servePacket(packet); err == nil {
			t.Fatal("UDP duplicate accepted")
		}
	})
}

func TestSS2022InvalidTimestampDoesNotAdvanceWindow(t *testing.T) {
	for _, multi := range []bool{false, true} {
		t.Run(fmt.Sprint(multi), func(t *testing.T) {
			var delta int64
			base := time.Now()
			serverClock := func() time.Time { return base.Add(time.Duration(atomic.LoadInt64(&delta)) * time.Second) }
			f := newFixture(t, "2022-blake3-aes-128-gcm", multi, serverClock)
			psk := bytes.Repeat([]byte{1}, 16)
			keys := [][]byte{psk}
			if multi {
				keys = append(keys, bytes.Repeat([]byte{2}, 16))
			}
			method, err := modern.New("2022-blake3-aes-128-gcm", keys, func() time.Time { return base })
			if err != nil {
				t.Fatal(err)
			}
			wire := &memoryConn{}
			c := method.DialPacketConn(wire)
			defer c.Close()
			if err = f.servePacket(packetBytes(t, c, wire)); err != nil {
				t.Fatal(err)
			}
			packet := packetBytes(t, c, wire)
			atomic.StoreInt64(&delta, 40)
			if err = f.servePacket(packet); !errors.Is(err, modern.ErrBadTimestamp) {
				t.Fatalf("stale packet: %v", err)
			}
			atomic.StoreInt64(&delta, 0)
			if err = f.servePacket(packet); err != nil {
				t.Fatalf("unvalidated packet poisoned window: %v", err)
			}
		})
	}
}

func TestSS2022UDPSessionCannotChangeIdentity(t *testing.T) {
	f := newFixture(t, "2022-blake3-aes-128-gcm", true, nil)
	otherKey := bytes.Repeat([]byte{3}, 16)
	s := f.service.(*modern.MultiService[string])
	if err := s.UpdateUsers([]string{"user", "other"}, [][]byte{bytes.Repeat([]byte{2}, 16), otherKey}); err != nil {
		t.Fatal(err)
	}
	wire := &memoryConn{}
	c := f.method.DialPacketConn(wire)
	defer c.Close()
	if err := f.servePacket(packetBytes(t, c, wire)); err != nil {
		t.Fatal(err)
	}
	packet := packetBytes(t, c, wire)
	changed := append([]byte(nil), packet...)
	block, _ := aes.NewCipher(bytes.Repeat([]byte{1}, 16))
	var header [16]byte
	block.Decrypt(header[:], changed[:16])
	hash := blake3.Sum512(otherKey)
	for i := range header {
		header[i] ^= hash[i]
	}
	block.Encrypt(changed[16:32], header[:])
	if err := f.servePacket(changed); err == nil {
		t.Fatal("another user's identity selected the cached session cipher")
	}
	if err := f.servePacket(packet); err != nil {
		t.Fatalf("identity mismatch poisoned the genuine session: %v", err)
	}
}

type identityPacketHandler struct {
	reviewHandler
	users chan string
	done  chan struct{}
}

func (h *identityPacketHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, _ M.Metadata) error {
	p := buf.NewPacket()
	defer p.Release()
	if _, err := conn.ReadPacket(p); err != nil {
		return err
	}
	user, _ := auth.UserFromContext[string](ctx)
	h.users <- user
	<-h.done
	return nil
}

func TestAEADUDPSourceReuseKeepsUserIdentity(t *testing.T) {
	h := &identityPacketHandler{users: make(chan string, 2), done: make(chan struct{})}
	defer close(h.done)
	s, err := old.NewMultiService[string]("aes-128-gcm", 300, h)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateUsersWithPasswords([]string{"first", "second"}, []string{"first-password", "second-password"}); err != nil {
		t.Fatal(err)
	}
	f := &fixture{packet: s}
	for _, test := range []struct{ user, password string }{{"first", "first-password"}, {"second", "second-password"}, {"first", "rotated-password"}} {
		if test.password == "rotated-password" {
			if err := s.UpdateUsersWithPasswords([]string{"first", "second"}, []string{test.password, "second-password"}); err != nil {
				t.Fatal(err)
			}
		}
		method, err := old.New("aes-128-gcm", nil, test.password)
		if err != nil {
			t.Fatal(err)
		}
		wire := &memoryConn{}
		c := method.DialPacketConn(wire)
		defer c.Close()
		if err := f.servePacket(packetBytes(t, c, wire)); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-h.users:
			if got != test.user {
				t.Fatalf("UDP user changed: got %s, want %s", got, test.user)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s reused a UDP association with a different identity or key", test.user)
		}
	}
}
