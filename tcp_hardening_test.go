package shadowsocks_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	ss "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/internal/testutil"
	old "github.com/sagernet/sing-shadowsocks/shadowaead"
	modern "github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func TestTCPShapingNativeClientCompatibility(t *testing.T) {
	eachFixture(t, func(t *testing.T, f *fixture) {
		ctx, err := ss.WithServerOptions(context.Background(), ss.ServerOptions{TrafficShaping: ss.TrafficShapingOptions{
			Enabled: true, MinRecordSize: 128, MaxRecordSize: 128, MinRecords: 4, MaxRecords: 4,
		}})
		if err != nil {
			t.Fatal(err)
		}
		f.h.payload = bytes.Repeat([]byte("shaped round trip/"), 5000)
		packet, client, clientWire := f.capture(t, f.h.payload)
		wire := &memoryConn{input: bytes.NewReader(packet)}
		if err := f.service.NewConnection(ctx, wire, M.Metadata{}); err != nil {
			t.Fatal(err)
		}
		clientWire.input = bytes.NewReader(wire.output.Bytes())
		got := make([]byte, len(f.h.payload))
		if _, err := io.ReadFull(client, got); err != nil || !bytes.Equal(got, f.h.payload) {
			t.Fatalf("native client could not decode shaped response: %v", err)
		}
		want := f.saltLength + 128 + 34
		if f.modern {
			want = 2*f.saltLength + 1 + 8 + 2 + 128 + 32
		}
		if wire.writes[0] != want {
			t.Fatalf("initial response was not coalesced/shaped: got %d want %d", wire.writes[0], want)
		}
	})
}

func TestTCPConcurrentFirstResponseAndEmptyWrites(t *testing.T) {
	for _, name := range []string{"aes-128-gcm", "2022-blake3-aes-128-gcm"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, name, true, nil)
			f.h.onConnection = func(conn net.Conn) error {
				if n, err := conn.Write(nil); n != 0 || err != nil {
					return errors.New("empty write failed")
				}
				var wg sync.WaitGroup
				for i := 0; i < 16; i++ {
					wg.Add(1)
					go func(value byte) {
						defer wg.Done()
						payload := bytes.Repeat([]byte{value}, 20000)
						if vector, ok := conn.(interface{ WriteVectorised([]*buf.Buffer) error }); ok && value%2 == 0 {
							part := buf.NewSize(len(payload))
							part.Write(payload)
							if err := vector.WriteVectorised([]*buf.Buffer{buf.New(), part}); err != nil {
								t.Error(err)
							}
						} else if _, err := conn.Write(payload); err != nil {
							t.Error(err)
						}
					}(byte(i))
				}
				wg.Wait()
				return nil
			}
			packet, client, clientWire := f.capture(t, []byte("request"))
			wire := &memoryConn{input: bytes.NewReader(packet)}
			ctx, _ := ss.WithServerOptions(context.Background(), ss.ServerOptions{TrafficShaping: ss.TrafficShapingOptions{Enabled: true}})
			if err := f.service.NewConnection(ctx, wire, M.Metadata{}); err != nil {
				t.Fatal(err)
			}
			clientWire.input = bytes.NewReader(wire.output.Bytes())
			payload := make([]byte, 16*20000)
			if _, err := io.ReadFull(client, payload); err != nil {
				t.Fatal(err)
			}
			seen := make(map[byte]bool)
			for len(payload) > 0 {
				value := payload[0]
				if seen[value] || !bytes.Equal(payload[:20000], bytes.Repeat([]byte{value}, 20000)) {
					t.Fatal("concurrent response writes interleaved")
				}
				seen[value] = true
				payload = payload[20000:]
			}
		})
	}
}

func realTCPFailure(t *testing.T, f *fixture, packet []byte, halfClose bool) {
	t.Helper()
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
		ctx, err := ss.WithServerOptions(context.Background(), ss.ServerOptions{HandshakeTimeout: 150 * time.Millisecond})
		if err == nil {
			err = f.service.NewConnection(ctx, conn, M.Metadata{})
		}
		common.Close(err)
		conn.Close()
		done <- err
	}()
	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	start := time.Now()
	if len(packet) > 0 {
		if _, err := client.Write(packet); err != nil {
			t.Fatal(err)
		}
	}
	if halfClose {
		if err := client.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatal(err)
		}
	}
	n, readErr := client.Read(make([]byte, 128))
	if n != 0 || !testutil.IsConnectionReset(readErr) {
		t.Fatalf("failure produced data or different close behavior: %d %v", n, readErr)
	}
	elapsed := time.Since(start)
	if !halfClose && elapsed < 110*time.Millisecond {
		t.Fatalf("failure exposed an early close after %v", elapsed)
	}
	if elapsed > time.Second {
		t.Fatalf("failure exceeded handshake budget: %v", elapsed)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("unauthenticated connection accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("server did not release failed handshake")
	}
}

func TestRealTCPFailureBehavior(t *testing.T) {
	for _, name := range []string{"aes-128-gcm", "2022-blake3-aes-128-gcm"} {
		t.Run(name, func(t *testing.T) {
			for _, kind := range []string{"empty", "short", "garbage", "bad-fixed", "bad-variable", "truncated", "wrong-password", "replay", "no-users", "half-close-short", "half-close-full"} {
				t.Run(kind, func(t *testing.T) {
					f := newFixture(t, name, true, nil)
					packet, _, _ := f.capture(t, []byte("client payload"))
					switch kind {
					case "empty":
						packet = nil
					case "short", "half-close-short":
						packet = packet[:1]
					case "garbage", "half-close-full":
						packet = bytes.Repeat([]byte{0x8a}, 4096)
					case "bad-fixed":
						packet[f.saltLength] ^= 1
					case "bad-variable":
						packet[len(packet)-1] ^= 1
					case "truncated":
						packet = packet[:len(packet)-1]
					case "wrong-password":
						var err error
						if f.modern {
							f.method, err = modern.New(name, [][]byte{bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{9}, 16)}, nil)
						} else {
							f.method, err = old.New(name, nil, "wrong-password")
						}
						if err != nil {
							t.Fatal(err)
						}
						packet, _, _ = f.capture(t, []byte("wrong password"))
					case "replay":
						if _, err := f.serve(packet); err != nil {
							t.Fatal(err)
						}
					case "no-users":
						if f.modern {
							f.service.(*modern.MultiService[string]).UpdateUsers(nil, nil)
						} else {
							f.service.(*old.MultiService[string]).UpdateUsers(nil, nil)
						}
					}
					realTCPFailure(t, f, packet, kind == "half-close-short" || kind == "half-close-full")
				})
			}
		})
	}
}

func TestRealTCPExpiredTimestamp(t *testing.T) {
	f := newFixture(t, "2022-blake3-aes-128-gcm", true, nil)
	var err error
	f.method, err = modern.New("2022-blake3-aes-128-gcm", [][]byte{bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16)}, func() time.Time { return time.Now().Add(-time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	packet, _, _ := f.capture(t, []byte("stale request"))
	realTCPFailure(t, f, packet, false)
}

func TestRealTCPApplicationOutlivesHandshakeDeadline(t *testing.T) {
	for _, name := range []string{"aes-128-gcm", "2022-blake3-aes-128-gcm"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, name, true, nil)
			f.h.payload = bytes.Repeat([]byte("late application data"), 2000)
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
				ctx, _ := ss.WithServerOptions(context.Background(), ss.ServerOptions{
					HandshakeTimeout: 100 * time.Millisecond, TrafficShaping: ss.TrafficShapingOptions{Enabled: true},
				})
				done <- f.service.NewConnection(ctx, conn, M.Metadata{})
			}()
			conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			client := f.method.DialEarlyConn(conn, M.ParseSocksaddr("example.com:443"))
			if _, err := client.Write(f.h.payload[:1]); err != nil {
				t.Fatal(err)
			}
			time.Sleep(200 * time.Millisecond)
			if _, err := client.Write(f.h.payload[1:]); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(f.h.payload))
			if _, err := io.ReadFull(client, got); err != nil || !bytes.Equal(got, f.h.payload) {
				t.Fatalf("application inherited authentication deadline: %v", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
