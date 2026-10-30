package shadowsocks_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	ss "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type packetResponse struct {
	data        []byte
	destination M.Socksaddr
}

type responsePacketConn struct {
	sinkPacketConn
	responses chan packetResponse
}

func (c *responsePacketConn) WritePacket(b *buf.Buffer, destination M.Socksaddr) error {
	packet := packetResponse{append([]byte(nil), b.Bytes()...), destination}
	b.Release()
	c.responses <- packet
	return nil
}

func udpRoundTrip(t *testing.T, f *fixture, ctx context.Context, payload []byte, target, source M.Socksaddr) []byte {
	t.Helper()
	done := make(chan error, 1)
	f.h.onPacket = func(_ context.Context, conn N.PacketConn, _ M.Metadata) error {
		incoming := buf.NewSize(65535)
		defer incoming.Release()
		destination, err := conn.ReadPacket(incoming)
		// The older sing NAT adapter reports EOF for an empty datagram.
		// This fixture exercises the response codec, including empty payloads.
		if err == io.EOF && len(payload) == 0 && incoming.Len() == 0 {
			err = nil
		}
		if err == nil {
			outgoing := buf.NewSize(2048 + incoming.Len() + 64)
			outgoing.Resize(2048, 0)
			outgoing.Write(incoming.Bytes())
			err = conn.WritePacket(outgoing, destination)
		}
		done <- err
		return err
	}
	wire := &memoryConn{}
	client := f.method.DialPacketConn(wire)
	defer client.Close()
	if _, err := client.WriteTo(payload, target); err != nil {
		t.Fatal(err)
	}
	request := buf.NewSize(wire.output.Len())
	request.Write(wire.output.Bytes())
	back := &responsePacketConn{responses: make(chan packetResponse, 1)}
	if err := f.packet.NewPacket(ctx, back, request, M.Metadata{Source: source}); err != nil {
		request.Release()
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("UDP handler failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no UDP response")
	}
	var response packetResponse
	select {
	case response = <-back.responses:
	default:
		t.Fatal("UDP handler returned without a response")
	}
	if response.destination != source {
		t.Fatalf("UDP response destination changed: %s", response.destination)
	}
	wire.input = bytes.NewReader(response.data)
	got := make([]byte, 65535)
	n, address, err := client.ReadFrom(got)
	if err != nil || !bytes.Equal(got[:n], payload) || M.SocksaddrFromNet(address) != target {
		t.Fatalf("UDP response changed payload/address: %d %v", n, err)
	}
	return response.data
}

func TestUDPPaddingNativeCompatibilityAndMTU(t *testing.T) {
	eachFixture(t, func(t *testing.T, base *fixture) {
		name := base.method.Name()
		multi := base.update != nil
		for _, sourceText := range []string{"192.0.2.1:12345", "[2001:db8::1]:12345"} {
			for _, targetText := range []string{"1.1.1.1:443", "[2606:4700:4700::1111]:443", "example.com:443"} {
				for _, size := range []int{0, 1, 127, 1100, 1190, 1200, 1400, 65000} {
					t.Run(fmt.Sprintf("%s/%s/%d", sourceText, targetText, size), func(t *testing.T) {
						f := newFixture(t, name, multi, nil)
						ctx, err := ss.WithServerOptions(context.Background(), ss.ServerOptions{UDPPadding: ss.UDPPaddingOptions{Enabled: true}})
						if err != nil {
							t.Fatal(err)
						}
						source, target := M.ParseSocksaddr(sourceText), M.ParseSocksaddr(targetText)
						payload := bytes.Repeat([]byte{0x5a}, size)
						response := udpRoundTrip(t, f, ctx, payload, target, source)
						if !f.modern {
							want := f.saltLength + 16 + M.SocksaddrSerializer.AddrPortLen(target) + size
							if len(response) != want {
								t.Fatal("legacy AEAD wire format was padded")
							}
							return
						}
						protocolOverhead := 16 + 1 + 8 + 8 + 2 + M.SocksaddrSerializer.AddrPortLen(target) + 16
						if name == "2022-blake3-chacha20-poly1305" {
							protocolOverhead += 24
						}
						padding := len(response) - protocolOverhead - size
						networkOverhead := 48
						if source.Addr.Is4() {
							networkOverhead = 28
						}
						budget := 1280 - networkOverhead - protocolOverhead - size
						if budget <= 0 {
							if padding != 0 {
								t.Fatal("oversized application packet received additional padding")
							}
						} else if padding < 1 || padding > 256 || padding > budget {
							t.Fatalf("padding exceeded IP packet budget: padding=%d budget=%d", padding, budget)
						}
					})
				}
			}
		}
	})
}

func TestUDPPaddingDisabledPreservesDNSPolicy(t *testing.T) {
	for _, port := range []int{53, 443} {
		f := newFixture(t, "2022-blake3-aes-128-gcm", true, nil)
		target := M.ParseSocksaddr(fmt.Sprintf("1.1.1.1:%d", port))
		payload := []byte("legacy policy")
		response := udpRoundTrip(t, f, context.Background(), payload, target, M.ParseSocksaddr("192.0.2.1:12345"))
		overhead := 16 + 1 + 8 + 8 + 2 + 7 + 16
		padding := len(response) - len(payload) - overhead
		if port == 53 && padding <= 0 || port != 53 && padding != 0 {
			t.Fatalf("default DNS policy changed: %d", padding)
		}
	}
}

func TestUDPPaddingCustomBudgetAndLongDomain(t *testing.T) {
	domain := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	target := M.ParseSocksaddr(domain + ":443")
	source := M.ParseSocksaddr("[2001:db8::1]:12345")
	for _, size := range []int{1, 150, 156, 157} {
		f := newFixture(t, "2022-blake3-aes-128-gcm", true, nil)
		ctx, err := ss.WithServerOptions(context.Background(), ss.ServerOptions{UDPPadding: ss.UDPPaddingOptions{Enabled: true, MaxPacketSize: 512, MaxPaddingBytes: 900}})
		if err != nil {
			t.Fatal(err)
		}
		wire := udpRoundTrip(t, f, ctx, bytes.Repeat([]byte{7}, size), target, source)
		baseline := size + 16 + 1 + 8 + 8 + 2 + 257 + 16 + 48
		if baseline >= 512 {
			if len(wire)+48 != baseline {
				t.Fatal("oversized packet was padded")
			}
		} else if len(wire)+48 > 512 || len(wire)+48 <= baseline {
			t.Fatalf("long-domain budget failed: %d", len(wire)+48)
		}
	}
}
