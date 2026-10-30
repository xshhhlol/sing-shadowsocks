package shadowaead_2022

import (
	"bytes"
	"net"
	"testing"

	ss "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type discardPacketConn struct {
	N.PacketConn
	bytes int64
}

func (c *discardPacketConn) WritePacket(p *buf.Buffer, _ M.Socksaddr) error {
	c.bytes += int64(p.Len())
	p.Release()
	return nil
}

func (c *discardPacketConn) LocalAddr() net.Addr {
	return M.ParseSocksaddr("192.0.2.1:12345").UDPAddr()
}

func BenchmarkUDPResponsePadding(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		b.Run(map[bool]string{false: "off", true: "on"}[enabled], func(b *testing.B) {
			service, err := NewService("2022-blake3-aes-128-gcm", bytes.Repeat([]byte{1}, 16), 300, nil, nil)
			if err != nil {
				b.Fatal(err)
			}
			s := service.(*Service)
			wire := &discardPacketConn{}
			padding, err := ss.NormalizeUDPPadding(ss.UDPPaddingOptions{Enabled: enabled})
			if err != nil {
				b.Fatal(err)
			}
			w := &serverPacketWriter{s, wire, wire, s.newUDPSession(), s.udpBlockCipher, padding}
			payload := bytes.Repeat([]byte{7}, 128)
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				p := buf.NewSize(w.FrontHeadroom() + len(payload) + w.RearHeadroom())
				p.Resize(w.FrontHeadroom(), 0)
				p.Write(payload)
				if err := w.WritePacket(p, M.ParseSocksaddr("1.1.1.1:443")); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(wire.bytes)/float64(b.N), "wire-B/op")
		})
	}
}
