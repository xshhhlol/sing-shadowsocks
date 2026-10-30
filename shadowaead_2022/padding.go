package shadowaead_2022

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/sagernet/sing-shadowsocks/shadowaead"
	M "github.com/sagernet/sing/common/metadata"
)

func (w *serverPacketWriter) paddingLength(payloadSize int, destination M.Socksaddr) int {
	// Budget the actual back-writer's client address, not the proxied target.
	// Unknown/domain addresses use the conservative IPv6 base-header cost.
	networkOverhead := 40 + 8
	if M.SocksaddrFromNet(w.nat.LocalAddr()).Addr.Is4() {
		networkOverhead = 20 + 8
	}
	overhead := 16 + 1 + 8 + 8 + 2 + M.SocksaddrSerializer.AddrPortLen(destination) + shadowaead.Overhead
	if w.udpCipher != nil {
		overhead += PacketNonceSize
	}
	limit := w.padding.MaxPacketSize - networkOverhead - overhead - payloadSize
	if limit > w.padding.MaxPaddingBytes {
		limit = w.padding.MaxPaddingBytes
	}
	if limit <= 0 {
		return 0
	}
	var random [4]byte
	if _, err := rand.Read(random[:]); err != nil {
		return 0
	}
	return 1 + int(uint64(binary.LittleEndian.Uint32(random[:]))%uint64(limit))
}
