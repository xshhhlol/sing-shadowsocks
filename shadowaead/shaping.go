package shadowaead

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/sagernet/sing-shadowsocks"
)

// EnableTrafficShaping must be called before a writer is used. A finite record
// budget limits the cost; no dummy application bytes or sleeps are introduced.
func (w *Writer) EnableTrafficShaping(options shadowsocks.TrafficShapingOptions) error {
	options, err := shadowsocks.NormalizeTrafficShaping(options)
	if err != nil {
		return err
	}
	w.shaping = options
	w.shapingLeft = 0
	if options.Enabled {
		w.shapingLeft = randomRange(options.MinRecords, options.MaxRecords)
	}
	return nil
}

// SelectPayloadSize reserves one record from the shaping budget. SS2022 uses
// this for its first payload, whose length is encoded in the response header.
// Calls must be serialized with writes, or made before publishing the writer.
func (w *Writer) SelectPayloadSize(available int) int {
	if available > w.maxPacketSize {
		available = w.maxPacketSize
	}
	if available > 0 && w.shapingLeft > 0 {
		w.shapingLeft--
		size := randomRange(w.shaping.MinRecordSize, w.shaping.MaxRecordSize)
		if available > size {
			available = size
		}
	}
	return available
}

func randomRange(min, max int) int {
	if min == max {
		return min
	}
	var value [4]byte
	if _, err := rand.Read(value[:]); err != nil {
		// Shaping randomness is not key material. Preserve availability on an
		// entropy failure; cryptographic salts still use their existing source.
		return min
	}
	return min + int(uint64(binary.LittleEndian.Uint32(value[:]))%uint64(max-min+1))
}
