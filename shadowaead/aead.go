package shadowaead

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"sync"

	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

// https://shadowsocks.org/en/wiki/AEAD-Ciphers.html
const (
	MaxPacketSize          = 16*1024 - 1
	PacketLengthBufferSize = 2
)

const (
	// Overhead
	// crypto/cipher.gcmTagSize
	// golang.org/x/crypto/chacha20poly1305.Overhead
	Overhead = 16
)

var ErrPacketTooLarge = E.New("packet too large")

type Reader struct {
	upstream io.Reader
	cipher   cipher.AEAD
	buffer   []byte
	nonce    []byte
	index    int
	cached   int
}

func NewReader(upstream io.Reader, cipher cipher.AEAD, maxPacketSize int) *Reader {
	return &Reader{
		upstream: upstream,
		cipher:   cipher,
		buffer:   make([]byte, maxPacketSize+Overhead),
		nonce:    make([]byte, cipher.NonceSize()),
	}
}

func NewRawReader(upstream io.Reader, cipher cipher.AEAD, buffer []byte, nonce []byte) *Reader {
	return &Reader{
		upstream: upstream,
		cipher:   cipher,
		buffer:   buffer,
		nonce:    nonce,
	}
}

func (r *Reader) Upstream() any {
	return r.upstream
}

func (r *Reader) WriteTo(writer io.Writer) (n int64, err error) {
	if r.cached > 0 {
		writeN, writeErr := writer.Write(r.buffer[r.index : r.index+r.cached])
		if writeErr != nil {
			return int64(writeN), writeErr
		}
		n += int64(writeN)
	}
	for {
		start := PacketLengthBufferSize + Overhead
		_, err = io.ReadFull(r.upstream, r.buffer[:start])
		if err != nil {
			return
		}
		_, err = r.cipher.Open(r.buffer[:0], r.nonce, r.buffer[:start], nil)
		if err != nil {
			return
		}
		increaseNonce(r.nonce)
		length := int(binary.BigEndian.Uint16(r.buffer[:PacketLengthBufferSize]))
		end := length + Overhead
		if end > len(r.buffer) {
			err = ErrPacketTooLarge
			return
		}
		_, err = io.ReadFull(r.upstream, r.buffer[:end])
		if err != nil {
			return
		}
		_, err = r.cipher.Open(r.buffer[:0], r.nonce, r.buffer[:end], nil)
		if err != nil {
			return
		}
		increaseNonce(r.nonce)
		writeN, writeErr := writer.Write(r.buffer[:length])
		if writeErr != nil {
			return int64(writeN), writeErr
		}
		n += int64(writeN)
	}
}

func (r *Reader) readInternal() (err error) {
	start := PacketLengthBufferSize + Overhead
	_, err = io.ReadFull(r.upstream, r.buffer[:start])
	if err != nil {
		return err
	}
	_, err = r.cipher.Open(r.buffer[:0], r.nonce, r.buffer[:start], nil)
	if err != nil {
		return err
	}
	increaseNonce(r.nonce)
	length := int(binary.BigEndian.Uint16(r.buffer[:PacketLengthBufferSize]))
	end := length + Overhead
	if end > len(r.buffer) {
		return ErrPacketTooLarge
	}
	_, err = io.ReadFull(r.upstream, r.buffer[:end])
	if err != nil {
		return err
	}
	_, err = r.cipher.Open(r.buffer[:0], r.nonce, r.buffer[:end], nil)
	if err != nil {
		return err
	}
	increaseNonce(r.nonce)
	r.cached = length
	r.index = 0
	return nil
}

func (r *Reader) ReadByte() (byte, error) {
	if r.cached == 0 {
		err := r.readInternal()
		if err != nil {
			return 0, err
		}
	}
	index := r.index
	r.index++
	r.cached--
	return r.buffer[index], nil
}

func (r *Reader) Read(b []byte) (n int, err error) {
	if r.cached > 0 {
		n = copy(b, r.buffer[r.index:r.index+r.cached])
		r.cached -= n
		r.index += n
		return
	}
	start := PacketLengthBufferSize + Overhead
	_, err = io.ReadFull(r.upstream, r.buffer[:start])
	if err != nil {
		return 0, err
	}
	_, err = r.cipher.Open(r.buffer[:0], r.nonce, r.buffer[:start], nil)
	if err != nil {
		return 0, err
	}
	increaseNonce(r.nonce)
	length := int(binary.BigEndian.Uint16(r.buffer[:PacketLengthBufferSize]))
	end := length + Overhead
	if end > len(r.buffer) {
		return 0, ErrPacketTooLarge
	}

	if len(b) >= end {
		data := b[:end]
		_, err = io.ReadFull(r.upstream, data)
		if err != nil {
			return 0, err
		}
		_, err = r.cipher.Open(b[:0], r.nonce, data, nil)
		if err != nil {
			return 0, err
		}
		increaseNonce(r.nonce)
		return length, nil
	} else {
		_, err = io.ReadFull(r.upstream, r.buffer[:end])
		if err != nil {
			return 0, err
		}
		_, err = r.cipher.Open(r.buffer[:0], r.nonce, r.buffer[:end], nil)
		if err != nil {
			return 0, err
		}
		increaseNonce(r.nonce)
		n = copy(b, r.buffer[:length])
		r.cached = length - n
		r.index = n
		return
	}
}

func (r *Reader) Discard(n int) error {
	for {
		if r.cached >= n {
			r.cached -= n
			r.index += n
			return nil
		} else if r.cached > 0 {
			n -= r.cached
			r.cached = 0
			r.index = 0
		}
		err := r.readInternal()
		if err != nil {
			return err
		}
	}
}

func (r *Reader) Buffer() *buf.Buffer {
	buffer := buf.With(r.buffer)
	buffer.Resize(r.index, r.cached)
	return buffer
}

func (r *Reader) Cached() int {
	return r.cached
}

func (r *Reader) CachedSlice() []byte {
	return r.buffer[r.index : r.index+r.cached]
}

func (r *Reader) ReadWithLengthChunk(lengthChunk []byte) error {
	_, err := r.cipher.Open(r.buffer[:0], r.nonce, lengthChunk, nil)
	if err != nil {
		return err
	}
	increaseNonce(r.nonce)
	length := int(binary.BigEndian.Uint16(r.buffer[:PacketLengthBufferSize]))
	end := length + Overhead
	if end > len(r.buffer) {
		return ErrPacketTooLarge
	}
	_, err = io.ReadFull(r.upstream, r.buffer[:end])
	if err != nil {
		return err
	}
	_, err = r.cipher.Open(r.buffer[:0], r.nonce, r.buffer[:end], nil)
	if err != nil {
		return err
	}
	increaseNonce(r.nonce)
	r.cached = length
	r.index = 0
	return nil
}

func (r *Reader) ReadWithLength(length uint16) error {
	end := int(length) + Overhead
	if end > len(r.buffer) {
		return ErrPacketTooLarge
	}
	_, err := io.ReadFull(r.upstream, r.buffer[:end])
	if err != nil {
		return err
	}
	_, err = r.cipher.Open(r.buffer[:0], r.nonce, r.buffer[:end], nil)
	if err != nil {
		return err
	}
	increaseNonce(r.nonce)
	r.cached = int(length)
	r.index = 0
	return nil
}

func (r *Reader) ReadExternalChunk(chunk []byte) error {
	bb, err := r.cipher.Open(r.buffer[:0], r.nonce, chunk, nil)
	if err != nil {
		return err
	}
	increaseNonce(r.nonce)
	r.cached = len(bb)
	r.index = 0
	return nil
}

func (r *Reader) ReadChunk(buffer *buf.Buffer, chunk []byte) error {
	bb, err := r.cipher.Open(buffer.Index(buffer.Len()), r.nonce, chunk, nil)
	if err != nil {
		return err
	}
	increaseNonce(r.nonce)
	buffer.Extend(len(bb))
	return nil
}

type Writer struct {
	upstream      io.Writer
	cipher        cipher.AEAD
	maxPacketSize int
	buffer        []byte
	nonce         []byte
	access        sync.Mutex
	shaping       shadowsocks.TrafficShapingOptions
	shapingLeft   int
	writeErr      error
}

func NewWriter(upstream io.Writer, cipher cipher.AEAD, maxPacketSize int) *Writer {
	return &Writer{
		upstream:      upstream,
		cipher:        cipher,
		buffer:        make([]byte, maxPacketSize+PacketLengthBufferSize+Overhead*2),
		nonce:         make([]byte, cipher.NonceSize()),
		maxPacketSize: maxPacketSize,
	}
}

func NewRawWriter(upstream io.Writer, cipher cipher.AEAD, maxPacketSize int, buffer []byte, nonce []byte) *Writer {
	return &Writer{
		upstream:      upstream,
		cipher:        cipher,
		maxPacketSize: maxPacketSize,
		buffer:        buffer,
		nonce:         nonce,
	}
}

func (w *Writer) Upstream() any {
	return w.upstream
}

// writeWire is called with access held. A partial encrypted write is fatal:
// advancing the nonce and retrying a whole record would corrupt the stream.
func (w *Writer) writeWire(data []byte) error {
	if w.writeErr != nil {
		return w.writeErr
	}
	n, err := w.upstream.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.writeErr = err
	}
	return err
}

func (w *Writer) encodeRecord(index int, payload []byte) int {
	output := w.buffer[index:]
	binary.BigEndian.PutUint16(output[:PacketLengthBufferSize], uint16(len(payload)))
	w.cipher.Seal(output[:0], w.nonce, output[:PacketLengthBufferSize], nil)
	increaseNonce(w.nonce)
	offset := Overhead + PacketLengthBufferSize
	packet := w.cipher.Seal(output[offset:offset], w.nonce, payload, nil)
	increaseNonce(w.nonce)
	return index + offset + len(packet)
}

func (w *Writer) ReadFrom(r io.Reader) (n int64, err error) {
	payload := buf.NewSize(w.maxPacketSize)
	defer payload.Release()
	empty := 0
	for {
		count, readErr := r.Read(payload.FreeBytes())
		if count > 0 {
			empty = 0
			written, writeErr := w.Write(payload.FreeBytes()[:count])
			n += int64(written)
			if writeErr != nil {
				return n, writeErr
			}
		} else if readErr == nil {
			empty++
			if empty >= 100 {
				return n, io.ErrNoProgress
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				readErr = nil
			}
			return n, readErr
		}
	}
}

func (w *Writer) Write(p []byte) (int, error) {
	w.access.Lock()
	defer w.access.Unlock()
	return w.writePayload(p, nil)
}

// writePayload preserves the initial salt/header and first payload in one
// underlying write. The caller owns access and supplies non-aliasing input.
func (w *Writer) writePayload(p, prefix []byte) (n int, err error) {
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	if len(p) == 0 {
		if len(prefix) > 0 {
			err = w.writeWire(prefix)
		}
		return
	}
	for len(p) > 0 {
		limit := len(w.buffer) - len(prefix) - PacketLengthBufferSize - 2*Overhead
		if limit > len(p) {
			limit = len(p)
		}
		size := w.SelectPayloadSize(limit)
		copy(w.buffer, prefix)
		end := w.encodeRecord(len(prefix), p[:size])
		if err = w.writeWire(w.buffer[:end]); err != nil {
			return
		}
		n += size
		p = p[size:]
		prefix = nil
	}
	return
}

func (w *Writer) WriteVectorised(buffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(buffers)
	w.access.Lock()
	defer w.access.Unlock()
	if w.writeErr != nil {
		return w.writeErr
	}
	index := 0
	flush := func() error {
		if index == 0 {
			return nil
		}
		err := w.writeWire(w.buffer[:index])
		index = 0
		return err
	}
	for _, buffer := range buffers {
		payload := buffer.Bytes()
		for len(payload) > 0 {
			shaped := w.shapingLeft > 0
			size := w.SelectPayloadSize(len(payload))
			if index+size+PacketLengthBufferSize+2*Overhead > len(w.buffer) {
				if err := flush(); err != nil {
					return err
				}
			}
			index = w.encodeRecord(index, payload[:size])
			payload = payload[size:]
			if shaped {
				if err := flush(); err != nil {
					return err
				}
			}
		}
	}
	return flush()
}

func (w *Writer) Buffer() *buf.Buffer {
	return buf.With(w.buffer)
}

func (w *Writer) WriteChunk(buffer *buf.Buffer, chunk []byte) {
	bb := w.cipher.Seal(buffer.Index(buffer.Len()), w.nonce, chunk, nil)
	buffer.Extend(len(bb))
	increaseNonce(w.nonce)
}

func (w *Writer) BufferedWriter(reversed int) *BufferedWriter {
	return &BufferedWriter{
		upstream: w,
		reversed: reversed,
		data:     w.buffer[PacketLengthBufferSize+Overhead : len(w.buffer)-Overhead],
	}
}

type BufferedWriter struct {
	upstream *Writer
	data     []byte
	reversed int
	index    int
}

func (w *BufferedWriter) Write(p []byte) (n int, err error) {
	for {
		cachedN := copy(w.data[w.reversed+w.index:], p[n:])
		w.index += cachedN
		if cachedN == len(p[n:]) {
			n += cachedN
			return
		}
		err = w.Flush()
		if err != nil {
			return
		}
		n += cachedN
	}
}

func (w *BufferedWriter) Flush() error {
	writer := w.upstream
	writer.access.Lock()
	defer writer.access.Unlock()
	if writer.writeErr != nil {
		return writer.writeErr
	}
	if writer.shapingLeft > 0 && w.index > 0 {
		// Buffered plaintext overlaps the output buffer. Preserve it before
		// splitting it into independently authenticated records.
		payload := append([]byte(nil), w.data[w.reversed:w.reversed+w.index]...)
		prefix := append([]byte(nil), writer.buffer[:w.reversed]...)
		_, err := writer.writePayload(payload, prefix)
		w.reversed = 0
		w.index = 0
		return err
	}
	if w.index == 0 {
		if w.reversed > 0 {
			err := writer.writeWire(w.upstream.buffer[:w.reversed])
			w.reversed = 0
			return err
		}
		return nil
	}
	buffer := w.upstream.buffer[w.reversed:]
	binary.BigEndian.PutUint16(buffer[:PacketLengthBufferSize], uint16(w.index))
	w.upstream.cipher.Seal(buffer[:0], w.upstream.nonce, buffer[:PacketLengthBufferSize], nil)
	increaseNonce(w.upstream.nonce)
	offset := Overhead + PacketLengthBufferSize
	packet := w.upstream.cipher.Seal(buffer[offset:offset], w.upstream.nonce, buffer[offset:offset+w.index], nil)
	increaseNonce(w.upstream.nonce)
	err := writer.writeWire(w.upstream.buffer[:w.reversed+offset+len(packet)])
	w.reversed = 0
	w.index = 0
	return err
}

func increaseNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}
