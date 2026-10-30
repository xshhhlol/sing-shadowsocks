package shadowaead

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"

	ss "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing/common/buf"
)

type recordingWriter struct {
	bytes.Buffer
	writes []int
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	w.writes = append(w.writes, len(p))
	return w.Buffer.Write(p)
}

func testCipher(t *testing.T) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(bytes.Repeat([]byte{7}, 16))
	if err != nil {
		t.Fatal(err)
	}
	c, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func decodeRecords(t *testing.T, wire []byte) ([]byte, []int) {
	t.Helper()
	c := testCipher(t)
	var payload []byte
	var sizes []int
	var nonce [12]byte
	for len(wire) > 0 {
		if len(wire) < 18 {
			t.Fatal("truncated length")
		}
		binary.LittleEndian.PutUint64(nonce[:], uint64(len(sizes)*2))
		length, err := c.Open(nil, nonce[:], wire[:18], nil)
		if err != nil {
			t.Fatal(err)
		}
		size := int(binary.BigEndian.Uint16(length))
		wire = wire[18:]
		if size == 0 || size > MaxPacketSize || len(wire) < size+16 {
			t.Fatalf("invalid record size %d", size)
		}
		binary.LittleEndian.PutUint64(nonce[:], uint64(len(sizes)*2+1))
		part, err := c.Open(nil, nonce[:], wire[:size+16], nil)
		if err != nil {
			t.Fatal(err)
		}
		payload = append(payload, part...)
		sizes = append(sizes, size)
		wire = wire[size+16:]
	}
	return payload, sizes
}

type finalDataReader struct{ data []byte }

func (r *finalDataReader) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}

func TestWriterShapingAllPaths(t *testing.T) {
	payload := bytes.Repeat([]byte("preserve-order-and-content/"), 3000)
	for _, shaped := range []bool{false, true} {
		for _, path := range []string{"write", "vector", "copy", "buffered"} {
			t.Run(path+map[bool]string{false: "/off", true: "/on"}[shaped], func(t *testing.T) {
				wire := &recordingWriter{}
				w := NewWriter(wire, testCipher(t), MaxPacketSize)
				if err := w.EnableTrafficShaping(ss.TrafficShapingOptions{Enabled: shaped, MinRecordSize: 256, MaxRecordSize: 256, MinRecords: 3, MaxRecords: 3}); err != nil {
					t.Fatal(err)
				}
				prefix := []byte(nil)
				switch path {
				case "write":
					if n, err := w.Write(payload); err != nil || n != len(payload) {
						t.Fatalf("write: %d %v", n, err)
					}
				case "vector":
					var buffers []*buf.Buffer
					for _, part := range [][]byte{payload[:3000], payload[3000:30000], payload[30000:31000], payload[31000:]} {
						b := buf.NewSize(len(part))
						b.Write(part)
						buffers = append(buffers, b)
					}
					if err := w.WriteVectorised(buffers); err != nil {
						t.Fatal(err)
					}
				case "copy":
					if n, err := w.ReadFrom(&finalDataReader{data: payload}); err != nil || n != int64(len(payload)) {
						t.Fatalf("copy lost final data: %d %v", n, err)
					}
				case "buffered":
					prefix = []byte("initial-salt-1234")
					copy(w.buffer, prefix)
					buffered := w.BufferedWriter(len(prefix))
					if n, err := buffered.Write(payload); err != nil || n != len(payload) {
						t.Fatalf("buffered: %d %v", n, err)
					}
					if err := buffered.Flush(); err != nil {
						t.Fatal(err)
					}
				}
				if !bytes.HasPrefix(wire.Bytes(), prefix) {
					t.Fatal("initial salt was not preserved")
				}
				got, sizes := decodeRecords(t, wire.Bytes()[len(prefix):])
				if !bytes.Equal(got, payload) {
					t.Fatal("decrypted data changed order or content")
				}
				if shaped {
					for _, size := range sizes[:3] {
						if size != 256 {
							t.Fatalf("shaping bypassed: %v", sizes)
						}
					}
					if sizes[3] <= 256 {
						t.Fatalf("shaping did not stop at its budget: %v", sizes)
					}
					if path == "buffered" && wire.writes[0] != len(prefix)+256+34 {
						t.Fatal("salt and first record were written separately")
					}
				}
			})
		}
	}
}

type partialWriter struct{ calls int }

func (w *partialWriter) Write(p []byte) (int, error) { w.calls++; return len(p) - 1, nil }

func TestWriterPartialWriteIsTerminal(t *testing.T) {
	for _, path := range []string{"write", "vector", "copy", "buffered"} {
		t.Run(path, func(t *testing.T) {
			wire := &partialWriter{}
			w := NewWriter(wire, testCipher(t), MaxPacketSize)
			var err error
			switch path {
			case "write":
				_, err = w.Write([]byte("payload"))
			case "vector":
				b := buf.New()
				b.WriteString("payload")
				err = w.WriteVectorised([]*buf.Buffer{b})
			case "copy":
				_, err = w.ReadFrom(bytes.NewReader([]byte("payload")))
			case "buffered":
				buffered := w.BufferedWriter(0)
				buffered.Write([]byte("payload"))
				err = buffered.Flush()
			}
			if !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("partial write was hidden: %v", err)
			}
			if _, err = w.Write([]byte("retry")); !errors.Is(err, io.ErrShortWrite) || wire.calls != 1 {
				t.Fatalf("writer retried with advanced nonces: %v, calls %d", err, wire.calls)
			}
		})
	}
}

func TestConcurrentWriterPreservesWholeWrites(t *testing.T) {
	wire := &recordingWriter{}
	w := NewWriter(wire, testCipher(t), MaxPacketSize)
	w.EnableTrafficShaping(ss.TrafficShapingOptions{Enabled: true})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(value byte) {
			defer wg.Done()
			if _, err := w.Write(bytes.Repeat([]byte{value}, 20000)); err != nil {
				t.Error(err)
			}
		}(byte(i))
	}
	wg.Wait()
	got, _ := decodeRecords(t, wire.Bytes())
	seen := make(map[byte]bool)
	for len(got) > 0 {
		if len(got) < 20000 || seen[got[0]] || !bytes.Equal(got[:20000], bytes.Repeat(got[:1], 20000)) {
			t.Fatal("concurrent writes interleaved or corrupted the stream")
		}
		seen[got[0]] = true
		got = got[20000:]
	}
	if len(seen) != 16 {
		t.Fatal("concurrent write was lost")
	}
}

type countWriter struct{ bytes, writes int64 }

func (w *countWriter) Write(p []byte) (int, error) {
	w.bytes += int64(len(p))
	w.writes++
	return len(p), nil
}

func BenchmarkTCPResponseShaping(b *testing.B) {
	payload := bytes.Repeat([]byte{7}, 64*1024)
	block, _ := aes.NewCipher(bytes.Repeat([]byte{1}, 16))
	c, _ := cipher.NewGCM(block)
	for _, shaped := range []bool{false, true} {
		b.Run(map[bool]string{false: "off", true: "on"}[shaped], func(b *testing.B) {
			var wire countWriter
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			for i := 0; i < b.N; i++ {
				w := NewWriter(&wire, c, MaxPacketSize)
				w.EnableTrafficShaping(ss.TrafficShapingOptions{Enabled: shaped})
				if _, err := w.Write(payload); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(wire.bytes)/float64(b.N), "wire-B/op")
			b.ReportMetric(float64(wire.writes)/float64(b.N), "writes/op")
		})
	}
}
