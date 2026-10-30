package shadowaead

import (
	"crypto/sha256"
	"errors"
	"sync"
)

// Traditional AEAD has no timestamp, so finite storage can protect only recent
// salts. Keep exact hashes in a bounded FIFO instead of retaining an unbounded
// history or silently claiming protection across restarts.
const recentSaltCapacity = 65536

var ErrReplay = errors.New("replayed or reflected salt")

type saltHistory struct {
	access sync.Mutex
	seen   map[[32]byte]struct{}
	order  [][32]byte
	next   int
}

func (m *Method) checkSalt(salt []byte, udp bool) bool {
	return m.salts.check(m.key, salt, udp)
}

func (h *saltHistory) check(masterKey, salt []byte, udp bool) bool {
	// Separate TCP and UDP namespaces, but include outgoing salts in the
	// corresponding namespace to reject reflected server responses as well.
	hash := sha256.New()
	if udp {
		hash.Write([]byte{1})
	} else {
		hash.Write([]byte{0})
	}
	hash.Write(masterKey)
	hash.Write(salt)
	var key [32]byte
	hash.Sum(key[:0])
	h.access.Lock()
	defer h.access.Unlock()
	if _, found := h.seen[key]; found {
		return false
	}
	if h.seen == nil {
		h.seen = make(map[[32]byte]struct{})
	}
	if len(h.order) < recentSaltCapacity {
		h.order = append(h.order, key)
	} else {
		delete(h.seen, h.order[h.next])
		h.order[h.next] = key
		h.next = (h.next + 1) % recentSaltCapacity
	}
	h.seen[key] = struct{}{}
	return true
}
