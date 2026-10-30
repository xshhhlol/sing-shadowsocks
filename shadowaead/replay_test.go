package shadowaead

import (
	"encoding/binary"
	"testing"
)

func TestSaltHistoryBoundedAndScoped(t *testing.T) {
	var h saltHistory
	key := []byte("test key")
	first := []byte("first salt")
	if !h.check(key, first, false) || h.check(key, first, false) {
		t.Fatal("TCP salt was not registered atomically")
	}
	if !h.check(key, first, true) || !h.check([]byte("other key"), first, false) {
		t.Fatal("different users or transports shared a salt namespace")
	}
	for i := 0; i < recentSaltCapacity; i++ {
		var salt [8]byte
		binary.BigEndian.PutUint64(salt[:], uint64(i))
		if !h.check(key, salt[:], false) {
			t.Fatal("unique salt rejected")
		}
	}
	if len(h.seen) != recentSaltCapacity || len(h.order) != recentSaltCapacity {
		t.Fatalf("history grew beyond its bound: %d/%d", len(h.seen), len(h.order))
	}
	if !h.check(key, first, false) {
		t.Fatal("FIFO did not evict the oldest entry")
	}
	var newest [8]byte
	binary.BigEndian.PutUint64(newest[:], recentSaltCapacity-1)
	if h.check(key, newest[:], false) {
		t.Fatal("FIFO lost a recent entry")
	}
}
