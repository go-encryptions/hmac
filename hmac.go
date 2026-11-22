// Package hmac is HMAC (RFC 2104, FIPS 198-1) whose keyed state can be wiped.
//
// crypto/hmac keeps the two padded keys inside its inner and outer hash
// states, where the program cannot reach them: they stay in memory until the
// garbage collector reuses the page. This package precomputes the same two
// keyed states, so Reset does not hash the pads again, but it keeps them in
// buffers it owns and can zero.
//
// # What Wipe does
//
// Wipe zeroes every byte the package itself holds that derives from the key:
// the marshaled inner and outer keyed states, the pads (when the hash cannot
// be marshaled), and the scratch buffer holding the last inner digest. When
// the hash implements encoding.BinaryMarshaler and BinaryUnmarshaler (every
// hash in the standard library does), the two live digests are also
// overwritten, in place, with the public initial state: the state a digest
// returns to is a full overwrite of its chaining value and its block buffer,
// which is how a digest whose fields are private can be wiped at all. The
// tests assert it by marshaling the digests after Wipe.
//
// # What Wipe cannot do
//
//   - Copies the Go runtime or the hash made. A digest's Sum copies its whole
//     state onto the stack or heap before padding it; that copy is a dead
//     variable the program cannot name. The garbage collector, the stack
//     copier (stack growth) and the register allocator may also leave copies
//     of any value. None can be reached or wiped from Go.
//   - The caller's key. New reads key and keeps no reference to it; zeroing
//     the slice is the caller's job.
//   - A hash that cannot be marshaled. Then the pads are kept (Reset has to
//     hash them again), they are zeroed by Wipe, and the digests are only
//     Reset, which a hash is not required to implement as an overwrite.
//     Wipeable reports which case applies.
//   - Swap, core dumps and hibernation images taken before Wipe.
//
// After Wipe the MAC is unusable: Write, Sum and Reset panic. Wipe is
// idempotent. A MAC is not safe for concurrent use.
package hmac

import (
	"encoding"
	"hash"
	"reflect"
	"runtime"
)

const (
	ipadByte = 0x36
	opadByte = 0x5c
)

// errWiped is the panic value of a use after Wipe.
const errWiped = "hmac: use after Wipe"

// MAC is a keyed HMAC computation; it implements hash.Hash.
type MAC struct {
	inner, outer hash.Hash
	size         int

	// marshal mode: the keyed states and the public initial state.
	innerU, outerU encoding.BinaryUnmarshaler
	istate, ostate []byte
	fresh          []byte

	// fallback mode: the pads, hashed again by every Reset.
	ipad, opad []byte

	tmp   []byte // the last inner digest
	wiped bool
}

var _ hash.Hash = (*MAC)(nil)

// New returns a MAC for the hash h under key. A key longer than the block
// size is hashed first, as RFC 2104 says. New panics, as crypto/hmac does,
// when h returns the same hash twice.
func New(h func() hash.Hash, key []byte) *MAC {
	m := &MAC{inner: h(), outer: h()}
	if sameHash(m.inner, m.outer) {
		panic("hmac: hash generation function does not produce unique values")
	}
	m.size = m.inner.Size()
	bs := m.inner.BlockSize()
	m.tmp = make([]byte, 0, m.size)

	if len(key) > bs {
		m.outer.Reset()
		m.outer.Write(key)
		hk := m.outer.Sum(nil)
		defer clear(hk)
		key = hk
		m.outer.Reset()
	}
	ipad := make([]byte, bs)
	opad := make([]byte, bs)
	copy(ipad, key)
	copy(opad, key)
	for i := range ipad {
		ipad[i] ^= ipadByte
		opad[i] ^= opadByte
	}

	if m.marshalMode(ipad, opad) {
		clear(ipad)
		clear(opad)
		return m
	}
	m.ipad, m.opad = ipad, opad
	m.Reset()
	return m
}

// marshalMode precomputes the keyed states and reports whether the hash
// supports it; on false the MAC is left untouched except for the digests.
func (m *MAC) marshalMode(ipad, opad []byte) bool {
	iu, ok1 := m.inner.(encoding.BinaryUnmarshaler)
	ou, ok2 := m.outer.(encoding.BinaryUnmarshaler)
	im, ok3 := m.inner.(encoding.BinaryMarshaler)
	om, ok4 := m.outer.(encoding.BinaryMarshaler)
	if !(ok1 && ok2 && ok3 && ok4) {
		return false
	}
	m.inner.Reset()
	fresh, err := im.MarshalBinary()
	if err != nil {
		return false
	}
	m.inner.Write(ipad)
	istate, err := im.MarshalBinary()
	if err != nil {
		return false
	}
	m.outer.Reset()
	m.outer.Write(opad)
	ostate, err := om.MarshalBinary()
	if err != nil {
		return false
	}
	if iu.UnmarshalBinary(istate) != nil || ou.UnmarshalBinary(ostate) != nil {
		return false
	}
	m.innerU, m.outerU = iu, ou
	m.istate, m.ostate, m.fresh = istate, ostate, fresh
	return true
}

func sameHash(a, b hash.Hash) bool {
	t := reflect.TypeOf(a)
	return t == reflect.TypeOf(b) && t.Comparable() && a == b
}

func (m *MAC) check() {
	if m.wiped {
		panic(errWiped)
	}
}

// Size returns the size of the MAC in bytes.
func (m *MAC) Size() int { return m.size }

// BlockSize returns the block size of the underlying hash.
func (m *MAC) BlockSize() int { return m.inner.BlockSize() }

// Write adds p to the message; it never returns an error.
func (m *MAC) Write(p []byte) (int, error) {
	m.check()
	return m.inner.Write(p)
}

// Reset returns the MAC to the state just after New, without hashing the
// pads again when the hash can be marshaled.
func (m *MAC) Reset() {
	m.check()
	if m.istate != nil {
		if err := m.innerU.UnmarshalBinary(m.istate); err != nil {
			panic("hmac: restoring the inner state: " + err.Error())
		}
		return
	}
	m.inner.Reset()
	m.inner.Write(m.ipad)
}

// Sum appends the MAC of the message so far to in and returns the result. It
// does not change the state: the message can be extended and Sum called
// again. Sum allocates only if in lacks the capacity.
func (m *MAC) Sum(in []byte) []byte {
	m.check()
	m.tmp = m.inner.Sum(m.tmp[:0])
	if m.istate != nil {
		if err := m.outerU.UnmarshalBinary(m.ostate); err != nil {
			panic("hmac: restoring the outer state: " + err.Error())
		}
	} else {
		m.outer.Reset()
		m.outer.Write(m.opad)
	}
	m.outer.Write(m.tmp)
	return m.outer.Sum(in)
}

// Wipeable reports whether Wipe overwrites the live digests (the hash can be
// marshaled) or only resets them; see the package comment.
func (m *MAC) Wipeable() bool { return m.fresh != nil }

// Wiped reports whether Wipe has been called.
func (m *MAC) Wiped() bool { return m.wiped }

// Wipe zeroes every key-derived byte the package holds and makes the MAC
// unusable. The package comment lists what that does not cover.
func (m *MAC) Wipe() {
	clear(m.istate)
	clear(m.ostate)
	clear(m.ipad)
	clear(m.opad)
	clear(m.tmp[:cap(m.tmp)])
	if m.fresh != nil {
		// The initial state is public, and overwrites chaining value, block
		// buffer and length of the live digests.
		_ = m.innerU.UnmarshalBinary(m.fresh)
		_ = m.outerU.UnmarshalBinary(m.fresh)
	} else {
		m.inner.Reset()
		m.outer.Reset()
	}
	m.wiped = true
	runtime.KeepAlive(m)
}
