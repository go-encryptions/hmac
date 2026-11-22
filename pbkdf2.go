package hmac

import (
	"errors"
	"hash"
)

// Errors returned by PBKDF2.
var (
	ErrIterations = errors.New("hmac: PBKDF2 iteration count must be at least 1")
	ErrKeyLength  = errors.New("hmac: PBKDF2 key length is negative or exceeds (2^32-1)*hLen")
)

// PBKDF2 derives keyLen bytes from password and salt with PBKDF2 (RFC 8018
// section 5.2) over HMAC with the hash h, iter iterations. The HMAC is built
// on New, so the keyed states are wiped before PBKDF2 returns, as are the
// intermediate blocks; the returned slice is the caller's to wipe.
func PBKDF2(h func() hash.Hash, password, salt []byte, iter, keyLen int) ([]byte, error) {
	if iter < 1 {
		return nil, ErrIterations
	}
	mac := New(h, password)
	defer mac.Wipe()
	size := mac.Size()
	if keyLen < 0 || uint64(keyLen) > uint64(1<<32-1)*uint64(size) {
		return nil, ErrKeyLength
	}

	dk := make([]byte, keyLen)
	u := make([]byte, 0, size)
	t := make([]byte, size)
	defer clear(t)
	for block, pos := uint32(1), 0; pos < keyLen; block, pos = block+1, pos+size {
		mac.Reset()
		mac.Write(salt)
		mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u = mac.Sum(u[:0])
		copy(t, u)
		for n := 1; n < iter; n++ {
			mac.Reset()
			mac.Write(u)
			u = mac.Sum(u[:0])
			for i := range t {
				t[i] ^= u[i]
			}
		}
		copy(dk[pos:], t)
	}
	clear(u[:cap(u)])
	return dk, nil
}
