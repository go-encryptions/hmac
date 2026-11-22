package hmac

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"fmt"
	"hash"
	"testing"
)

var benchKey = make([]byte, 32)

// reuse measures one keyed MAC reused for many messages: Reset, Write, Sum.
func reuse(b *testing.B, mac hash.Hash, size int) {
	msg := make([]byte, size)
	out := make([]byte, 0, 32)
	b.ReportAllocs()
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mac.Reset()
		mac.Write(msg)
		out = mac.Sum(out[:0])
	}
}

var sizes = []struct {
	name string
	n    int
}{{"64B", 64}, {"4KiB", 4 << 10}, {"1MiB", 1 << 20}}

func BenchmarkHMACSHA256(b *testing.B) {
	for _, s := range sizes {
		b.Run("wipeable/"+s.name, func(b *testing.B) { reuse(b, New(sha256.New, benchKey), s.n) })
		b.Run("stdlib/"+s.name, func(b *testing.B) { reuse(b, hmac.New(sha256.New, benchKey), s.n) })
	}
}

// BenchmarkSector is theca's pattern: one keyed state, Reset + Sum per 4 KiB
// sector (label, index and ciphertext written separately).
func BenchmarkSector(b *testing.B) {
	sector := make([]byte, 4096)
	label := []byte("\x04leaf")
	idx := make([]byte, 8)
	run := func(b *testing.B, mac hash.Hash) {
		out := make([]byte, 0, 32)
		b.ReportAllocs()
		b.SetBytes(4096)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mac.Reset()
			mac.Write(label)
			mac.Write(idx)
			mac.Write(sector)
			out = mac.Sum(out[:0])
		}
	}
	b.Run("wipeable", func(b *testing.B) { run(b, New(sha256.New, benchKey)) })
	b.Run("stdlib", func(b *testing.B) { run(b, hmac.New(sha256.New, benchKey)) })
}

func BenchmarkPBKDF2(b *testing.B) {
	for _, iter := range []int{1000, 100000} {
		b.Run(fmt.Sprintf("wipeable/%d", iter), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				PBKDF2(sha256.New, []byte("password"), []byte("salt"), iter, 32)
			}
		})
		b.Run(fmt.Sprintf("stdlib/%d", iter), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				pbkdf2.Key(sha256.New, "password", []byte("salt"), iter, 32)
			}
		})
	}
}
