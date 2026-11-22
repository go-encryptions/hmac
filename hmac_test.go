package hmac

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"hash"
	mrand "math/rand/v2"
	"os"
	"strconv"
	"strings"
	"testing"
)

// plain hides the marshal methods of a hash, forcing the fallback mode.
type plain struct{ h hash.Hash }

func (p plain) Write(b []byte) (int, error) { return p.h.Write(b) }
func (p plain) Sum(b []byte) []byte         { return p.h.Sum(b) }
func (p plain) Reset()                      { p.h.Reset() }
func (p plain) Size() int                   { return p.h.Size() }
func (p plain) BlockSize() int              { return p.h.BlockSize() }

type namedHash struct {
	name string
	new  func() hash.Hash
}

var hashes = []namedHash{
	{"sha256", sha256.New},
	{"sha1", sha1.New},
	{"sha512", sha512.New},
	{"sha384", sha512.New384},
	{"md5", md5.New},
	{"plain-sha256", func() hash.Hash { return &plain{sha256.New()} }},
	{"plain-sha512", func() hash.Hash { return &plain{sha512.New()} }},
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDifferentialStdlib(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(1, 2))
	for _, hh := range hashes {
		t.Run(hh.name, func(t *testing.T) {
			for round := 0; round < 300; round++ {
				key := make([]byte, rng.IntN(300))
				rand.Read(key)
				msg := make([]byte, rng.IntN(700))
				rand.Read(msg)
				ref := hmac.New(hh.new, key)
				m := New(hh.new, key)
				cut := 0
				if len(msg) > 0 {
					cut = rng.IntN(len(msg))
				}
				for _, mm := range []hash.Hash{ref, m} {
					mm.Write(msg[:cut])
					mm.Write(msg[cut:])
				}
				if g, w := m.Sum(nil), ref.Sum(nil); !bytes.Equal(g, w) {
					t.Fatalf("keylen %d msglen %d: %x != %x", len(key), len(msg), g, w)
				}
				// Sum must not change the state: extend and sum again.
				m.Write([]byte("more"))
				ref.Write([]byte("more"))
				if g, w := m.Sum([]byte("pre")), ref.Sum([]byte("pre")); !bytes.Equal(g, w) {
					t.Fatalf("after extend: %x != %x", g, w)
				}
				// Reset must restore the keyed state.
				m.Reset()
				ref.Reset()
				m.Write(msg)
				ref.Write(msg)
				if g, w := m.Sum(nil), ref.Sum(nil); !bytes.Equal(g, w) {
					t.Fatalf("after reset: %x != %x", g, w)
				}
			}
		})
	}
}

func TestSizes(t *testing.T) {
	m := New(sha256.New, []byte("k"))
	if m.Size() != 32 || m.BlockSize() != 64 {
		t.Fatal(m.Size(), m.BlockSize())
	}
}

func TestNonUniquePanics(t *testing.T) {
	h := sha256.New()
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	New(func() hash.Hash { return h }, nil)
}

func TestRFC4231(t *testing.T) {
	cases := []struct {
		h         func() hash.Hash
		key, data string
		mac       string
	}{
		{sha256.New, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265",
			"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"},
		{sha256.New, "4a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
			"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"},
		{sha256.New, strings.Repeat("aa", 20), strings.Repeat("dd", 50),
			"773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"},
		{sha256.New, "0102030405060708090a0b0c0d0e0f10111213141516171819", strings.Repeat("cd", 50),
			"82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"},
		{sha256.New, strings.Repeat("aa", 131), "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
			"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"},
		{sha256.New, strings.Repeat("aa", 131), "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
			"9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"},
		{sha512.New, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265",
			"87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"},
		{sha512.New, "4a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
			"164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"},
	}
	for i, c := range cases {
		for _, wrap := range []bool{false, true} {
			newh := c.h
			if wrap {
				inner := c.h
				newh = func() hash.Hash { return &plain{inner()} }
			}
			m := New(newh, unhex(t, c.key))
			m.Write(unhex(t, c.data))
			if got := hex.EncodeToString(m.Sum(nil)); got != c.mac {
				t.Errorf("RFC 4231 case %d (plain=%v): %s", i, wrap, got)
			}
		}
	}
}

// refHMAC is theca's reference (go-theca/theca internal/ta1/ta1_test.go,
// refHMAC, origin/main 939ca2f): RFC 2104 on bare SHA-256.
func refHMAC(key, msg []byte) []byte {
	if len(key) > 64 {
		s := sha256.Sum256(key)
		key = s[:]
	}
	k := make([]byte, 64)
	copy(k, key)
	in := make([]byte, 0, 64+len(msg))
	out := make([]byte, 64)
	for i := range k {
		in = append(in, k[i]^0x36)
		out[i] = k[i] ^ 0x5c
	}
	in = append(in, msg...)
	h := sha256.Sum256(in)
	o := sha256.Sum256(append(out, h[:]...))
	return o[:]
}

func TestThecaVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/theca_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Source string
		Cases  []struct{ Key, Data, Mac string }
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.Source, "go-theca/theca") || len(f.Cases) != 3 {
		t.Fatalf("vector file lost its citation or cases: %q, %d", f.Source, len(f.Cases))
	}
	for i, c := range f.Cases {
		key := []byte(nil)
		if rest, ok := strings.CutPrefix(c.Key, "REPEAT:"); ok {
			parts := strings.Split(rest, ":")
			n := 0
			for _, ch := range parts[1] {
				n = n*10 + int(ch-'0')
			}
			key = bytes.Repeat(unhex(t, parts[0]), n)
		} else {
			key = unhex(t, c.Key)
		}
		data := unhex(t, c.Data)
		m := New(sha256.New, key)
		m.Write(data)
		if got := hex.EncodeToString(m.Sum(nil)); got != c.Mac {
			t.Errorf("theca vector %d: %s", i, got)
		}
		if got := hex.EncodeToString(refHMAC(key, data)); got != c.Mac {
			t.Errorf("theca refHMAC vector %d: %s", i, got)
		}
	}
}

// TestThecaPatterns reproduces how theca uses HMAC: labelled messages
// u8(len(label)) || label || parts (ta1.MAC, SectorTag), a 24-byte truncated
// tag, one keyed state reused across sectors by Reset, and multi-part Write
// as in internal/merkle hm().
func TestThecaPatterns(t *testing.T) {
	var km [32]byte
	rand.Read(km[:])
	m := New(sha256.New, km[:])
	defer m.Wipe()
	lab := func(l string) []byte { return append([]byte{byte(len(l))}, l...) }
	for i := 0; i < 200; i++ {
		ct := make([]byte, 4096)
		rand.Read(ct)
		var idx [8]byte
		idx[7] = byte(i)
		var msg []byte
		for _, p := range [][]byte{lab("leaf"), idx[:], ct} {
			msg = append(msg, p...)
		}
		m.Reset()
		m.Write(lab("leaf"))
		m.Write(idx[:])
		m.Write(ct)
		got := m.Sum(nil)
		if want := refHMAC(km[:], msg); !bytes.Equal(got, want) {
			t.Fatalf("sector %d differs from refHMAC", i)
		}
		std := hmac.New(sha256.New, km[:])
		std.Write(msg)
		if !bytes.Equal(got[:24], std.Sum(nil)[:24]) {
			t.Fatalf("sector %d: 24-byte tag differs from crypto/hmac", i)
		}
	}
}

func TestPBKDF2Vectors(t *testing.T) {
	type kat struct {
		h        func() hash.Hash
		pw, salt string
		iter, n  int
		want     string
		long     bool
	}
	cases := []kat{
		// RFC 6070, PBKDF2-HMAC-SHA1.
		{sha1.New, "password", "salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6", false},
		{sha1.New, "password", "salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957", false},
		{sha1.New, "password", "salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1", false},
		{sha1.New, "password", "salt", 16777216, 20, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984", true},
		{sha1.New, "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25,
			"3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038", false},
		{sha1.New, "pass\x00word", "sa\x00lt", 4096, 16, "56fa6aa75548099dcc37d7f03425e0c3", false},
		// Widely published PBKDF2-HMAC-SHA-256 vectors.
		{sha256.New, "password", "salt", 1, 32, "120fb6cffcf8b32c43e7225256c4f837a86548c9" + "2ccc35480805987cb70be17b", false},
		{sha256.New, "password", "salt", 2, 32, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43", false},
		{sha256.New, "password", "salt", 4096, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a", false},
		{sha256.New, "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40,
			"348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9", false},
	}
	for i, c := range cases {
		if c.long && os.Getenv("HMAC_LONG") == "" {
			continue
		}
		got, err := PBKDF2(c.h, []byte(c.pw), []byte(c.salt), c.iter, c.n)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != c.want {
			t.Errorf("case %d: %x", i, got)
		}
	}
}

func TestPBKDF2Errors(t *testing.T) {
	if _, err := PBKDF2(sha1.New, nil, nil, 0, 1); err != ErrIterations {
		t.Fatal(err)
	}
	if _, err := PBKDF2(sha1.New, nil, nil, 1, -1); err != ErrKeyLength {
		t.Fatal(err)
	}
	if got, err := PBKDF2(sha1.New, nil, nil, 1, 0); err != nil || len(got) != 0 {
		t.Fatal(got, err)
	}
	if strconv.IntSize == 64 {
		// One byte above (2^32-1)*hLen, refused before anything is allocated.
		over := uint64(20)*(1<<32-1) + 1 // a variable: a constant would not compile on 32-bit
		if _, err := PBKDF2(sha1.New, nil, nil, 1, int(over)); err != ErrKeyLength {
			t.Fatal(err)
		}
	}
}

func TestPBKDF2DifferentialStdlib(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(3, 4))
	for _, hh := range hashes[:5] {
		for i := 0; i < 20; i++ {
			pw := make([]byte, rng.IntN(150))
			salt := make([]byte, rng.IntN(40))
			rand.Read(pw)
			rand.Read(salt)
			iter, n := 1+rng.IntN(50), rng.IntN(200)
			want, err := pbkdf2.Key(hh.new, string(pw), salt, iter, n)
			if err != nil {
				t.Fatal(err)
			}
			got, err := PBKDF2(hh.new, pw, salt, iter, n)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("%s iter %d n %d: %x != %x (%v)", hh.name, iter, n, got, want, err)
			}
		}
	}
}

func FuzzPBKDF2(f *testing.F) {
	f.Add([]byte("password"), []byte("salt"), uint8(3), uint8(40), uint8(0))
	f.Fuzz(func(t *testing.T, pw, salt []byte, iter, n, which uint8) {
		hh := hashes[int(which)%5]
		it := 1 + int(iter)%64
		want, err := pbkdf2.Key(hh.new, string(pw), salt, it, int(n))
		if err != nil {
			t.Skip()
		}
		got, err := PBKDF2(hh.new, pw, salt, it, int(n))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s: %x != %x (%v)", hh.name, got, want, err)
		}
	})
}

func TestWipeZeroesState(t *testing.T) {
	for _, hh := range hashes {
		t.Run(hh.name, func(t *testing.T) {
			key := bytes.Repeat([]byte{0xA5}, 200)
			m := New(hh.new, key)
			m.Write([]byte("message"))
			m.Sum(nil)
			if m.Wipeable() != !strings.HasPrefix(hh.name, "plain") {
				t.Fatalf("Wipeable = %v", m.Wipeable())
			}
			m.Wipe()
			m.Wipe() // idempotent
			if !m.Wiped() {
				t.Fatal("not wiped")
			}
			for name, b := range map[string][]byte{"istate": m.istate, "ostate": m.ostate, "ipad": m.ipad, "opad": m.opad, "tmp": m.tmp[:cap(m.tmp)]} {
				if !allZero(b) {
					t.Errorf("%s not zero: %x", name, b)
				}
			}
			if m.Wipeable() {
				// The live digests hold the public initial state again.
				for _, d := range []hash.Hash{m.inner, m.outer} {
					got := marshal(t, d)
					if !bytes.Equal(got, m.fresh) {
						t.Errorf("live digest still holds state: %x", got)
					}
				}
			}
		})
	}
}

func marshal(t *testing.T, h hash.Hash) []byte {
	t.Helper()
	b, err := h.(interface{ MarshalBinary() ([]byte, error) }).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// TestKeyedStateIsInTheDigests is the control of the test above: before Wipe
// the live digests differ from the public initial state, so the comparison
// after Wipe measures something.
func TestKeyedStateIsInTheDigests(t *testing.T) {
	m := New(sha256.New, bytes.Repeat([]byte{7}, 32))
	if bytes.Equal(marshal(t, m.inner), m.fresh) || bytes.Equal(marshal(t, m.outer), m.fresh) {
		t.Fatal("keyed digest equals the initial state")
	}
	if allZero(m.istate) || allZero(m.ostate) {
		t.Fatal("keyed states are zero before Wipe")
	}
}

func TestUseAfterWipePanics(t *testing.T) {
	for _, hh := range hashes {
		for name, use := range map[string]func(*MAC){
			"Sum":   func(m *MAC) { m.Sum(nil) },
			"Write": func(m *MAC) { m.Write([]byte("x")) },
			"Reset": func(m *MAC) { m.Reset() },
		} {
			m := New(hh.new, []byte("key"))
			m.Wipe()
			func() {
				defer func() {
					if r := recover(); r != errWiped {
						t.Errorf("%s/%s: recovered %v", hh.name, name, r)
					}
				}()
				use(m)
			}()
		}
	}
}

// failing marshals once, then refuses to marshal or to unmarshal.
type failing struct {
	hash.Hash
	marshals  int
	failAt    int // the 1-based MarshalBinary call that fails; 0 for none
	failUn    bool
}

func (f *failing) MarshalBinary() ([]byte, error) {
	f.marshals++
	// The state is valid even when the error is returned: only the error
	// guard in New can refuse it, not a later unmarshal of garbage.
	b, err := f.Hash.(interface{ MarshalBinary() ([]byte, error) }).MarshalBinary()
	if f.marshals == f.failAt {
		return b, os.ErrInvalid
	}
	return b, err
}

func (f *failing) UnmarshalBinary(b []byte) error {
	if f.failUn {
		return os.ErrInvalid
	}
	return f.Hash.(interface{ UnmarshalBinary([]byte) error }).UnmarshalBinary(b)
}

// TestMarshalFailureFallsBack: a hash whose marshal fails at any step still
// gives the right answer, through the pads.
func TestMarshalFailureFallsBack(t *testing.T) {
	key, msg := []byte("key"), []byte("message")
	want := func() []byte { h := hmac.New(sha256.New, key); h.Write(msg); return h.Sum(nil) }()
	// The first hash New asks for is the inner one, the second the outer.
	for _, c := range []struct {
		innerAt, outerAt int
		failUn           bool
	}{{1, 0, false}, {2, 0, false}, {0, 1, false}, {0, 0, true}} {
		calls := 0
		m := New(func() hash.Hash {
			calls++
			at := c.innerAt
			if calls == 2 {
				at = c.outerAt
			}
			return &failing{Hash: sha256.New(), failAt: at, failUn: c.failUn}
		}, key)
		if m.Wipeable() {
			t.Errorf("%+v: still wipeable", c)
		}
		m.Write(msg)
		if got := m.Sum(nil); !bytes.Equal(got, want) {
			t.Errorf("%+v: %x", c, got)
		}
		m.Wipe()
	}
}

// brokenRestore marshals fine but later refuses to restore.
type brokenRestore struct {
	hash.Hash
	armed *bool
}

func (b *brokenRestore) MarshalBinary() ([]byte, error) {
	return b.Hash.(interface{ MarshalBinary() ([]byte, error) }).MarshalBinary()
}

func (b *brokenRestore) UnmarshalBinary(p []byte) error {
	if *b.armed {
		return os.ErrInvalid
	}
	return b.Hash.(interface{ UnmarshalBinary([]byte) error }).UnmarshalBinary(p)
}

func TestRestoreFailurePanics(t *testing.T) {
	armed := false
	m := New(func() hash.Hash { return &brokenRestore{Hash: sha256.New(), armed: &armed} }, []byte("k"))
	armed = true
	for name, use := range map[string]func(){"Reset": m.Reset, "Sum": func() { m.Sum(nil) }} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			use()
		}()
	}
}

func FuzzMAC(f *testing.F) {
	f.Add([]byte("key"), []byte("message"), uint8(0), uint8(3))
	f.Add(bytes.Repeat([]byte{0xaa}, 131), []byte("Test Using Larger Than Block-Size Key"), uint8(2), uint8(0))
	f.Add([]byte{}, []byte{}, uint8(5), uint8(1))
	f.Fuzz(func(t *testing.T, key, msg []byte, which, cut uint8) {
		hh := hashes[int(which)%len(hashes)]
		ref := hmac.New(hh.new, key)
		m := New(hh.new, key)
		c := int(cut)
		if c > len(msg) {
			c = len(msg)
		}
		for _, h := range []hash.Hash{ref, m} {
			h.Write(msg[:c])
			h.Write(msg[c:])
		}
		if g, w := m.Sum(nil), ref.Sum(nil); !bytes.Equal(g, w) {
			t.Fatalf("%s: %x != %x", hh.name, g, w)
		}
		m.Reset()
		m.Write(msg)
		ref.Reset()
		ref.Write(msg)
		if g, w := m.Sum(nil), ref.Sum(nil); !bytes.Equal(g, w) {
			t.Fatalf("%s after reset: %x != %x", hh.name, g, w)
		}
	})
}
