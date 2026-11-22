# hmac

HMAC for Go whose keyed state can be wiped.

`crypto/hmac` keeps the two padded keys inside its inner and outer hash
states, where a program cannot reach them: they stay in memory until the
garbage collector reuses the page. `hmac` precomputes the same two keyed
states, so `Reset` does not hash the pads again, but keeps them in buffers it
owns and zeroes them on request. The gap is described in
[go-theca/theca#74](https://github.com/go-theca/theca/issues/74).

```go
m := hmac.New(sha256.New, key) // implements hash.Hash; key is not retained
defer m.Wipe()                 // zeroes every key-derived byte the package holds

for _, sector := range sectors {
	m.Reset() // restores the keyed state; no pad is hashed again
	m.Write(sector)
	tag = m.Sum(tag[:0])
}

dk, err := hmac.PBKDF2(sha256.New, password, salt, 500000, 64) // RFC 8018
```

The output is byte-for-byte what `crypto/hmac` produces, for every hash.
A `MAC` is not safe for concurrent use. After `Wipe`, `Write`, `Sum` and
`Reset` panic (a hash.Hash has no error to return): a wiped MAC computing a
tag under an all-zero key would be a silent failure.

## What Wipe guarantees, and what it cannot

Wipe zeroes, in place:

- the marshaled inner and outer keyed states (the precomputed pads);
- the pads themselves, when the hash cannot be marshaled;
- the scratch buffer holding the last inner digest;
- the two live digests, when the hash implements `encoding.BinaryMarshaler`
  and `BinaryUnmarshaler` (every hash of the standard library does): their
  private fields cannot be named, so they are overwritten by restoring the
  public initial state, which replaces the chaining value, the block buffer
  and the length. The tests marshal the digests after `Wipe` and compare with
  the initial state, and a control test shows the comparison differs before.
  `Wipeable` reports whether this applies.

It cannot reach:

- **copies made by the runtime or the hash**: a digest's `Sum` copies its
  whole state before padding it, the garbage collector and stack growth move
  values, and registers spill. Those copies are unnamed and unreachable from
  Go;
- **your key**: `New` keeps no reference to it, zeroing the slice is yours;
- **a hash that cannot be marshaled**: the pads are kept (every `Reset` has to
  hash them again) and zeroed by `Wipe`, but the digests are only `Reset`,
  which a hash need not implement as an overwrite;
- **swap, core dumps, hibernation images** taken before `Wipe`.

So `Wipe` removes the long-lived copies the package owns, which are the ones
that outlive a call; it is not a proof that no byte of the key is left in the
process.

## PBKDF2

`PBKDF2(h, password, salt, iter, keyLen)` is RFC 8018 section 5.2 over this
HMAC (the header derivation of VeraCrypt and zed). The keyed states and the
intermediate blocks are wiped before it returns. It returns `ErrIterations`
for `iter < 1` and `ErrKeyLength` for a negative length or one above
(2^32-1) times the hash size.

## Correctness

Known-answer vectors: RFC 4231 test cases 1 to 4, 6 and 7 (HMAC-SHA-256) and 1 and 2
(HMAC-SHA-512); RFC 6070 (PBKDF2-HMAC-SHA1, the 16777216-iteration case with
`HMAC_LONG=1`) and published PBKDF2-HMAC-SHA-256 vectors; the HMAC-SHA-256
vectors of go-theca/theca (`testdata/theca_vectors.json`, source cited in the
file) and theca's access patterns (labelled messages, 24-byte tags, Reset per
sector). Differential tests and fuzz targets (`FuzzMAC`, `FuzzPBKDF2`, corpus
in `testdata/fuzz`) against `crypto/hmac` and `crypto/pbkdf2` for SHA-256,
SHA-1, SHA-512, SHA-384, MD5 and two wrapped hashes that force the
non-marshal path, 100% statement coverage, `-race`, govulncheck, and a
32-bit (386) run in CI.

## Performance

Allocations per operation, `go test -bench . -cpu 1` (exact; Go 1.27.4,
Apple M4 Max), one keyed MAC reused, Reset + Write + Sum:

| operation | `hmac` | `crypto/hmac` |
|---|---:|---:|
| HMAC-SHA-256, 64 B | 0 | 0 |
| HMAC-SHA-256, 4 KiB | 0 | 0 |
| HMAC-SHA-256, 1 MiB | 0 | 0 |
| Reset + Sum per 4 KiB sector (theca) | 0 | 0 |
| PBKDF2-HMAC-SHA-256, per call | 14 | 12 |

Times, one core, Apple M4 Max, five rounds (not interleaved), started after
`waitload --max-load 8` succeeded:

| operation | `hmac` | `crypto/hmac` |
|---|---:|---:|
| HMAC-SHA-256, 64 B | 85.2 to 85.6 ns | 85.0 to 85.2 ns |
| HMAC-SHA-256, 4 KiB | 1434 to 1468 ns | 1461 to 1469 ns |

So the two are level: the precomputed states match what `crypto/hmac` does
internally, and the gain is the wipe, not speed. The 1 MiB and
Reset + Sum per 4 KiB sector rows are not yet measured: the machine's load
rose above 20 during those rounds. Other platforms are not measured either.

## Licence

BSD 3-Clause.
