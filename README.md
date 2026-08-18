ed25519lab
==========

![Dependencies: None](https://img.shields.io/badge/dependencies-none-success)

An INSECURE implementation of the Ed25519 curve and related cryptographic
schemes written in Python, intended for prototyping, experimentation and
education.

It is a sibling of [secp256k1lab](https://github.com/secp256k1lab/secp256k1lab),
built to support a port of FROST threshold signing and ChillDKG from BIP-340 /
secp256k1 to Ed25519 with Solana-compatible signatures. Class and method names
are kept identical to secp256k1lab wherever the role of a function is unchanged,
so that call sites in the reference implementations stay comparable against
upstream.

Features:
* Low-level Ed25519 field, scalar and group arithmetic.
* Strict point decoding: RFC 8032 section 5.1.3 plus a prime-order-subgroup
  check.
* Raw-scalar key generation (no seeds, no clamping).
* The internal PoP / CertEq signature scheme (`internal_sign`,
  `internal_verify`), deliberately not verifiable as an ordinary Ed25519
  signature.
* ECDH key derivation for encrypted share transport (`ecdh_ed25519`).

WARNING: The code in this library is slow and trivially vulnerable to side
channel attacks.

Differences from a standard Ed25519 library
-------------------------------------------

These are deliberate and are what the library exists for.

* **Strict decoding.** `GE.from_bytes_compressed` rejects non-canonical
  encodings (`y >= p`, and `x == 0` with the sign bit set), all seven
  non-neutral small-order points, and all mixed-order points `[k]B + T`. Every
  standard library accepts most of these.
* **No cofactor anywhere in the arithmetic.** The verify equation this library
  is built for is the cofactorless `[s]B = R + [e]A`, which is what Solana
  enforces, not the cofactored `[8][s]B = [8]R + [8][e]A` that RFC 8032 gives as
  its primary form and implements in its own appendix code.
* **Raw scalars.** Secret keys are uniform scalars mod L, little-endian. There
  is no seed, no SHA-512 expansion, no clamping and no nonce prefix, because the
  protocol needs unclamped scalar signing and keeping one key type avoids
  maintaining two signing constructions.
* **`Scalar.from_bytes_wide` instead of `from_bytes_wrapping`.** It takes
  exactly 64 bytes and raises otherwise. On secp256k1 a random 256-bit hash is
  almost always a valid scalar; on Ed25519 `L ~ 2**252`, so it is valid only
  about 1 time in 16. Reducing a hash the wrong way therefore fails late and
  intermittently. The distinct name plus the length check make it fail
  immediately, at the call site.
* **`domain_hash` instead of `tagged_hash`.** Domain separation is a plain
  SHA-512 tag prefix, `SHA-512(tag || parts...)`, matching how every
  construction in the protocol spec is written. BIP340's double-hash
  `H(H(tag) || H(tag) || msg)` is dropped along with the rest of the BIP340
  machinery, and the function is renamed rather than redefined because
  `tagged_hash` names that specific construction. The 64-byte output feeds
  `Scalar.from_bytes_wide` with no length adapter. The trade-off is that
  concatenation is no longer injective for free: callers must ensure no tag is a
  prefix of another, and that at most one part is variable-length and comes
  last. Both hazards are pinned by tests.
* **The neutral element is an ordinary point.** `GE()` is `(0, 1)` and encodes
  as `0x01` followed by 31 zero bytes. There is no
  `from_bytes_compressed_with_infinity` or `to_bytes_compressed_with_infinity`;
  call sites that must not accept the neutral element check `.infinity`
  themselves.

Endianness
----------

All byte input and output in this library is little-endian, by definition of
Ed25519. It is not encoded in any method name. Identifiers, lengths and counts
that go inside hash inputs are big-endian; that mixing is intentional and is the
caller's responsibility.

Testing
-------

No installation needed -- `test/__init__.py` puts `src/` on the path, so a fresh
clone runs as is.

    python3 -m unittest                            # all 87
    python3 -m unittest test.test_strictness -v    # one module, verbose

`test_ed25519.py` covers arithmetic and constructors, `test_strictness.py` covers
everything that must be rejected, `test_internal_sig.py` and `test_ecdh.py` cover
the protocol layer, and `test_crosscheck.py` compares every primitive against
libsodium through PyNaCl (>= 1.6.2 -- CVE-2025-69277 affects exactly the subgroup
predicate used here as an oracle).

The cross-check module skips if PyNaCl is absent, so that the library itself can
stay dependency-free. Those are the only tests that check the implementation
against something we did not write, so a silent skip is dangerous in CI: set

    ED25519LAB_REQUIRE_CROSSCHECK=1 python3 -m unittest

to turn the skip into a hard failure. CI sets it.

RFC 8032 section 7.1 vectors are used as positive parser vectors: every public
key and every signature R must survive strict decoding. The signatures
themselves are not verified, because RFC 8032 key generation clamps a hashed
seed and this library signs with raw scalars, so there is no common ground.

Timing
------

    python3 bench.py            # all primitives
    python3 bench.py decode     # filter by substring or group name

Documentation
-------------

`WALKTHROUGH.md` explains every function, why it is written the way it is, what
the tests cover, and what is still missing.
