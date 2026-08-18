# Changelog

## Unreleased

Initial curve and scalar layer.

* `FE`, `Scalar`, `GE`, `G` in `ed25519lab.ed25519`.
* `GE.from_bytes_compressed` does RFC 8032 section 5.1.3 decoding plus a
  prime-order-subgroup check, rejecting non-canonical encodings, small-order
  points and mixed-order points.
* `Scalar.from_bytes_wide` replaces secp256k1lab's `Scalar.from_bytes_wrapping`,
  takes exactly 64 bytes, and is the only supported way to turn a hash output
  into a scalar.
* `pubkey_gen` uses raw scalars: no seed, no clamping.
* `domain_hash(tag, *parts)` replaces secp256k1lab's `tagged_hash`. The BIP340
  double-hash construction is dropped: this is Ed25519, and every construction
  in the spec uses a plain SHA-512 tag prefix. The rename is deliberate --
  `tagged_hash` names the BIP340 construction specifically. The 64-byte output
  feeds `Scalar.from_bytes_wide` directly. Callers must ensure no tag prefixes
  another and that at most one part is variable-length and last; both hazards
  are pinned by tests.

* `internal_sign` / `internal_verify` in `ed25519lab.internal_sig`, replacing
  secp256k1lab's `schnorr_sign` / `schnorr_verify`. The domain tag is prepended
  to the challenge input, before R and the public key, so an internal signature
  is structurally unverifiable as an ordinary Ed25519 signature. The nonce is
  derived deterministically from the raw secret scalar, since the protocol has
  no seeds. `aux` is fixed at 32 bytes -- see below.
* `ecdh_ed25519` in `ed25519lab.ecdh`, replacing `ecdh_libsecp256k1`. The peer
  key goes through strict decoding, which is what closes the small-subgroup
  attack that would otherwise leak `deckey mod 8`. The raw shared point is never
  key material: it is hashed together with both public keys and the context.

Deviation from the spec, deliberate: the spec writes the nonce input as
`tag || d_le || aux || m` with both `aux` and `m` variable-length. Plain
concatenation is not injective, so two different (aux, m) pairs can yield the
same nonce, and two signatures sharing R with different challenges disclose the
secret key. `aux` is therefore required to be exactly 32 bytes, making `m`
unambiguously the tail. The spec should be updated to match.

Not yet implemented: a cofactorless `verify` for the final aggregate signature
(the API mapping table has no row for it).
