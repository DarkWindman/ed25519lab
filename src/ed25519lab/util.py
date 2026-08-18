# Copyright (c) 2025- The secp256k1lab Developers
# Copyright (c) 2026- The ed25519lab Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Hashing and byte helpers.

All integer/byte conversion here is LITTLE-ENDIAN, matching the rest of the
library. Note that this differs from secp256k1lab, where bytes_from_int and
int_from_bytes are big-endian; the names are kept because the role is unchanged.
"""

import hashlib

__all__ = [
    "domain_hash",
    "bytes_from_int",
    "int_from_bytes",
    "xor_bytes",
    "hash_sha512",
]


def domain_hash(tag: str, *parts: bytes) -> bytes:
    """SHA-512 over a domain tag followed by the concatenated parts. 64 bytes.

        domain_hash("proto-v1/nonce", d_le, aux, m)
            == SHA-512(b"proto-v1/nonce" || d_le || aux || m)

    This REPLACES secp256k1lab's tagged_hash, which is the BIP340 construction
    H(H(tag) || H(tag) || msg). That name is a term of art for that specific
    construction, so reusing it for a different one would be a trap; the
    function is renamed rather than redefined.

    The 64-byte output is deliberate: it is exactly what Scalar.from_bytes_wide
    requires, so `Scalar.from_bytes_wide(domain_hash(...))` composes without a
    length adapter, and no other length can be passed by accident.

    CONCATENATION IS NOT INJECTIVE -- read this before adding a call site.

    A plain tag prefix does not, by itself, make the input unambiguous the way
    BIP340's fixed 64-byte prefix does. Two guarantees have to be provided by
    the CALLER instead of by this function:

    1. No tag may be a prefix of another tag. Check this by hand whenever a tag
       is added; nothing here enforces it.

    2. At most one part may be variable-length, and it must be last. Otherwise
       distinct inputs collide: with parts (aux, m), the pairs (b"ab", b"cd")
       and (b"a", b"bcd") produce identical hashes.

    Guarantee 2 is not academic for a signature nonce. If k = domain_hash(tag,
    d, aux, m) collides for two different messages, the signer produces the same
    R twice with different challenges, and the private key falls out of
    d = (s1 - s2) / (e1 - e2). Fix every variable-length field except the last
    one -- hash it to 32 bytes, or length-prefix it.
    """
    return hashlib.sha512(tag.encode() + b"".join(parts)).digest()


def bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, byteorder="little")


def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="little")


def xor_bytes(b0: bytes, b1: bytes) -> bytes:
    assert len(b0) == 32 and len(b1) == 32
    return bytes(x ^ y for (x, y) in zip(b0, b1))


def hash_sha512(b: bytes) -> bytes:
    return hashlib.sha512(b).digest()
