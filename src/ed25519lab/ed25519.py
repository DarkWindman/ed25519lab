# Copyright (c) 2022-2023 The Bitcoin Core developers
# Copyright (c) 2025- The secp256k1lab Developers
# Copyright (c) 2026- The ed25519lab Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Derived from secp256k1lab (https://github.com/secp256k1lab/secp256k1lab).
# The class and method names are kept identical wherever the role of a function
# is unchanged, so that call sites in the FROST and ChillDKG reference
# implementations stay byte-for-byte comparable against upstream.

"""Test-only implementation of low-level Ed25519 field and group arithmetic.

It is designed for ease of understanding, not performance.

WARNING: This code is slow and trivially vulnerable to side channel attacks. Do
not use for anything but tests.

ENDIANNESS: all byte I/O in this module is LITTLE-ENDIAN, by definition of
Ed25519 (RFC 8032). It is stated here once and is not encoded in any method
name. Identifiers, lengths and counts that go *inside* hash inputs are
big-endian; that mixing is intentional and is the caller's responsibility.

STRICTNESS: GE.from_bytes_compressed implements RFC 8032 section 5.1.3 decoding
plus a prime-order-subgroup check. It is deliberately stricter than every
standard Ed25519 library: it rejects non-canonical encodings, small-order points
and mixed-order points. That divergence is pinned by test vectors.

Exports:
* FE: class for Ed25519 field elements
* Scalar: class for scalars modulo the group order L
* GE: class for Ed25519 group elements
* G: the Ed25519 generator point B
"""

from __future__ import annotations

from typing import Self

__all__ = ["FE", "Scalar", "GE", "G"]


class APrimeFE:
    """Objects of this class represent elements of a prime field.

    They are represented internally in numerator / denominator form, in order to
    delay inversions.
    """

    # The size of the field (also its modulus and characteristic).
    SIZE: int

    def __init__(self, a: int | Self = 0, b: int | Self = 1) -> None:
        """Initialize a field element a/b; both a and b can be ints or field elements."""
        if isinstance(a, type(self)):
            num = a._num
            den = a._den
        else:
            assert isinstance(a, int)
            num = a % self.SIZE
            den = 1
        if isinstance(b, type(self)):
            den = (den * b._num) % self.SIZE
            num = (num * b._den) % self.SIZE
        else:
            assert isinstance(b, int)
            den = (den * b) % self.SIZE
        assert den != 0
        if num == 0:
            den = 1
        self._num: int = num
        self._den: int = den

    def __add__(self, a: int | Self) -> Self:
        if isinstance(a, type(self)):
            return type(self)(self._num * a._den + self._den * a._num, self._den * a._den)
        if isinstance(a, int):
            return type(self)(self._num + self._den * a, self._den)
        return NotImplemented

    def __radd__(self, a: int) -> Self:
        return self.__add__(a)

    @classmethod
    def sum(cls, *es: Self) -> Self:
        """Compute the sum of field elements."""
        acc = cls(0)
        for e in es:
            acc = acc + e
        return acc

    def __sub__(self, a: int | Self) -> Self:
        if isinstance(a, type(self)):
            return type(self)(self._num * a._den - self._den * a._num, self._den * a._den)
        if isinstance(a, int):
            return type(self)(self._num - self._den * a, self._den)
        return NotImplemented

    def __rsub__(self, a: int) -> Self:
        return type(self)(self._den * a - self._num, self._den)

    def __mul__(self, a: int | Self) -> Self:
        if isinstance(a, type(self)):
            return type(self)(self._num * a._num, self._den * a._den)
        if isinstance(a, int):
            return type(self)(self._num * a, self._den)
        return NotImplemented

    def __rmul__(self, a: int) -> Self:
        return self.__mul__(a)

    def __truediv__(self, a: int | Self) -> Self:
        return type(self)(self, a)

    def __pow__(self, a: int) -> Self:
        return type(self)(pow(self._num, a, self.SIZE), pow(self._den, a, self.SIZE))

    def __neg__(self) -> Self:
        return type(self)(-self._num, self._den)

    def __int__(self) -> int:
        """Convert to an integer in range 0..SIZE-1. The result is cached."""
        if self._den != 1:
            self._num = (self._num * pow(self._den, -1, self.SIZE)) % self.SIZE
            self._den = 1
        return self._num

    def sqrt(self) -> Self | None:
        raise NotImplementedError

    def is_square(self) -> bool:
        return self.sqrt() is not None

    def is_even(self) -> bool:
        return int(self) & 1 == 0

    def __eq__(self, a: object) -> bool:
        if isinstance(a, type(self)):
            return (self._num * a._den - self._den * a._num) % self.SIZE == 0
        elif isinstance(a, int):
            return (self._num - self._den * a) % self.SIZE == 0
        return False

    def __hash__(self) -> int:
        return hash(int(self))

    def to_bytes(self) -> bytes:
        """Convert to a 32-byte array (LE byte order)."""
        return int(self).to_bytes(32, "little")

    @classmethod
    def from_int_checked(cls, v: int) -> Self:
        """Convert an integer (no overflow allowed)."""
        if v >= cls.SIZE:
            raise ValueError
        return cls(v)

    @classmethod
    def from_int_wrapping(cls, v: int) -> Self:
        """Convert an integer (reduced modulo SIZE)."""
        return cls(v % cls.SIZE)

    @classmethod
    def from_bytes_checked(cls, b: bytes) -> Self:
        """Convert a 32-byte array (LE byte order, no overflow allowed)."""
        if len(b) != 32:
            raise ValueError
        return cls.from_int_checked(int.from_bytes(b, "little"))

    def __str__(self) -> str:
        return f"{int(self):064x}"

    def __repr__(self) -> str:
        return f"{type(self).__qualname__}(0x{int(self):x})"


class FE(APrimeFE):
    SIZE = 2**255 - 19

    def sqrt(self) -> Self | None:
        # p % 8 == 5, so a candidate root is a^((p+3)/8); if that is wrong the
        # root, if it exists at all, is that candidate times sqrt(-1).
        v = int(self)
        s = pow(v, (self.SIZE + 3) // 8, self.SIZE)
        if s * s % self.SIZE == v:
            return type(self)(s)
        s = s * _SQRT_M1 % self.SIZE
        if s * s % self.SIZE == v:
            return type(self)(s)
        return None


_SQRT_M1 = pow(2, (FE.SIZE - 1) // 4, FE.SIZE)

# d = -121665/121666 (mod p)
_D = FE(-121665) / FE(121666)


class Scalar(APrimeFE):
    """An integer modulo L, the prime order of the Ed25519 subgroup.

    Byte I/O is little-endian.
    """

    SIZE = 2**252 + 27742317777372353535851937790883648493

    @classmethod
    def from_int_nonzero_checked(cls, v: int) -> Self:
        """Convert an integer (no zero or overflow allowed)."""
        if not (0 < v < cls.SIZE):
            raise ValueError
        return cls(v)

    @classmethod
    def from_bytes_nonzero_checked(cls, b: bytes) -> Self:
        """Convert a 32-byte array (LE byte order, no zero or overflow allowed)."""
        if len(b) != 32:
            raise ValueError
        return cls.from_int_nonzero_checked(int.from_bytes(b, "little"))

    @classmethod
    def from_bytes_wide(cls, b: bytes) -> Self:
        """Reduce a 64-byte little-endian value modulo L.

        THIS IS THE ONLY CORRECT WAY TO TURN A HASH OUTPUT INTO A SCALAR.

        The length check is load-bearing. On secp256k1 the group order is
        ~2**256, so a random 256-bit hash is almost always a valid scalar and
        parsing a digest with from_bytes_checked worked by accident. Here
        L ~ 2**252, so a random 256-bit value is below L only about 1 time in
        16: the same code fails roughly 15 sessions out of 16, late and with an
        unhelpful exception. Passing a 32-byte digest raises here instead, at
        the call site.

        This method replaces secp256k1lab's Scalar.from_bytes_wrapping. The
        rename is deliberate: the distinct name plus the length check turn a
        silent failure into a loud one.
        """
        if len(b) != 64:
            raise ValueError(
                f"from_bytes_wide requires exactly 64 bytes, got {len(b)}; "
                "hash outputs must be reduced wide, never parsed with "
                "from_bytes_checked"
            )
        return cls.from_int_wrapping(int.from_bytes(b, "little"))


class GE:
    """Objects of this class represent Ed25519 group elements (curve points).

    The curve is the twisted Edwards curve -x^2 + y^2 = 1 + d*x^2*y^2 over
    GF(2**255 - 19).

    Unlike the short Weierstrass case there is no separate point-at-infinity
    representation: the neutral element is the ordinary curve point (0, 1) with
    an ordinary 32-byte encoding. GE() constructs it, and the .infinity property
    reports it.

    Coordinates are held as FE objects, which keep a numerator/denominator form
    internally, so the divisions in the affine addition law below are deferred
    and no modular inversion happens until a coordinate is actually read.
    """

    ORDER = Scalar.SIZE
    # Cofactor. Present because every security argument in this protocol turns
    # on it; the arithmetic here never multiplies by it.
    COFACTOR = 8

    def __init__(self, x: int | FE | None = None, y: int | FE | None = None) -> None:
        """Construct a curve point; with no arguments, the neutral element."""
        if x is None and y is None:
            x, y = FE(0), FE(1)
        elif x is None or y is None:
            raise ValueError("GE takes either no coordinates or both")
        fx = x if isinstance(x, FE) else FE(x)
        fy = y if isinstance(y, FE) else FE(y)
        if -(fx**2) + fy**2 != 1 + _D * fx**2 * fy**2:
            raise ValueError("point is not on the curve")
        self._x: FE = fx
        self._y: FE = fy

    @classmethod
    def _unchecked(cls, x: FE, y: FE) -> GE:
        """Construct without re-verifying the curve equation.

        Used only for the output of the addition law, which is closed over the
        curve: adding two curve points always yields a curve point, so checking
        again is pure cost. Every point that enters the library from outside
        goes through the public constructor or from_bytes_compressed, both of
        which do check. test_addition_output_is_always_on_the_curve pins this.
        """
        obj = cls.__new__(cls)
        obj._x = x
        obj._y = y
        return obj

    @property
    def x(self) -> FE:
        return self._x

    @property
    def y(self) -> FE:
        return self._y

    @property
    def infinity(self) -> bool:
        """Whether this is the neutral element (0, 1).

        Both coordinates are checked. Testing only x == 0 would also match
        (0, -1), which is the point of ORDER TWO, not the neutral element. That
        conflation is a known silent failure mode; do not reintroduce it.
        """
        return self._x == 0 and self._y == 1

    def __add__(self, a: GE) -> GE:
        """Add two points using the complete affine addition law for a = -1.

        The law has no exceptional cases: it is correct for equal points, for
        the neutral element, and for the torsion points, because d is not a
        square modulo p.
        """
        if not isinstance(a, GE):
            return NotImplemented
        x1, y1, x2, y2 = self._x, self._y, a._x, a._y
        k = _D * x1 * x2 * y1 * y2
        x3 = (x1 * y2 + y1 * x2) / (1 + k)
        y3 = (y1 * y2 + x1 * x2) / (1 - k)
        return GE._unchecked(x3, y3)

    def __sub__(self, a: GE) -> GE:
        if not isinstance(a, GE):
            return NotImplemented
        return self + (-a)

    def __neg__(self) -> GE:
        return GE._unchecked(-self._x, self._y)

    def __rmul__(self, a: int | Scalar) -> GE:
        """Multiply by a scalar (double-and-add; variable time in the scalar)."""
        if isinstance(a, Scalar):
            k = int(a)
        elif isinstance(a, int):
            k = a % self.ORDER
        else:
            return NotImplemented
        return _mul_int(self, k)

    __mul__ = __rmul__

    def __eq__(self, a: object) -> bool:
        if not isinstance(a, GE):
            return NotImplemented
        return self._x == a._x and self._y == a._y

    def __hash__(self) -> int:
        return hash(self.to_bytes_compressed())

    @staticmethod
    def sum(*ps: GE) -> GE:
        """Compute the sum of group elements. GE.sum() is the neutral element."""
        acc = GE()
        for p in ps:
            acc = acc + p
        return acc

    @staticmethod
    def batch_mul(*aps: tuple[Scalar, GE]) -> GE:
        """Compute the sum of scalar-point products.

        Reference implementation: no Straus or Pippenger, just the obvious loop.
        """
        acc = GE()
        for a, p in aps:
            acc = acc + a * p
        return acc

    # -- encoding -----------------------------------------------------------

    def to_bytes_compressed(self) -> bytes:
        """Encode as 32 bytes: little-endian y, with the sign of x in bit 255.

        The neutral element encodes as 0x01 followed by 31 zero bytes. There is
        deliberately no to_bytes_compressed_with_infinity variant: the neutral
        element has a native encoding here and needs no sentinel.
        """
        b = bytearray(int(self._y).to_bytes(32, "little"))
        b[31] |= (int(self._x) & 1) << 7
        return bytes(b)

    @staticmethod
    def from_bytes_compressed(b: bytes) -> GE:
        """Strictly decode 32 bytes. RFC 8032 section 5.1.3 plus a subgroup check.

        Rejects, in this order:
          - wrong length
          - non-canonical y (y >= p)
          - y for which no x exists on the curve
          - x == 0 with the sign bit set (non-canonical neutral encoding)
          - any point outside the prime-order subgroup, that is every
            small-order point and every mixed-order point [k]B + T

        The neutral element IS accepted; it is a legitimate element of the
        prime-order subgroup. Call sites that must not accept it check
        .infinity explicitly. There is deliberately no
        from_bytes_compressed_with_infinity to hide that decision in.
        """
        if len(b) != 32:
            raise ValueError(f"expected 32 bytes, got {len(b)}")
        sign = b[31] >> 7
        y = int.from_bytes(bytes(b[:31]) + bytes([b[31] & 0x7F]), "little")
        if y >= FE.SIZE:
            raise ValueError("non-canonical encoding: y >= p")
        x = _recover_x(FE(y), sign)
        if x is None:
            raise ValueError("not a curve point: no square root for x")
        if int(x) == 0 and sign == 1:
            raise ValueError("non-canonical encoding: x == 0 with sign bit set")
        p = GE(x, FE(y))
        if not p.in_prime_order_subgroup():
            raise ValueError("point is not in the prime-order subgroup")
        return p

    # -- subgroup -----------------------------------------------------------

    def in_prime_order_subgroup(self) -> bool:
        """Whether [L]P is the neutral element.

        Deliberately the plain formulation, for clarity: the check runs per
        received point, not per session. A production port can substitute
        Pornin's point-halving check (eprint 2022/1164); the predicate is
        identical.
        """
        return _mul_int(self, self.ORDER).infinity

    def __str__(self) -> str:
        return self.to_bytes_compressed().hex()

    def __repr__(self) -> str:
        if self.infinity:
            return "GE()"
        return f"GE(0x{int(self._x):x}, 0x{int(self._y):x})"


def _recover_x(y: FE, sign: int) -> FE | None:
    """RFC 8032 section 5.1.3, steps 2 to 4. None if no square root exists.

    Does not apply the "x == 0 and sign == 1" rule: that rule is about the
    encoding being non-canonical, not about the point, so the caller applies it.
    """
    v = 1 + _D * y**2
    if v == 0:
        return None
    x = ((y**2 - 1) / v).sqrt()
    if x is None:
        return None
    if int(x) != 0 and int(x) & 1 != sign:
        x = -x
    return x


def _mul_int(p: GE, k: int) -> GE:
    """Double-and-add. Variable time in k; reference implementation only."""
    if k < 0:
        raise ValueError("negative scalar")
    acc = GE()
    a = p
    while k:
        if k & 1:
            acc = acc + a
        a = a + a
        k >>= 1
    return acc


def _base_point() -> GE:
    # RFC 8032 section 5.1: B is the point with y = 4/5 and even x.
    y = FE(4) / FE(5)
    x = _recover_x(y, 0)
    assert x is not None
    return GE(x, y)


G = _base_point()
