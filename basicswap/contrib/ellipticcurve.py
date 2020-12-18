#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# Implementation of elliptic curves, for cryptographic applications.
#
# This module doesn't provide any way to choose a random elliptic
# curve, nor to verify that an elliptic curve was chosen randomly,
# because one can simply use NIST's standard curves.
#
# Notes from X9.62-1998 (draft):
#   Nomenclature:
#     - Q is a public key.
#     The "Elliptic Curve Domain Parameters" include:
#     - q is the "field size", which in our case equals p.
#     - p is a big prime.
#     - G is a point of prime order (5.1.1.1).
#     - n is the order of G (5.1.1.1).
#   Public-key validation (5.2.2):
#     - Verify that Q is not the point at infinity.
#     - Verify that X_Q and Y_Q are in [0,p-1].
#     - Verify that Q is on the curve.
#     - Verify that nQ is the point at infinity.
#   Signature generation (5.3):
#     - Pick random k from [1,n-1].
#   Signature checking (5.4.2):
#     - Verify that r and s are in [1,n-1].
#
# Version of 2008.11.25.
#
# Revision history:
#    2005.12.31 - Initial version.
#    2008.11.25 - Change CurveFp.is_on to contains_point.
#
# Written in 2005 by Peter Pearson and placed in the public domain.

def inverse_mod(a, m):
    """Inverse of a mod m."""

    if a < 0 or m <= a:
        a = a % m

    # From Ferguson and Schneier, roughly:

    c, d = a, m
    uc, vc, ud, vd = 1, 0, 0, 1
    while c != 0:
        q, c, d = divmod(d, c) + (c,)
        uc, vc, ud, vd = ud - q * uc, vd - q * vc, uc, vc

    # At this point, d is the GCD, and ud*a+vd*m = d.
    # If d == 1, this means that ud is a inverse.

    assert d == 1
    if ud > 0:
        return ud
    else:
        return ud + m


def modular_sqrt(a, p):
    # from http://eli.thegreenplace.net/2009/03/07/computing-modular-square-roots-in-python/
    """ Find a quadratic residue (mod p) of 'a'. p
    must be an odd prime.

    Solve the congruence of the form:
    x^2 = a (mod p)
    And returns x. Note that p - x is also a root.

    0 is returned is no square root exists for
    these a and p.

    The Tonelli-Shanks algorithm is used (except
    for some simple cases in which the solution
    is known from an identity). This algorithm
    runs in polynomial time (unless the
    generalized Riemann hypothesis is false).
    """
    # Simple cases
    #
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return p
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    # Partition p-1 to s * 2^e for an odd s (i.e.
    # reduce all the powers of 2 from p-1)
    #
    s = p - 1
    e = 0
    while s % 2 == 0:
        s /= 2
        e += 1

    # Find some 'n' with a legendre symbol n|p = -1.
    # Shouldn't take long.
    #
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    # Here be dragons!
    # Read the paper "Square roots from 1; 24, 51,
    # 10 to Dan Shanks" by Ezra Brown for more
    # information
    #

    # x is a guess of the square root that gets better
    # with each iteration.
    # b is the "fudge factor" - by how much we're off
    # with the guess. The invariant x^2 = ab (mod p)
    # is maintained throughout the loop.
    # g is used for successive powers of n to update
    # both a and b
    # r is the exponent - decreases with each update
    #
    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m


def legendre_symbol(a, p):
    """ Compute the Legendre symbol a|p using
    Euler's criterion. p is a prime, a is
    relatively prime to p (if p divides
    a, then a|p = 0)

    Returns 1 if a has a square root modulo
    p, -1 otherwise.
    """
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls


def jacobi_symbol(n, k):
    """Compute the Jacobi symbol of n modulo k

    See http://en.wikipedia.org/wiki/Jacobi_symbol

    For our application k is always prime, so this is the same as the Legendre symbol."""
    assert k > 0 and k & 1, "jacobi symbol is only defined for positive odd k"
    n %= k
    t = 0
    while n != 0:
        while n & 1 == 0:
            n >>= 1
            r = k & 7
            t ^= (r == 3 or r == 5)
        n, k = k, n
        t ^= (n & k & 3 == 3)
        n = n % k
    if k == 1:
        return -1 if t else 1
    return 0


class CurveFp(object):
    """Elliptic Curve over the field of integers modulo a prime."""
    def __init__(self, p, a, b):
        """The curve of points satisfying y^2 = x^3 + a*x + b (mod p)."""
        self.__p = p
        self.__a = a
        self.__b = b

    def p(self):
        return self.__p

    def a(self):
        return self.__a

    def b(self):
        return self.__b

    def contains_point(self, x, y):
        """Is the point (x,y) on this curve?"""
        return (y * y - (x * x * x + self.__a * x + self.__b)) % self.__p == 0


class Point(object):
    """ A point on an elliptic curve. Altering x and y is forbidding,
        but they can be read by the x() and y() methods."""
    def __init__(self, curve, x, y, order=None):
        """curve, x, y, order; order (optional) is the order of this point."""
        self.__curve = curve
        self.__x = x
        self.__y = y
        self.__order = order
        # self.curve is allowed to be None only for INFINITY:
        if self.__curve:
            assert self.__curve.contains_point(x, y)
        if order:
            assert self * order == INFINITY

    def __eq__(self, other):
        """Return 1 if the points are identical, 0 otherwise."""
        if self.__curve == other.__curve \
           and self.__x == other.__x \
           and self.__y == other.__y:
            return 1
        else:
            return 0

    def __add__(self, other):
        """Add one point to another point."""

        # X9.62 B.3:
        if other == INFINITY:
            return self
        if self == INFINITY:
            return other
        assert self.__curve == other.__curve
        if self.__x == other.__x:
            if (self.__y + other.__y) % self.__curve.p() == 0:
                return INFINITY
            else:
                return self.double()

        p = self.__curve.p()

        l = ((other.__y - self.__y) * inverse_mod(other.__x - self.__x, p)) % p

        x3 = (l * l - self.__x - other.__x) % p
        y3 = (l * (self.__x - x3) - self.__y) % p

        return Point(self.__curve, x3, y3)

    def __sub__(self, other):
        #The inverse of a point P=(xP,yP) is its reflexion across the x-axis : P′=(xP,−yP).
        #If you want to compute Q−P, just replace yP by −yP in the usual formula for point addition.

        # X9.62 B.3:
        if other == INFINITY:
            return self
        if self == INFINITY:
            return other
        assert self.__curve == other.__curve

        p = self.__curve.p()
        #opi = inverse_mod(other.__y, p)
        opi = -other.__y % p
        #print(opi)
        #print(-other.__y % p)

        if self.__x == other.__x:
            if (self.__y + opi) % self.__curve.p() == 0:
                return INFINITY
            else:
                return self.double

        l = ((opi - self.__y) * inverse_mod(other.__x - self.__x, p)) % p

        x3 = (l * l - self.__x - other.__x) % p
        y3 = (l * (self.__x - x3) - self.__y) % p

        return Point(self.__curve, x3, y3)

    def __mul__(self, e):
        if self.__order:
            e %= self.__order
        if e == 0 or self == INFINITY:
            return INFINITY
        result, q = INFINITY, self
        while e:
            if e & 1:
                result += q
            e, q = e >> 1, q.double()
        return result

    """
    def __mul__(self, other):
        #Multiply a point by an integer.

        def leftmost_bit( x ):
            assert x > 0
            result = 1
            while result <= x: result = 2 * result
            return result // 2

        e = other
        if self.__order: e = e % self.__order
        if e == 0: return INFINITY
        if self == INFINITY: return INFINITY
        assert e > 0

        # From X9.62 D.3.2:

        e3 = 3 * e
        negative_self = Point( self.__curve, self.__x, -self.__y, self.__order )
        i = leftmost_bit( e3 ) // 2
        result = self
        # print "Multiplying %s by %d (e3 = %d):" % ( self, other, e3 )
        while i > 1:
            result = result.double()
            if ( e3 & i ) != 0 and ( e & i ) == 0: result = result + self
            if ( e3 & i ) == 0 and ( e & i ) != 0: result = result + negative_self
            # print ". . . i = %d, result = %s" % ( i, result )
            i = i // 2

        return result
    """

    def __rmul__(self, other):
        """Multiply a point by an integer."""

        return self * other

    def __str__(self):
        if self == INFINITY:
            return "infinity"
        return "(%d, %d)" % (self.__x, self.__y)

    def inverse(self):
        return Point(self.__curve, self.__x, -self.__y % self.__curve.p())

    def double(self):
        """Return a new point that is twice the old."""

        if self == INFINITY:
            return INFINITY

        # X9.62 B.3:

        p = self.__curve.p()
        a = self.__curve.a()

        l = ((3 * self.__x * self.__x + a) * inverse_mod(2 * self.__y, p)) % p

        x3 = (l * l - 2 * self.__x) % p
        y3 = (l * (self.__x - x3) - self.__y) % p

        return Point(self.__curve, x3, y3)

    def x(self):
        return self.__x

    def y(self):
        return self.__y

    def pair(self):
        return (self.__x, self.__y)

    def curve(self):
        return self.__curve

    def order(self):
        return self.__order


# This one point is the Point At Infinity for all purposes:
INFINITY = Point(None, None, None)


def __main__():

    class FailedTest(Exception):
        pass

    def test_add(c, x1, y1, x2, y2, x3, y3):
        """We expect that on curve c, (x1,y1) + (x2, y2 ) = (x3, y3)."""
        p1 = Point(c, x1, y1)
        p2 = Point(c, x2, y2)
        p3 = p1 + p2
        print("%s + %s = %s" % (p1, p2, p3))
        if p3.x() != x3 or p3.y() != y3:
            raise FailedTest("Failure: should give (%d,%d)." % (x3, y3))
        else:
            print(" Good.")

    def test_double(c, x1, y1, x3, y3):
        """We expect that on curve c, 2*(x1,y1) = (x3, y3)."""
        p1 = Point(c, x1, y1)
        p3 = p1.double()
        print("%s doubled = %s" % (p1, p3))
        if p3.x() != x3 or p3.y() != y3:
            raise FailedTest("Failure: should give (%d,%d)." % (x3, y3))
        else:
            print(" Good.")

    def test_double_infinity(c):
        """We expect that on curve c, 2*INFINITY = INFINITY."""
        p1 = INFINITY
        p3 = p1.double()
        print("%s doubled = %s" % (p1, p3))
        if p3.x() != INFINITY.x() or p3.y() != INFINITY.y():
            raise FailedTest("Failure: should give (%d,%d)." % (INFINITY.x(), INFINITY.y()))
        else:
            print(" Good.")

    def test_multiply(c, x1, y1, m, x3, y3):
        """We expect that on curve c, m*(x1,y1) = (x3,y3)."""
        p1 = Point(c, x1, y1)
        p3 = p1 * m
        print("%s * %d = %s" % (p1, m, p3))
        if p3.x() != x3 or p3.y() != y3:
            raise FailedTest("Failure: should give (%d,%d)." % (x3, y3))
        else:
            print(" Good.")

    # A few tests from X9.62 B.3:

    c = CurveFp(23, 1, 1)
    test_add(c, 3, 10, 9, 7, 17, 20)
    test_double(c, 3, 10, 7, 12)
    test_add(c, 3, 10, 3, 10, 7, 12)    # (Should just invoke double.)
    test_multiply(c, 3, 10, 2, 7, 12)

    test_double_infinity(c)

    # From X9.62 I.1 (p. 96):

    g = Point(c, 13, 7, 7)

    check = INFINITY
    for i in range(7 + 1):
        p = (i % 7) * g
        print("%s * %d = %s, expected %s . . ." % (g, i, p, check))
        if p == check:
            print(" Good.")
        else:
            raise FailedTest("Bad.")
        check = check + g

    # NIST Curve P-192:
    p = 6277101735386680763835789423207666416083908700390324961279
    r = 6277101735386680763835789423176059013767194773182842284081
    #s = 0x3045ae6fc8422f64ed579528d38120eae12196d5L
    c = 0x3099d2bbbfcb2538542dcd5fb078b6ef5f3d6fe2c745de65
    b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
    Gx = 0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012
    Gy = 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811

    c192 = CurveFp(p, -3, b)
    p192 = Point(c192, Gx, Gy, r)

    # Checking against some sample computations presented
    # in X9.62:

    d = 651056770906015076056810763456358567190100156695615665659
    Q = d * p192
    if Q.x() != 0x62B12D60690CDCF330BABAB6E69763B471F994DD702D16A5:
        raise FailedTest("p192 * d came out wrong.")
    else:
        print("p192 * d came out right.")

    k = 6140507067065001063065065565667405560006161556565665656654
    R = k * p192
    if R.x() != 0x885052380FF147B734C330C43D39B2C4A89F29B0F749FEAD \
       or R.y() != 0x9CF9FA1CBEFEFB917747A3BB29C072B9289C2547884FD835:
        raise FailedTest("k * p192 came out wrong.")
    else:
        print("k * p192 came out right.")

    u1 = 2563697409189434185194736134579731015366492496392189760599
    u2 = 6266643813348617967186477710235785849136406323338782220568
    temp = u1 * p192 + u2 * Q
    if temp.x() != 0x885052380FF147B734C330C43D39B2C4A89F29B0F749FEAD \
       or temp.y() != 0x9CF9FA1CBEFEFB917747A3BB29C072B9289C2547884FD835:
        raise FailedTest("u1 * p192 + u2 * Q came out wrong.")
    else:
        print("u1 * p192 + u2 * Q came out right.")


if __name__ == "__main__":
    __main__()
