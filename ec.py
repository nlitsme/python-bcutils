"""
By Willem Hengeveld <itsme@xs4all.nl>

Elliptic curve operations
"""

class WeierstrassCurve:
    """
    WeierstrassCurve implements a point on a elliptic curve of form

    y^2 = x^3 + A*x + B

    with 4a^3+27b^2 != 0 (mod p)
    """
    class Point:
        """
        represent a value in the WeierstrassCurve

        this class forwards all operations to the WeierstrassCurve class
        """
        def __init__(self, curve, x, y):
            self.curve = curve
            self.x = x
            self.y = y
        # Point + Point
        def __add__(self, rhs): return self.curve.add(self, rhs)
        def __sub__(self, rhs): return self.curve.sub(self, rhs)

        # Point * int   or Point * Value
        def __mul__(self, rhs): return self.curve.mul(self, rhs)
        def __rmul__(self, lhs): return self.curve.mul(self, lhs)
        def __div__(self, rhs): return self.curve.div(self, rhs)
        def __truediv__(self, rhs): return self.__div__(rhs)
        def __floordiv__(self, rhs): return self.__div__(rhs)

        def __eq__(self, rhs): return self.curve.eq(self, rhs)
        def __ne__(self, rhs): return not (self==rhs)

        def __le__(self, rhs): raise Exception("points are not ordered")
        def __lt__(self, rhs): raise Exception("points are not ordered")
        def __ge__(self, rhs): raise Exception("points are not ordered")
        def __gt__(self, rhs): raise Exception("points are not ordered")
        def __hash__(self): return int(self.x+self.y) if self else 0

        def __str__(self): return "(%s,%s)" % (self.x, self.y)
        def __neg__(self): return self.curve.neg(self)

        def __nonzero__(self): return self.curve.nonzero(self)
        def __bool__(self): return self.__nonzero__() != 0
        def isoncurve(self):
            return self.curve.isoncurve(self)
        def __repr__(self):
            return f"({self.x}, {self.y})"

    def __init__(self, field, a, b):
        self.field = field
        self.a = field.value(a)
        self.b = field.value(b)

    def discriminant(self):
        return -16*(4*self.a**3+27*self.b**2)

    def __str__(self): return "Weierstrass(%s;%s;%s)" % (self.field, self.a, self.b)

    def add(self, p, q):
        """
        perform elliptic curve addition
        """
        if not p: return q
        if not q: return p

        # calculate the slope of the intersection line
        if p==q:
            if not p:
                return self.zero()
            l = (3* p.x**2 + self.a) // (2* p.y)
        elif p.x==q.x: # implies: p.y == -q.y
            return self.zero()
        else:
            l = (p.y-q.y)//(p.x-q.x)

        # calculate the intersection point
        x = l**2 - ( p.x + q.x )
        y = l*(p.x-x)-p.y
        return self.point(x,y)

    # subtraction is :  a - b  =  a + -b
    def sub(self, lhs, rhs): return lhs + -rhs

    # scalar multiplication is implemented like repeated addition
    def mul(self, pt, scalar): 
        scalar = int(scalar)
        ispos = True
        if scalar<0:
            ispos = False
            scalar = -scalar
        accumulator = self.zero()
        shifter = pt
        while scalar != 0:
            bit = scalar % 2
            if bit:
                accumulator += shifter
            shifter += shifter
            scalar //= 2

        if not ispos:
            accumulator = -accumulator
        return accumulator

    def div(self, pt, scalar):
        """
        scalar division:  P / a = P * (1/a)

        scalar is assumed to be of type FiniteField(grouporder)
        """
        return pt * (1//scalar)

    def eq(self, lhs, rhs): return lhs.x==rhs.x and lhs.y==rhs.y if lhs and rhs else not(lhs and rhs)
    def neg(self, pt):
        if not pt:
            return pt
        return self.point(pt.x, -pt.y)
    def nonzero(self, pt):
        return not (pt.x is None and pt.y is None)
    def zero(self):
        """
        Return the additive identity point ( aka '0' )

        P + 0 = P
        """
        return self.point(None, None)

    def point(self, x, y):
        """
        construct a point from 2 values
        """
        return WeierstrassCurve.Point(self, self.coord(x), self.coord(y))

    def coord(self, x):
        if x is None:
            return None
        return self.field.value(x)

    def isoncurve(self, p):
        """
        verifies if a point is on the curve
        """
        a, b = self.a, self.b
        x, y = p.x, p.y
        return not p or (y**2 == x**3 + a*x + b)

    def decompress(self, x, flag):
        """
        calculate the y coordinate given only the x value.
        there are 2 possible solutions, use 'flag' to select.
        """
        x = self.coord(x)
        a, b = self.a, self.b
        ysquare = x**3 + a*x + b
        y = ysquare.sqrt(flag)
        if y is None:
            return

        return self.point(x, y)

    def decompressy(self, y, flag):
        """
        calculate the x coordinate given only the y value.
        there are 3 possible solutions, use 'flag' to select.
        """
        y = self.coord(y)
        if self.a:
            # works only for a==0
            return
        xcube  = y**2-self.b
        x = xcube.cubert(flag)
        if x is None:
            return

        return self.point(x, y)

