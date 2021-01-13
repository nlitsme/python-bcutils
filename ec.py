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
        def __hash__(self): return int(self.x+self.y)

        def __str__(self): return "(%s,%s)" % (self.x, self.y)
        def __neg__(self): return self.curve.neg(self)

        def __nonzero__(self): return self.curve.nonzero(self)
        def __bool__(self): return self.__nonzero__() != 0
        def isoncurve(self):
            return self.curve.isoncurve(self)

    def __init__(self, field, a, b):
        self.field = field
        self.a = field.value(a)
        self.b = field.value(b)

    def add(self, p, q):
        """
        perform elliptic curve addition
        """
        if not p: return q
        if not q: return p

        # calculate the slope of the intersection line
        if p==q:
            if p.y==0:
                return self.zero()
            l = (3* p.x**2 + self.a) // (2* p.y)
        elif p.x==q.x:
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
        if scalar<0:
            raise Exception("negative scalar")
        accumulator = self.zero()
        shifter = pt
        while scalar != 0:
            bit = scalar % 2
            if bit:
                accumulator += shifter
            shifter += shifter
            scalar //= 2

        return accumulator

    def div(self, pt, scalar):
        """
        scalar division:  P / a = P * (1/a)

        scalar is assumed to be of type FiniteField(grouporder)
        """
        return pt * (1//scalar)

    def eq(self, lhs, rhs): return lhs.x==rhs.x and lhs.y==rhs.y
    def neg(self, pt):
        return self.point(pt.x, -pt.y)
    def nonzero(self, pt):
        return 1 if pt.x or pt.y else 0
    def zero(self):
        """
        Return the additive identity point ( aka '0' )

        P + 0 = P
        """
        return self.point(self.field.zero(), self.field.zero())

    def point(self, x, y):
        """
        construct a point from 2 values
        """
        return WeierstrassCurve.Point(self, self.field.value(x), self.field.value(y))

    def isoncurve(self, p):
        """
        verifies if a point is on the curve
        """
        return not p or (p.y**2 == p.x**3 + self.a*p.x + self.b)

    def decompress(self, x, flag):
        """
        calculate the y coordinate given only the x value.
        there are 2 possible solutions, use 'flag' to select.
        """
        x = self.field.value(x)
        ysquare = x**3 + self.a*x+self.b

        return self.point(x, ysquare.sqrt(flag))

