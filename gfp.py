from __future__ import print_function, division
from modinv import modinv
"""
By Willem Hengeveld <itsme@xs4all.nl>

Operations modulus a prime number
"""

class FiniteField:
    """
    FiniteField implements a value modulus a number.
    """
    class Value:
        """
        represent a value in the FiniteField

        this class forwards all operations to the FiniteField class
        """
        def __init__(self, field, value):
            self.field = field
            self.value = int(value)

        # Value * int
        def __add__(self, rhs): return self.field.add(self, self.field.value(rhs))
        def __sub__(self, rhs): return self.field.sub(self, self.field.value(rhs))
        def __mul__(self, rhs): return self.field.mul(self, self.field.value(rhs))
        def __div__(self, rhs): return self.field.div(self, self.field.value(rhs))
        def __truediv__(self, rhs): return self.__div__(rhs)
        def __floordiv__(self, rhs): return self.__div__(rhs)
        def __pow__(self, rhs): return self.field.pow(self, rhs)

        # int * Value
        def __radd__(self, lhs): return self.field.add(self.field.value(lhs), self)
        def __rsub__(self, lhs): return self.field.sub(self.field.value(lhs), self)
        def __rmul__(self, lhs): return self.field.mul(self.field.value(lhs), self)
        def __rdiv__(self, lhs): return self.field.div(self.field.value(lhs), self)
        def __rtruediv__(self, lhs): return self.__rdiv__(lhs)
        def __rfloordiv__(self, lhs): return self.__rdiv__(lhs)
        def __rpow__(self, lhs): return self.field.pow(self.field.value(lhs), self)

        def __eq__(self, rhs): return self.field.eq(self, self.field.value(rhs))
        def __ne__(self, rhs): return not (self==rhs)

        def __str__(self): return "0x%x" % self.value
        def __neg__(self): return self.field.neg(self)


        def sqrt(self, flag): return self.field.sqrt(self, flag)
        def issquare(self): return self.field.issquare(self)
        def inverse(self):  return self.field.inverse(self)
        def __nonzero__(self): return self.field.nonzero(self)
        def __bool__(self): return self.__nonzero__() != 0
        def __int__(self): return self.field.intvalue(self)

        def samefield(a,b): 
            """
            determine if a uses the same field 
            """
            if a.field != b.field: 
                print("field mismatch")
            return True

        def sqrtflag(self):
            return self.value%2


    def __init__(self, p):
        self.p = p

    """
    several basic operators


    Complexity:
      mul:    M(n)+D(n)

      barrett     2*M(n)
      montgomery  1.66*M(n)
      mclaughlin  1.5*M(n)

    """
    def add(self, lhs, rhs): return lhs.samefield(rhs) and self.value((lhs.value + rhs.value) % self.p)
    def sub(self, lhs, rhs): return lhs.samefield(rhs) and self.value((lhs.value - rhs.value) % self.p)
    def mul(self, lhs, rhs): return lhs.samefield(rhs) and self.value((lhs.value * rhs.value) % self.p)
    def div(self, lhs, rhs): return lhs.samefield(rhs) and self.value((lhs.value * rhs.inverse()) % self.p)
    def pow(self, lhs, rhs): return self.value(pow(lhs.value, int(rhs), self.p))
    def eq(self, lhs, rhs): return (lhs.value-rhs.value) % self.p == 0
    def neg(self, val): return self.value(self.p-val.value)

    # nr is square legendre symbol == 1
    def issquare(self, val):
        return val**((self.p-1)//2)==1
    def sqrt(self, val, flag):
        """
        calculate the square root modulus p
        """
        if not val:
            return val
        sw = self.p % 8
        if sw==3 or sw==7:
            res = val**((self.p+1)//4)
        elif sw==5:
            x = val**((self.p+1)//4)
            if x==1:
                res = val**((self.p+3)//8)
            else:
                res = (4*val)**((self.p-5)//8)*2*val
        else:
            # todo: Tonelli-Shanks algorithm
            raise Exception("modsqrt non supported for (p%8)==1")
        if res*res != val:
            return None
        if res.value%2==flag:
            return res
        else:
            return -res

    def inverse(self, value):
        """
        calculate the multiplicative inverse

        Complexity:  O(M(n)*log(n))
        """
        return modinv(value.value, self.p)

    def nonzero(self, x):
        return 1 if not (x.value % self.p)==0 else 0

    def value(self, x):
        """
        converts an integer or FinitField.Value to a value of this FiniteField.
        """
        return x if isinstance(x, FiniteField.Value) and x.field==self else FiniteField.Value(self, x)

    def zero(self):
        """
        returns the additive identity value

        meaning:  a + 0 = a
        """
        return FiniteField.Value(self, 0)
    def one(self):
        """
        returns the multiplicative identity value

        meaning a * 1 = a
        """
        return FiniteField.Value(self, 1)

    def intvalue(self, x):
        return x.value % self.p


