from __future__ import print_function, division
"""
By Willem Hengeveld <itsme@xs4all.nl>

modular inverse, and Greated Common Divisor calculation
"""
# (gcd,c,d)= GCD(a, b)  ===> a*c+b*d==gcd
#   also:    (c+b)*a+(d-a)*b == c*a+d*b
def GCD(a, b):
    prevx, x = 1, 0
    prevy, y = 0, 1
    while b:
        q = a//b
        x, prevx = prevx - q*x, x
        y, prevy = prevy - q*y, y
        a, b = b, a%b
    return a, prevx, prevy


def modinv(x, m):
    (gcd, c, d)= GCD(x,m)
    if c<0:
        c += m
    return c


def gcd(a, b):
    (gcd, c, d)= GCD(a,b)
    return gcd


