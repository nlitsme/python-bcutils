from gfp import FiniteField
from ec import EllipticCurve
"""
By Willem Hengeveld <itsme@xs4all.nl>

ecdsa implementation in python

demonstrating several 'unconventional' calculations,
like finding a public key from a signature,
and finding a private key from 2 signatures with identical 'r'
"""



class ECDSA:
    """
    Digital Signature Algorithm using Elliptic Curves
    """
    def __init__(self, ec, G, n):
        self.ec= ec
        self.G= G
        self.GFn= FiniteField(n)

    def calcpub(self, privkey):
        """
        calculate the public key for private key x

        return G*x
        """
        return self.G * self.GFn.value(privkey)

    def sign(self, message, privkey, secret):
        """
        sign the message using private key and sign secret

        for signsecret k, message m, privatekey x
        return (G*k,  (m+x*r)/k)
        """
        m= self.GFn.value(message)
        x= self.GFn.value(privkey)
        k= self.GFn.value(secret)

        R= self.G * k

        r= self.GFn.value(R.x)
        s= (m + x*r) / k

        return (r, s)

     
    def verify(self, message, pubkey, rnum, snum):
        """
        Verify the signature

        for message m, pubkey Y, signature (r,s)

        r = xcoord(R)

        verify that :  G*m+Y*r=R*s

        this is true because: { Y=G*x, and R=G*k, s=(m+x*r)/k }
         
        G*m+G*x*r = G*k*(m+x*r)/k  ->
        G*(m+x*r) = G*(m+x*r)

        several ways to do the verification:
            r == xcoord[ G*(m/s) + Y*(r/s) ]  <<< the standard way
            R * s == G*m + Y*r
            r == xcoord[ (G*m + Y*r)/s) ]
 
        """
        m= self.GFn.value(message)
        r= self.GFn.value(rnum)
        s= self.GFn.value(snum)

        R = self.G * (m/s) + pubkey * (r/s)

        # alternative methods of verifying
        #RORG= self.ec.decompress(r, 0)
        #RR = self.G * m + pubkey * r
        #print "#1: %s .. %s"  % (RR, RORG*s)
        #print "#2: %s .. %s"  % (RR*(1/s), r)
        #print "#3: %s .. %s"  % (R, r)

        return R.x == r

    def findpk(self, message, rnum, snum, flag):
        """
        find pubkey Y from message m, signature (r,s)
        Y = (R*s-G*m)/r

        note that there are 2 pubkeys related to a signature
        """
        m= self.GFn.value(message)
        r= self.GFn.value(rnum)
        s= self.GFn.value(snum)

        R= self.ec.decompress(r, flag)

        #return (R*s - self.G * m)*(1/r)
        return R*(s/r) - self.G * (m/r)

    def findpk2(self, r1, s1, r2, s2, flag1, flag2):
        """
        find pubkey Y from 2 different signature on the same message
        sigs: (r1,s1) and (r2,s2)

        returns  (R1*s1-R2*s2)/(r1-r2)
        """
        R1= self.ec.decompress(r1, flag1)
        R2= self.ec.decompress(r2, flag2)

        rdiff= self.GFn.value(r1-r2)

        return (R1*s1-R2*s2)*(1/rdiff)

    def crack2(self, r, s1, s2, m1, m2):
        """
        find signsecret and privkey from duplicate 'r'

        signature (r,s1) for message m1
        and signature (r,s2) for message m2

        s1= (m1 + x*r)/k
        s2= (m2 + x*r)/k

        subtract -> (s1-s2) = (m1-m2)/k  ->  k = (m1-m2)/(s1-s2)

        -> privkey =  (s1*k-m1)/r  .. or  (s2*k-m2)/r
        """
        sdelta= self.GFn.value(s1-s2)
        mdelta= self.GFn.value(m1-m2)

        secret= mdelta / sdelta
        x1= self.crack1(r, s1, m1, secret)
        x2= self.crack1(r, s2, m2, secret)

        if x1!=x2:
            print "x1=%s" % x1
            print "x2=%s" % x2

        return (secret, x1)

    def crack1(self, rnum, snum, message, signsecret):
        """
        find privkey, given signsecret k, message m, signature (r,s)

        x= (s*k-m)/r
        """
        m= self.GFn.value(message)
        r= self.GFn.value(rnum)
        s= self.GFn.value(snum)
        k= self.GFn.value(signsecret)
        return (s*k-m)/r

    def find_k(self, message, privkey, rnum, snum):
        """
        find signing secret used to create signature, given message, privkey and signature

        k= (m+x*r)/s
        """
        m= self.GFn.value(message)
        r= self.GFn.value(rnum)
        s= self.GFn.value(snum)
        x= self.GFn.value(privkey)
        return (m+x*r)/s

def secp256k1():
    """
    create the secp256k1 curve
    """
    GFp= FiniteField(2**256 - 2**32 - 977)
    ec= EllipticCurve(GFp, 0, 7)
    return ECDSA(ec, ec.point( 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8  ), 2**256 - 432420386565659656852420866394968145599)


