from __future__ import print_function, division
from gfp import FiniteField
from ec import WeierstrassCurve
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
        self.ec = ec
        self.G = G
        self.GFn = FiniteField(n)

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
        m = self.GFn.value(message)
        x = self.GFn.value(privkey)
        k = self.GFn.value(secret)

        R = self.G * k

        r = self.GFn.value(R.x)
        s = (m + x*r) // k

        return (r, s)

    def calcr(self, k):
        R = self.G * k
        return self.GFn.value(R.x)

     
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
        m = self.GFn.value(message)
        r = self.GFn.value(rnum)
        s = self.GFn.value(snum)

        R = self.G * (m//s) + pubkey * (r//s)

        # alternative methods of verifying
        #RORG = self.ec.decompress(r, 0)
        #RR = self.G * m + pubkey * r
        #print("#1: %s .. %s"  % (RR, RORG*s))
        #print("#2: %s .. %s"  % (RR*(1//s), r))
        #print("#3: %s .. %s"  % (R, r))

        return R.x == r

    def findpk(self, message, rnum, snum, flag):
        """
        find pubkey Y from message m, signature (r,s)
        Y = (R*s-G*m)/r

        note that there are 2 pubkeys related to a signature
        """
        m = self.GFn.value(message)
        r = self.GFn.value(rnum)
        s = self.GFn.value(snum)

        R = self.ec.decompress(r, flag)

        #return (R*s - self.G * m)*(1//r)
        return R*(s//r) - self.G * (m//r)

    def findpk2(self, r1, s1, r2, s2, flag1, flag2):
        """
        find pubkey Y from 2 different signature on the same message
        sigs: (r1,s1) and (r2,s2)

        returns  (R1*s1-R2*s2)/(r1-r2)
        """
        R1 = self.ec.decompress(r1, flag1)
        R2 = self.ec.decompress(r2, flag2)

        rdiff = self.GFn.value(r1-r2)

        return (R1*s1-R2*s2)*(1//rdiff)

    def crack2(self, r, s1, s2, m1, m2):
        """
        find signsecret and privkey from duplicate 'r'

        signature (r,s1) for message m1
        and signature (r,s2) for message m2

        s1 = (m1 + x*r)/k
        s2 = (m2 + x*r)/k

        subtract -> (s1-s2) = (m1-m2)/k  ->  k = (m1-m2)/(s1-s2)

        -> privkey =  (s1*k-m1)/r  .. or  (s2*k-m2)/r
        """
        sdelta = self.GFn.value(s1-s2)
        mdelta = self.GFn.value(m1-m2)

        secret = mdelta // sdelta
        x1 = self.crack1(r, s1, m1, secret)
        x2 = self.crack1(r, s2, m2, secret)

        if x1 != x2:
            print("x1=%s" % x1)
            print("x2=%s" % x2)

        return (secret, x1)

    def crack1(self, rnum, snum, message, signsecret):
        """
        find privkey, given signsecret k, message m, signature (r,s)

        x = (s*k-m)/r
        """
        m = self.GFn.value(message)
        r = self.GFn.value(rnum)
        s = self.GFn.value(snum)
        k = self.GFn.value(signsecret)
        return (s*k-m)//r

    def find_k(self, message, privkey, rnum, snum):
        """
        find signing secret used to create signature, given message, privkey and signature

        k = (m+x*r)/s
        """
        m = self.GFn.value(message)
        r = self.GFn.value(rnum)
        s = self.GFn.value(snum)
        x = self.GFn.value(privkey)
        return (m+x*r)//s

    def find_M(self, rnum, snum, pubkey, flag):
        """
        calculate the G^message from a signature + pubkey

        M = G*m=R*s-Y*r

        One could use this to find that two signatures sign
        the same message.

        """
        r = self.GFn.value(rnum)
        s = self.GFn.value(snum)
        R = self.ec.decompress(r, flag)

        M = R*s-pubkey*r

        return M


def secp256k1():
    """
    create the secp256k1 curve
    """
    GFp = FiniteField(2**256 - 2**32 - 977)
    ec = WeierstrassCurve(GFp, 0, 7)
    generator = ec.point( 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8  )
    grouporder = 2**256 - 432420386565659656852420866394968145599
    return ECDSA(ec, generator, grouporder)

def secp521r1():
    """
    create the secp521r1 curve
    """
    GFp = FiniteField(2**521 - 1)
    ec = WeierstrassCurve(GFp, 2**521 - 4, 0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00)
    return ECDSA(ec, ec.point( 0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66, 0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650 ),
            2**521-657877501894328237357444332315020117536923257219387276263472201219398408051703 )


def test512():
    """
    a 512 bit curve

    TODO: fix this curve, something wrong here.
    """
    GFp = FiniteField(2**512 - 2**32 - 2021)
    ec = WeierstrassCurve(GFp, 0, 7)
    return ECDSA(ec, ec.point(0x8e9ff6f105f3eb636bf3860d6e1ca2f026b1475eb466468ab78cd6ad85e01a19297992153e01e15dddf6dce52e1f606ff43a84a9ccebe62e2891fc24ff3cb606,0xc2896e5170498003c41fc1da434cf269a9376d430cf23a8310e5f3d642c7c625821255171276751de0c3f460e457a7b10e46644a05f47b2bee71eb7a1ab9b9f4),
            2**512 - 6895582808925642222872035181967446310655415402756856680443584449013251397012)


def test4096():
    """
    a 4096 bit curve
    """
    GFp = FiniteField(2**4096 - 2**32 - 2537)
    ec = WeierstrassCurve(GFp, 0, 7)
    return ECDSA(ec, ec.point(0x1685e3b7f2ee19ccfa47a6bce5e3fe999bcec3814325cdc5be6b8968505c4a07caf70b7929b27662a85a2c13bb99d5e275d947e67d5d71bd3b69e19299ebad9ceca798f5a08546324dd4b073b137e396f3f2c0504e1e7947d7d651f12bd2b8e4dbf41cc2ce2f5752e4e737c7488c86d29444916c62ce43dc3332eec37abe6487d1eff007f14d4b2f34e22e8a04ff13fed3d50afd383332f652f24c908f87d0aaca790865d1a74c9f5c3dbb8f39daf0e2a3e88460e76fc5fcee1478f60edd9f557e7897ad816420082e6237f467d41b93a1def0e16562a4687600329eac2d7eabfa4b6721d0dd9ed7033eced3efc409e2f5150b4344fe05b535efcd6d025428d6e1a923c3e4df49acfa7fdf2005ed23aa2ce632127d97194d39145c49391ed2941f6767eb311ba3b8c381c77fbfb3122851c4083dac8de11e4078c8dfe0e84a888ea8f4da18cc6fbcde1a9b64d75b46ebefbd781ba7a93d2a9006db842966c791e6159d1f2aa010d885eb3ee448926a1c7598ab5f2e48591943b771a8d3918b2af53ec8b0fc871b9d9051502113fe9ef0ebf4ff8e2f3a2a961a55adc565dd1f7e426d3b8a9d2a41436fd86923c51d63353c0728b7a66ae8ea39e2d8580f7b164665b89691b0e4575039053c496e9c8e2b5fa1764f54d450214cc743194c107f1c4250de002b446cdafb96575fd13d5db977971f1e53d74a4d1e3a5da7b4ba3920,0xb5e012bc1fe44b7dd5a10b4ab821391ada73e1cc2df848a43d9c7f3144837cbc75b8e883af1393177c9795a30fbfc81ea943f1f9463cabcb610a31433fa6e96e9de41e337ee1cf729552ed20f5d8d7c846881aab9602327b9811847086d8d2d93b4accd76871415449db83876b46115ba8450e56785434b1d692a023c138cec1b8cc502a18c8517a175b093f4903eb6f636433d43ab44ab6e9ad9c252236eb21afaf0e6f81a5b23b6c2fe1206fc8635c3dd3f72e5363cfb3b6c5ca426ddd19f1171e94e640da705925e213bf8e0818ff61bcdaf7567cec2f37c30633d4fb869557b35ae0afde3c82d3076af101d33fca1c0c8a6fe0048342554e9e5edef3ad9b33694568274fa7362bfacd71b1738db0971280f189f97208c1ef80a65f9225eb5bb0564b880fe89d0520b313c7633b017de82fdf1424e6f2da25abb9fe6260f3a931b8cf57a1873d7281370c048e992eaa9884027c7562f5f14932eba6efac20dd31d5ea9c177bfb54e635fa074d77ad951ff1c2862db79062bb58291016156ebf0a1cb8c0d62c6cd7b5c3a18a7275c0dc71a3f20b3bb534a0adc970a2295bfc80f29cdd878cf71910c78c2eb4bca64d268a30f7208c52a5078c43c700513ddb1aecae415254e2111d40bf5209568165f5f5b03c0cae7a03377511d1ce0f465925862790f760d69d647906b6bfa7dc111ff9063a708a1bb81a07e44910d4fa3e),
            2**4096 - 15787038050835261139727473240632701678801359219990631510877267829169330959162948488165650753848869590983746944212813863965377670228845736254534787510912418420652893326068746642904667264372558891710237797366766181971757342659203537793080285150152751005384967243420022238322992906760095995836462891911958739812874169586869753591456898694827154063269411873501193289294399280654401837948800093834381560396905039959407190649328769848101131114406715808686253866533861144467946024203112376581408329288635232043317889422050242324593056324526742572727503289941755773038964720862007376605112301728375457511119559511362294902237)


