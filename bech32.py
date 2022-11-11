""" module for decoding and encoding bech32 addresses """
import re

alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def binary(x, n):
    return bin(x)[2:].rjust(n, '0')

def quintstobytes(quints):
    res = 0
    for b in quints:
        res *= 32
        res += b

    n = (len(quints)*5)//8
    #print("b=%3d, n=%3d -> shift=%d" % (len(quints)*5, n*8, len(quints)*5-n*8))
    res >>= len(quints)*5-n*8
    return res.to_bytes(n, "big")

def bytestoquints(data):
    val = int.from_bytes(data, "big")
    n = (len(data)*8+4)//5

    val <<= n*5-len(data)*8
    quints = []
    for i in range(n):
        quints.append(val&31)
        val //= 32
    return quints[::-1]

def decode32toquints(txt):
    return [ alphabet.find(c) for c in txt ]

def encode32(digits):
    return "".join(alphabet[d] for d in digits)


def detaildecode(txt):
    for c in txt:
        i = alphabet.find(c)
        print("%s  - %s" % (c, binary(i, 5)))

BECH32_CONST = 1
# BECH32M_CONST = 0x2bc830a3 ( see bip350 )
def bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def bech32_hrp_expand(s):
    return [ord(x) >> 5 for x in s] + [0] + [ord(x) & 31 for x in s]

def bech32_verify_checksum(hrp, data):
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == BECH32_CONST

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0,0,0,0,0,0]) ^ BECH32_CONST
    #print(polymod)
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def decode(txt):
    m = re.match(r'(?:(\w+)1)?(\w+)', txt)
    if not m:
        raise Exception("invalid bech32")
    hrp = m.group(1) or ""
    b32 = m.group(2)
    ok = bech32_verify_checksum(hrp, decode32toquints(b32))
    if not ok:
        raise Exception("invalid bech32")
    quints = decode32toquints(b32[:-6])

    tag = quints[0]
    data = quintstobytes(quints[1:])
    return hrp, tag, data

def encode(hrp, tag, data):
    quints = [tag%32] + bytestoquints(data)
    chk = bech32_create_checksum(hrp, quints)
    if hrp:
        hrp += "1"
    return hrp + encode32(quints) + encode32(chk)

