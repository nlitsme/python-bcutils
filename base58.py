from __future__ import print_function, division
from binascii import a2b_hex, b2a_hex

"""
By Willem Hengeveld <itsme@xs4all.nl>

base58 encode and decode
"""

charset= "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def encode(data):
    def nbytes(x):
       return (x.bit_length()+7)//8

    res= ""
    if type(data)==bytes:
        bytelen= len(data)
        if bytelen:
            data= int(b2a_hex(data), 16)
        else:
            data= 0
        nrzeros= bytelen - nbytes(data)
    else:
        data= int(data)
        bytelen= nbytes(data)
        nrzeros= 0

    while data:
        res += charset[data%58]
        data //= 58

    res += charset[0] * nrzeros

    return res[::-1]

def decode(enc):
    num= 0
    nrzeros= 0
    for c in enc:
        if c==charset[0]:
            nrzeros += 1
        else:
            break

    for c in enc:
        digit= charset.find(c)
        if digit<0:
            break
        num *= 58
        num += digit

    if num:
        hexstr= "%x" % num
        if len(hexstr)%2:
            hexstr= "0" + hexstr
    else:
        hexstr= ""
    hexstr= "00" * nrzeros + hexstr

    return a2b_hex(hexstr)

