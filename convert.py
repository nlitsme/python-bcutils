"""
By Willem Hengeveld <itsme@xs4all.nl>

convert between bytes and number
"""
import sys
if sys.version_info[0] == 2:
    import binascii
    def numfrombytes(b):
        return int(binascii.b2a_hex(b), 16)
    def bytesfromnum(num, n= 32):
        return binascii.a2b_hex(("%x" % num).rjust(2*n, '0'))
else:
    def numfrombytes(b):
        return int.from_bytes(b, 'big')
    def bytesfromnum(num, n= 32):
        return int(num).to_bytes(32, 'big')


