"""
By Willem Hengeveld <itsme@xs4all.nl>

convert between bytes and number
"""
def numfrombytes(b):
    return int.from_bytes(b, 'big')
def bytesfromnum(num, n= 32):
    return int(num).to_bytes(32, 'big')


