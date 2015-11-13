"""
By Willem Hengeveld <itsme@xs4all.nl>

convert between bytes and number
"""
def numfrombytes(b):
    return int(b.encode("hex"), 16)
def bytesfromnum(num, n= 32):
    b= "%x" % int(num)
    if len(b)%2:
        b= "0" + b
    b= b.decode("hex")
    if len(b)<n:
        b= "\x00" * (n-len(b)) + b
    return b


