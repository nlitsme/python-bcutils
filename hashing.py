from Crypto.Hash import SHA256
try:
    from Crypto.Hash import RIPEMD160
except:
    from Crypto.Hash import RIPEMD as RIPEMD160
"""
By Willem Hengeveld <itsme@xs4all.nl>

two hashing operations used by bitcoin
"""


def shasha(*args):
    h= SHA256.new()
    for x in args:
        h.update(x)
    h2= SHA256.new()
    h2.update(h.digest())
    return h2.digest()


def sharip(*args):
    h= SHA256.new()
    for x in args:
        h.update(x)
    h2= RIPEMD160.new()
    h2.update(h.digest())
    return h2.digest()

