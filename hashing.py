try:
    from Crypto.Hash import SHA256
    try:
        from Crypto.Hash import RIPEMD160
    except:
        from Crypto.Hash import RIPEMD as RIPEMD160
except:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography import utils

    @utils.register_interface(hashes.HashAlgorithm)
    class MD160(object):
        name = "ripemd160"
        digest_size = 20
        block_size = 64


    class SHA256:
        @staticmethod
        def new():
            return SHA256()
        def __init__(self):
            self.h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        def update(self, x):
            self.h.update(x)
        def digest(self):
            return self.h.finalize()
    class RIPEMD160:
        @staticmethod
        def new():
            return RIPEMD160()
        def __init__(self):
            self.h = hashes.Hash(MD160(), backend=default_backend())
        def update(self, x):
            self.h.update(x)
        def digest(self):
            return self.h.finalize()

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

