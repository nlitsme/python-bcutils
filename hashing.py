"""
By Willem Hengeveld <itsme@xs4all.nl>

two hashing operations used by bitcoin
"""
try:
    from Crypto.Hash import  SHA256, RIPEMD160
except ImportError:
    from Cryptodome.Hash import  SHA256, RIPEMD160

def sha256(*data):
    """ Calculate a sha256 """
    h1 = SHA256.new()
    for x in data:
        h1.update(x)
    
    return h1.digest()

def shasha(*data):
    """ Calculate a transaction hash """
    h1 = SHA256.new()
    for x in data:
        h1.update(x)
    
    h2 = SHA256.new()
    h2.update( h1.digest() )

    return h2.digest()

def sharip(data):
    """ Calculate a address hash """
    h1 = SHA256.new()
    h1.update(data)
    
    h2 = RIPEMD160.new()
    h2.update( h1.digest() )

    return h2.digest()


