"""
By Willem Hengeveld <itsme@xs4all.nl>

two hashing operations used by bitcoin
"""
import Crypto.Hash.SHA256
import Crypto.Hash.RIPEMD160

def sha256(*data):
    """ Calculate a sha256 """
    h1 = Crypto.Hash.SHA256.new()
    for x in data:
        h1.update(x)
    
    return h1.digest()

def shasha(*data):
    """ Calculate a transaction hash """
    h1 = Crypto.Hash.SHA256.new()
    for x in data:
        h1.update(x)
    
    h2 = Crypto.Hash.SHA256.new()
    h2.update( h1.digest() )

    return h2.digest()

def sharip(data):
    """ Calculate a address hash """
    h1 = Crypto.Hash.SHA256.new()
    h1.update(data)
    
    h2 = Crypto.Hash.RIPEMD160.new()
    h2.update( h1.digest() )

    return h2.digest()


