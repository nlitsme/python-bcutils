"""
By Willem Hengeveld <itsme@xs4all.nl>

two hashing operations used by bitcoin
"""
import hashlib

def sha256(*data):
    """ Calculate a sha256 """
    h1 = hashlib.new('sha256')
    for x in data:
        h1.update(x)
    
    return h1.digest()

def shasha(*data):
    """ Calculate a transaction hash """
    h1 = hashlib.new('sha256')
    for x in data:
        h1.update(x)
    
    h2 = hashlib.new('sha256')
    h2.update( h1.digest() )

    return h2.digest()

def sharip(data):
    """ Calculate a address hash """
    h1 = hashlib.new('sha256')
    h1.update(data)
    
    h2 = hashlib.new('ripemd160')
    h2.update( h1.digest() )

    return h2.digest()


