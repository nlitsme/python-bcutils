from __future__ import print_function, division
import ecdsa
from hashing import *
import base58
import bech32
import re
import convert
import struct
import binascii

def byt(c):
    return struct.pack("<B", c)

"""
By Willem Hengeveld <itsme@xs4all.nl>

Objects representing all bitcoin address releated information



note on uniqueness:
    'small':  less than: 2^256 - the group order 'n'

    'small' priv keys can be represented as both 'x', and 'x+n'
    pubkeys with 'small' x-coordinate can be represented both as:
    (x,y)  and (x+n,y)
    both of which lead to different addresses.
"""

# the bitcoin wallet version.
wallet_version = 0x80
address_version = 0x00

ecdsa= ecdsa.secp256k1()

def setversions(aver, wver):
    global address_version
    global wallet_version
    address_version= aver
    wallet_version= wver

"""
represent hashed address
either from compressed or full pubkey
knows how to convert between hash and base58 representation
"""
class Address:
    def __init__(self):
        global address_version
        self.hash= None
        self.version= address_version  # global
        self.hrp = "bc"  # 'human readable prefix'

    @staticmethod
    def fromhash(hash):
        self= Address()
        self.hash= hash
        return self

    @staticmethod
    def frombase58(b58):
        self= Address()
        data= base58.decode(b58)
        if len(data)>25:
            print("addr len > 25: %s" % binascii.b2a_hex(data))
            raise Exception("Invalid base58 length")
        if len(data)<25:
            data= "\x00" * (25-len(data))
        self.version= ord(data[0])
        self.hash= data[1:21]
        if shasha(data[0:21])[:4] != data[21:]:
            print("addr: %s: %s != %s" % (binascii.b2a_hex(data[:21]), binascii.b2a_hex(data[21:]), shasha(data[0:21])[:4]))
            raise Exception("Invalid base58 checksum")

        return self

    @staticmethod
    def frombech32(b32):
        self = Address()
        self.hrp, self.version, self.hash = bech32.decode(b32)
        return self

    def base58(self):
        data= byt(self.version) + self.hash
        data += shasha(data)[0:4]
        return base58.encode(data)

    def bech32(self):
        return bech32.encode(self.hrp, self.version, self.hash)

    def dump(self):
        print("%-20s: %3d %-34s - %s" % (binascii.b2a_hex(self.hash).decode('ascii'), self.version, self.base58(), self.bech32()))

"""
represent the public key
knows how to encode/decode a pubkey into bytes
"""
class PublicKey:
    def __init__(self):
        self.point= None
    def compressed(self):
        return struct.pack("<B", 2 + self.point.y.sqrtflag()) + convert.bytesfromnum(self.point.x) 
    def uncompressed(self):
        return struct.pack("<B", 4) + convert.bytesfromnum(self.point.x) + convert.bytesfromnum(self.point.y)

    def dump(self):
        print("%-20s: %s" % ("compressed", binascii.b2a_hex(self.compressed()).decode('ascii')))
        print("%-20s: %s" % ("full", binascii.b2a_hex(self.uncompressed()).decode('ascii')))

    @staticmethod
    def frompubkey(key):
        self= PublicKey()
        if len(key)==33 and (ord(key[0])==2 or ord(key[0])==3):
            self.point= ecdsa.ec.decompress(convert.numfrombytes(key[1:]), ord(key[0])-2)
        elif len(key)==65 and ord(key[0])==4:
            self.point= ecdsa.ec.point(convert.numfrombytes(key[1:33]), convert.numfrombytes(key[33:65]))
        else:
            print(binascii.b2a_hex(key))
            raise Exception("invalid point representation")
        return self
    @staticmethod
    def frompoint(pt):
        self= PublicKey()
        self.point= pt
        return self

"""
represent the private part of the bitcoin address
knows how to convert between wallet and privkey,
can be initialized from minikey.
"""
class PrivateKey:
    def __init__(self):
        global wallet_version
        self.privkey= None
        self.minikey= None
        self.version= wallet_version  # global
        self.compressed= None

    @staticmethod
    def fromwallet(b58):
        self= PrivateKey()
        data= base58.decode(b58)
        if not len(data) in (37, 38):
            print("wallet len != 37/38: %s" % binascii.b2a_hex(data))
            raise Exception("Invalid wallet length")
        self.version= ord(data[0:1])
        self.privkey= convert.numfrombytes(data[1:33])
        if len(data)==38:
            # todo: ?? what is this for?
            self.compressed= ord(data[33])
        if shasha(data[:-4])[:4] != data[-4:]:
            print("wallet: %s: %s != %s" % (binascii.b2a_hex(data[:33]), binascii.b2a_hex(data[33:]), shasha(data[0:33])[:4]))
            raise Exception("Invalid base58 checksum")

        return self

    @staticmethod
    def fromminikey(key):
        h= SHA256.new()
        h.update(key)
        self= PrivateKey()
        self.privkey= convert.numfrombytes(h.digest())
        return self

    @staticmethod
    def fromprivkey(key):
        self= PrivateKey()
        self.privkey= convert.numfrombytes(key)
        return self

    def publickey(self):
        return PublicKey.frompoint(ecdsa.calcpub(self.privkey))
    def wallet(self):
        data= byt(self.version)+convert.bytesfromnum(self.privkey)
        data += shasha(data)[:4]
        return base58.encode(data)

    def dump(self):
        if self.minikey: print("%-20s: %s" % ("minikey", self.minikey))
        print("%-20s: %064x" % ("privkey", self.privkey))
        print("%-20s: %s" % ("wallet", self.wallet()))
        if self.version is not None and self.compressed is not None:
            print("version: %d          compressed: %d" % (self.version, self.compressed))
        elif self.compressed is not None:
            print("compressed:  %d" % self.compressed)
        elif self.version is not None:
            print("version:     %d" % self.version)


"""
represent all components of a bitcoin address combined
"""
class BitcoinAddress:
    def __init__(self, arg):
        if isinstance(arg, PrivateKey):
            self.privkey= arg
        elif isinstance(arg, PublicKey):
            self.privkey= None
            self.pubkey= arg
        elif isinstance(arg, Address):
            self.privkey= None
            self.pubkey= None
            self.compaddr = self.fulladdr = arg
        else:
            self.privkey= None
            self.pubkey= None
            self.compaddr = self.fulladdr = None
            self.p2sh = None

        if self.privkey:
            self.pubkey= self.privkey.publickey()
        if  self.pubkey:
            self.compaddr= Address.fromhash(sharip(self.pubkey.compressed()))
            self.fulladdr= Address.fromhash(sharip(self.pubkey.uncompressed()))
            if self.privkey and self.privkey.version:
                # most coins have walletversion = 128 + addressversion
                self.compaddr.version= self.privkey.version-128
                self.fulladdr.version= self.privkey.version-128
        if self.compaddr:
            self.p2sh = Address.fromhash(sharip(struct.pack(">H", len(self.compaddr.hash))+self.compaddr.hash))
            self.p2sh.version = 5


    @staticmethod
    def from_privkey(arg):
        if type(arg)==str: arg = binascii.a2b_hex(arg)
        return BitcoinAddress(PrivateKey.fromprivkey(arg))
    @staticmethod
    def from_wallet(arg):
        return BitcoinAddress(PrivateKey.fromwallet(arg))
    @staticmethod
    def from_minikey(arg):
        return BitcoinAddress(PrivateKey.fromminikey(arg))
    @staticmethod
    def from_pubkey(arg):
        return BitcoinAddress(PublicKey.frompubkey(binascii.a2b_hex(arg)))
    @staticmethod
    def from_hash(arg):
        return BitcoinAddress(Address.fromhash(binascii.a2b_hex(arg)))
    @staticmethod
    def from_base58(arg):
        return BitcoinAddress(Address.frombase58(arg))
    @staticmethod
    def from_bech32(arg):
        return BitcoinAddress(Address.frombech32(arg))
    @staticmethod
    def from_auto(arg):
        ishex= re.match(r'[0-9a-f]+$', arg)
        isb58= re.match('['+base58.charset+']+$', arg)
        isb32= re.match('(?:\w+1)?['+bech32.alphabet+']+$', arg)

        if len(arg)==51 and arg[0]=='5' and 'H' <= arg[1] <= 'K' and isb58:
            # a wallet private key
            return BitcoinAddress(PrivateKey.fromwallet(arg))
        if len(arg)==52 and "Kw" <= arg[:2] <='L5' and isb58:
            # a wallet private key
            return BitcoinAddress(PrivateKey.fromwallet(arg))
        elif 33<=len(arg)<=34 and arg[0]=='1' and isb58:
            # a 'p2pkh' address
            return BitcoinAddress(Address.frombase58(arg))
        elif 33<=len(arg)<=34 and arg[0]=='3' and isb58:
            # a 'p2sh' address
            return BitcoinAddress(Address.frombase58(arg))
        elif len(arg)==42 and isb32:
            # a 'p2wpkh' address
            return BitcoinAddress(Address.frombech32(arg))
        elif len(arg)==62 and isb32:
            # a 'p2wsh' address
            return BitcoinAddress(Address.frombech32(arg))
        elif len(arg)==130 and arg[:2]=='04' and ishex:
            # a full public key
            return BitcoinAddress(PublicKey.frompubkey(binascii.a2b_hex(arg)))
        elif len(arg)==66 and arg[0]=='0' and arg[1] in ('2','3') and ishex:
            # a compressed public key
            return BitcoinAddress(PublicKey.frompubkey(binascii.a2b_hex(arg)))
        elif len(arg)==64 and ishex:
            # a hex private key
            return BitcoinAddress(PrivateKey.fromprivkey(binascii.a2b_hex(arg)))
        else:
            print("unknown string: %s" % arg)

    def dump(self):
        if self.privkey: self.privkey.dump()
        if self.pubkey: self.pubkey.dump()
        if self.fulladdr==self.compaddr:
            if self.compaddr:
                self.compaddr.dump()
        else:
            print("comp:", end=" ")
            self.compaddr.dump()
            print("full:", end=" ")
            self.fulladdr.dump()
        print("p2sh:", end=" ")
        self.p2sh.dump()


