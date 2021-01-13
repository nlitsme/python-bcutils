from io import BytesIO
import struct
from binascii import a2b_hex, b2a_hex
import hashlib
from collections import defaultdict
import itertools
from ecdsa import secp256k1

transactions = [
    "01000000023c99cb033a0f5897d0587c0172a5456f036496fe585f01d9fb6009154e26627e000000008b483045022100cabc3692f1f7ba75a8572dc5d270b35bcc00650534f6e5ecd6338e55355454d502200437b68b1ea23546f6f712fd6a7e5370cfc2e658a8f0245628afd8b6999d9da60141044a87eb1c5255b7d224e15b046f88fd322af1168954f0cba020a4358641d008c13228b85e0a1fd313e032326aff1b27240ece99c90dc58b19bab804c705fcd2ecffffffff3c99cb033a0f5897d0587c0172a5456f036496fe585f01d9fb6009154e26627e010000008c493046022100cabc3692f1f7ba75a8572dc5d270b35bcc00650534f6e5ecd6338e55355454d5022100b584c5e2f26eaac9510307f466d13f8d4e8f57b1323cc4151ff6ffeb6747ca9b014104bb6c1de01f36618ae05f7c183c22dfa8797e779f39537752c27e2dc045b0e6942f8af53270bf045f2258834b6dad7481ad6fca009d80f5b54697b08d104fc7b3ffffffff0180969800000000001976a914aed8036193b2e7ebdd7596fb658894548c6eb5bf88ac00000000",
    "0100000001ff7f73f59ef98051052d7ab6ed319dd9acc50598dcc4ea4a5f822cd9abd3df07010000008c493046022100cabc3692f1f7ba75a8572dc5d270b35bcc00650534f6e5ecd6338e55355454d50221009cae782a191f3e742d9d4ff8f726d097a3a256af9fbc1faf16e7ec4d9fcf6feb014104bb6c1de01f36618ae05f7c183c22dfa8797e779f39537752c27e2dc045b0e6942f8af53270bf045f2258834b6dad7481ad6fca009d80f5b54697b08d104fc7b3ffffffff0240420f00000000001976a914031b45590c4ce1b4082ab1ec7e46c72666653c1e88ac40548900000000001976a914b54405702bad7fd74cdb0567db22d1f58a48494e88ac00000000",
    "01000000015acb328d14b27ecf45f029db0023631773ad2b8ed7ac67380d445b21b6af1f9a010000008c493046022100cabc3692f1f7ba75a8572dc5d270b35bcc00650534f6e5ecd6338e55355454d5022100f65bfc44435a91814c142a3b8ee288a9183e6a3f012b84545d1fe334ccfac25e014104bb6c1de01f36618ae05f7c183c22dfa8797e779f39537752c27e2dc045b0e6942f8af53270bf045f2258834b6dad7481ad6fca009d80f5b54697b08d104fc7b3ffffffff0180969800000000001976a914a8964e5b08170f5601f526813d80c9f825b8775588ac00000000",
]

def shasha(data):
    """ Calculate a transaction hash """
    h1 = hashlib.new('sha256')
    h1.update(data)
    
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

class Reader:
    """ helper class for reading data from a transaction """
    def __init__(self, fh):
        self.fh = fh
    def readbyte(self):
        data = self.fh.read(1)
        if not data:
            return
        b, = struct.unpack("<B", data)
        return b
    def readshort(self):
        data = self.fh.read(2)
        if not data:
            return
        w, = struct.unpack("<H", data)
        return w
    def readdword(self):
        data = self.fh.read(4)
        if not data:
            return
        w, = struct.unpack("<L", data)
        return w
    def readqword(self):
        data = self.fh.read(8)
        if not data:
            return
        w, = struct.unpack("<Q", data)
        return w
    def readvarint(self):
        b = self.readbyte()
        if b is None:
            return
        if b<0xfd:
            return b
        if b==0xfd:
            return self.readshort()
        if b==0xfe:
            return self.readdword()
        if b==0xff:
            return self.readqword()
    def readbytes(self, size):
        return self.fh.read(size)
    def readobject(self, objtype):
        obj = objtype()
        obj.decode(self)
        return obj

class Writer:
    """ helper class for writing data from a transaction """
    def __init__(self, fh):
        self.fh = fh
    def writebyte(self, b):
        self.fh.write(struct.pack("<B", b))
    def writeshort(self, w):
        self.fh.write(struct.pack("<H", w))
    def writedword(self, w):
        self.fh.write(struct.pack("<L", w))
    def writeqword(self, w):
        self.fh.write(struct.pack("<Q", w))
    def writevarint(self, x):
        if x<0xfd:
            self.writebyte(x)
        elif x<0x10000:
            self.writebyte(0xfd)
            self.writeshort(x)
        elif x<0x100000000:
            self.writebyte(0xfe)
            self.writedword(x)
        else:
            self.writebyte(0xff)
            self.writeqword(x)
    def writebytes(self, size):
        self.fh.write(size)
    def writeobject(self, obj):
        obj.encode(self)


class Input:
    """ encode, decode a transaction input """
    def decode(self, r):
        self.txn_hash = r.readbytes(32)
        self.output_index = r.readdword()
        self.script = r.readobject(Script)
        self.sequence_number = r.readdword()
    def encode(self, w):
        w.writebytes(self.txn_hash)
        w.writedword(self.output_index)
        self.script.encode(w)
        w.writedword(self.sequence_number)
    def copy(self):
        inp = Input()
        inp.txn_hash = self.txn_hash
        inp.output_index = self.output_index 
        inp.script = self.script
        inp.sequence_number = self.sequence_number
        return inp


class Output:
    """ encode, decode a transaction output """
    def decode(self, r):
        self.btcvalue = r.readqword()
        self.script = r.readobject(Script)
    def encode(self, w):
        w.writeqword(self.btcvalue)
        self.script.encode(w)

class Script:
    """ encode, decode a transaction script """
    def __init__(self):
        self.bytecode = b''
    def decode(self, r):
        size = r.readvarint()
        self.bytecode = r.readbytes(size)
    def encode(self, w):
        w.writevarint(len(self.bytecode))
        w.writebytes(self.bytecode)

    def __iter__(self):
        """ enumerate all items in the script's bytecode """
        r = Reader(BytesIO(self.bytecode))
        while True:
            b = r.readbyte()
            if b is None:
                break
            if b<79:
                if b<=75:
                    asize = b
                elif b==76:
                    asize = r.readbyte()
                elif b==77:
                    asize = r.readshort()
                elif b==78:
                    asize = r.readdword()
                data = r.readbytes(asize)
                yield 'data', data
            elif 81<=b<=96:
                yield "constant", b-80
            else:
                yield 'opcode', b

class Transaction:
    """
    encode, decode an entire transaction.

    Note that this code does not support BIP0141 style transactions, with witness data
    """
    def decode(self, r):
        self.version = r.readdword()
        nrin = r.readvarint()
        self.inputs = [ r.readobject(Input) for _ in range(nrin) ]
        nrout = r.readvarint()
        self.outputs = [ r.readobject(Output) for _ in range(nrout) ]
        self.locktime = r.readdword()

    def encode(self, w):
        w.writedword(self.version)
        w.writevarint(len(self.inputs))
        for inp in self.inputs:
            inp.encode(w)
        w.writevarint(len(self.outputs))
        for outp in self.outputs:
            outp.encode(w)
        w.writedword(self.locktime)

    def copy(self):
        t = Transaction()
        t.version = self.version
        t.inputs = [ _.copy() for _ in self.inputs ]
        t.outputs = [ _ for _ in self.outputs ]
        t.locktime = self.locktime
        return t

def messagehash(txn, ci, inputindex):
    """ Calculate the message hash given the transaction, crackinfo and inputindex """
    txndup = txn.copy()
    for i, inp in enumerate(txndup.inputs):
        if i==inputindex:
            inp.script = ci.invent_scriptpub()
        else:
            inp.script = Script()  # empty script

    bio = BytesIO()
    w = Writer(bio) 

    txndup.encode(w)
    w.writedword(1)   # the hashtype

    data = bio.getvalue()
    
    return shasha(data)


class CrackInfo:
    def invent_scriptpub(self):
        bio = BytesIO()

        w = Writer(bio) 
        w.writebyte(0x76)  # DUP
        w.writebyte(0xa9)  # HASH160
        w.writebyte(0x14)  # size of addrhash
        w.writebytes(sharip(self.pubkey))  # the address hash
        w.writebyte(0x88)  # EQUALVERIFY
        w.writebyte(0xac)  # CHECKSIG

        s = Script()
        s.bytecode = bio.getvalue()

        return s

def decode_signature(sigdata):
    """ extract the r and s values from a signature """
    r = Reader(BytesIO(sigdata))

    seqtag = r.readbyte()
    if seqtag != 0x30: raise Exception("not a signature")
    rslen = r.readbyte()
    inttag = r.readbyte()
    if inttag != 0x02: raise Exception("not a signature")
    rlen = r.readbyte()
    rval = r.readbytes(rlen)
    inttag = r.readbyte()
    if inttag != 0x02: raise Exception("not a signature")
    slen = r.readbyte()
    sval = r.readbytes(slen)

    sighashtype = r.readbyte()  # always 0x01

    def make32bytes(x):
        if len(x)==32:
            return x
        if len(x)<32:
            return x.rjust(b"\x00")
        return x[-32:]

    return make32bytes(rval), make32bytes(sval)

def tonum(data):
    return int.from_bytes(data, 'big')

def do_crack(a, b):
    E = secp256k1()
    k, x = E.crack2(tonum(a.r), tonum(a.s), tonum(b.s), tonum(a.m), tonum(b.m))
    print(" --> %s %s" % (k, x))

def main():
    crackdata = []

    # first go over all transactions, extracting the 'crackinfo'
    # needed to do the cracking later.
    for hextxn in transactions:
        txndata = a2b_hex(hextxn)
        txnhash = shasha(txndata)
        print("txn", b2a_hex(txnhash))
        r = Reader(BytesIO(txndata))
        txn = r.readobject(Transaction)
        for i, inp in enumerate(txn.inputs):
            ci = CrackInfo()
            ci.srctxn = inp.txn_hash
            ci.srcindex = inp.output_index
            for tag, value in inp.script:
                if tag == 'data':
                    if len(value) in (33, 65):
                        ci.pubkey = value
                        print("found pubkey", b2a_hex(value))
                    elif 65 < len(value) < 74:
                        ci.r, ci.s = decode_signature(value)
                        print("found signature", b2a_hex(value))
            ci.m = messagehash(txn, ci, i)

            crackdata.append(ci)

    # now sort the crackinfo by pubkey and rvalue.
    by_pk_and_r = defaultdict(list)
    for ci in crackdata:
        by_pk_and_r[(ci.pubkey,ci.r)].append(ci)

    # now go over all combinations of duplicate (pubkey+rvalue) pair,
    # and run 'crack'
    for crackable in by_pk_and_r.values():
        for a, b in itertools.combinations(crackable, 2):
            do_crack(a, b)

if __name__ == '__main__':
    main()
