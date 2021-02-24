""" handle decoding and encoding of transactions """
from bcdataio import Reader
from io import BytesIO
from hashing import shasha, sharip

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

class Witness:
    """ encode, decode a transaction output """
    def decode(self, r):
        nr = r.readvarint()
        self.wstruct = []
        for _ in range(nr):
            size = r.readvarint()
            self.wstruct.append(r.readbytes(size))
    def encode(self, w):
        w.writevarint(len(self.wstruct))
        for item in self.wstruct:
            w.writevarint(len(item))
            w.writebytes(item)

    def gettype(self):
        if len(self.wstruct)==2:
            return "p2wpkh"
        return "p2wsh"

    def encode_scriptcode(self, w):
        t = self.gettype()
        if t == "p2wpkh":
            self.p2wpkh_scriptcode(w)
        elif t == "p2wsh":
            self.p2wsh_scriptcode(w)
        else:
            raise Exception("not implemented")

    def p2wpkh_scriptcode(self, w):
        w.writebyte(0x19)
        w.writebyte(0x76)
        w.writebyte(0xa9)
        w.writebyte(0x14)
        w.writebytes(sharip(self.wstruct[1]))
        w.writebyte(0x88)
        w.writebyte(0xac)

    def p2wsh_scriptcode(self, w):
        pass  # TODO

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
    """
    def decode(self, r):
        self.version = r.readdword()
        nrin = r.readvarint()
        witnessflag = 0
        if nrin==0:
            witnessflag = r.readbyte()
            nrin = r.readvarint()
        self.inputs = [ r.readobject(Input) for _ in range(nrin) ]
        nrout = r.readvarint()
        self.outputs = [ r.readobject(Output) for _ in range(nrout) ]
        self.witness = None
        if witnessflag:
            self.witness = [ r.readobject(Witness) for _ in range(nrin) ]
        self.locktime = r.readdword()

    def encode(self, w, exclude_witness=False):
        """
        pass the 'exclude_witness=True' flag when calculating the transaction hash.
        """
        w.writedword(self.version)
        if self.witness and not exclude_witness:
            w.writebyte(0)
            w.writebyte(1)
        w.writevarint(len(self.inputs))
        for inp in self.inputs:
            inp.encode(w)
        w.writevarint(len(self.outputs))
        for outp in self.outputs:
            outp.encode(w)
        if self.witness and not exclude_witness:
            for wit in self.witness:
                wit.encode(w)
        w.writedword(self.locktime)


    def copy(self):
        t = Transaction()
        t.version = self.version
        t.inputs = [ _.copy() for _ in self.inputs ]
        t.outputs = self.outputs
        t.witness = self.witness
        t.locktime = self.locktime
        return t

