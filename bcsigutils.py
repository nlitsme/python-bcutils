from bcdataio import Reader, Writer
from io import BytesIO

from hashing import shasha, sharip

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

def messagehash(txn, ci, inputindex):
    """ Calculate the message hash given the transaction, crackinfo and inputindex """
    txndup = txn.copy()
    for i, inp in enumerate(txndup.inputs):
        if i==inputindex:
            inp.script = ci.invent_scriptpub()
        else:
            inp.script = ci.empty_script()

    bio = BytesIO()
    w = Writer(bio) 

    txndup.encode(w)
    w.writedword(1)   # the hashtype

    data = bio.getvalue()
    
    return shasha(data)


def calcPrevOutsHash(txn):
    bio = BytesIO()
    w = Writer(bio) 

    for inp in txn.inputs:
        w.writebytes(inp.txn_hash)
        w.writedword(inp.output_index)

    return shasha(bio.getvalue())

def calcSequenceHash(txn):
    bio = BytesIO()
    w = Writer(bio) 

    for inp in txn.inputs:
        w.writedword(inp.sequence_number)

    return shasha(bio.getvalue())

def calcOutputsHash(txn):
    bio = BytesIO()
    w = Writer(bio) 

    for out in txn.outputs:
        out.encode(w)

    return shasha(bio.getvalue())


def witnesshash(txn, inputindex, btcvalue):
    bio = BytesIO()
    w = Writer(bio) 
    w.writedword(txn.version)
    w.writebytes(calcPrevOutsHash(txn))
    w.writebytes(calcSequenceHash(txn))

    inp = txn.inputs[inputindex]
    w.writebytes(inp.txn_hash)
    w.writedword(inp.output_index)

    wit = txn.witness[inputindex]
    wit.encode_scriptcode(w)

    w.writeqword(btcvalue)
    w.writedword(inp.sequence_number)
    w.writebytes(calcOutputsHash(txn))
    w.writedword(txn.locktime)
    w.writedword(1)   # hashtype

    data = bio.getvalue()
    return shasha(data)


