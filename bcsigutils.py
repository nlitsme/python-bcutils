from bcdataio import Reader, Writer
from io import BytesIO

from hashing import shasha, sharip
from txndecoder import Script
from binascii import b2a_hex

def decode_signature(sigdata):
    """ extract the r and s values from a signature """
    if len(sigdata)==0x41:
        return sigdata[0:32], sigdata[32:64], sigdata[64]
    r = Reader(BytesIO(sigdata))

    seqtag = r.readbyte()
    if seqtag != 0x30:
        raise Exception("not a signature")
    rslen = r.readbyte()
    inttag = r.readbyte()
    if inttag != 0x02: raise Exception("not a signature")
    rlen = r.readbyte()
    rval = r.readbytes(rlen)
    inttag = r.readbyte()
    if inttag != 0x02: raise Exception("not a signature")
    slen = r.readbyte()
    sval = r.readbytes(slen)

    # note: for BitcoinCash this has many different values, or None
    sighashtype = r.readbyte() or 1  # 1,2,3 or 0x81,0x82,0x83

    def make32bytes(x):
        if len(x)==32:
            return x
        if len(x)<32:
            return x.rjust(32, b"\x00")
        return x[-32:]

    return make32bytes(rval), make32bytes(sval), sighashtype 

def messagehash(txn, hashtype, inputindex, outscript):
    """ Calculate the message hash given the transaction, crackinfo and inputindex """
    _anyonecanpay = hashtype&0x80
    _single = (hashtype&31) == 3
    _none = (hashtype&31) == 2

    if _single and inputindex >= len(txn.outputs):
        # this is a documented bug!!
        return b"\x01" + b"\x00"*31

    txndup = txn.copy()
    if _anyonecanpay:
        txndup.inputs = [ txndup.inputs[inputindex] ]

    for i, inp in enumerate(txndup.inputs):
        if _anyonecanpay or i==inputindex:
            inp.script = outscript
        else:
            inp.script = Script()
            if (_single or _none):
                inp.sequence_number = 0

    if _none:
        txndup.outputs = []
    elif _single:
        txndup.outputs = txndup.outputs[:inputindex+1]
        for i, out in enumerate(txndup.outputs):
            if i!=inputindex:
                out.script = Script()
                out.btcvalue = 2**64-1

    bio = BytesIO()
    w = Writer(bio) 

    txndup.encode(w, exclude_witness=True)
    w.writedword(hashtype)   # the hashtype

    data = bio.getvalue()
    #print("hashing %s" % b2a_hex(data))
    
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

def calcSingleHash(txn, inputindex):
    if inputindex < len(txn.outputs):
        bio = BytesIO()
        w = Writer(bio) 
        txn.outputs[inputindex].encode(w)
        return shasha(bio.getvalue())
    else:
        return b"\x00"*32

def witnesshash(txn, hashtype, inputindex, btcvalue, outscript):
    _anyonecanpay = hashtype&0x80
    _single = (hashtype&31) == 3
    _none = (hashtype&31) == 2

    bio = BytesIO()
    w = Writer(bio) 
    w.writedword(txn.version)             # nVersion

    if _anyonecanpay:
        w.writebytes(b"\x00"*32)
    else:
        w.writebytes(calcPrevOutsHash(txn))   # hashPrevouts

    if _anyonecanpay or _single or _none:
        w.writebytes(b"\x00"*32)
    else:
        w.writebytes(calcSequenceHash(txn))   # hashSequence

    inp = txn.inputs[inputindex]
    w.writebytes(inp.txn_hash)            # outpoint.hash
    w.writedword(inp.output_index)        # outpoint.index

    if txn.witness:
        wit = txn.witness[inputindex]
        if not wit.encode_scriptcode(w):      # scriptcode
            return messagehash(txn, hashtype, inputindex, outscript)
    else:
        outscript.encode(w)

    w.writeqword(btcvalue)                # value
    w.writedword(inp.sequence_number)     # nSequence

    if _single:
        if inputindex < len(txn.outputs):
            w.writebytes(calcSingleHash(txn, inputindex))
        else:
            w.writebytes(b"\x00"*32)
    elif _none:
        w.writebytes(b"\x00"*32)
    else:
        w.writebytes(calcOutputsHash(txn))    # hashOutputs

    w.writedword(txn.locktime)            # nLocktime
    w.writedword(hashtype)                # hashtype

    data = bio.getvalue()
    return shasha(data)


