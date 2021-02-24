# check a list of transactions for crackable keys.
from io import BytesIO
from binascii import a2b_hex, b2a_hex
from collections import defaultdict
import itertools
from ecdsa import secp256k1

from hashing import shasha, sharip
from bcdataio import Reader, Writer
from txndecoder import Transaction, Script
from bcsigutils import decode_signature, messagehash

from convert import numfrombytes as tonum

import blockchairapi
import re
import binascii

def unhex(x):
    x = re.sub(r'\s+--.*', '', x)
    return binascii.a2b_hex(x.replace(" ", "").replace("\n", ""))

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

    def empty_script(self):
        return Script()

def do_crack(a, b):
    E = secp256k1()
    k, x = E.crack2(tonum(a.r), tonum(a.s), tonum(b.s), tonum(a.m), tonum(b.m))
    print("(++s) --> %s %s" % (k, x))
    k, x = E.crack2(tonum(a.r), tonum(a.s), -tonum(b.s), tonum(a.m), tonum(b.m))
    print("(+-s) --> %s %s" % (k, x))
    k, x = E.crack2(tonum(a.r), -tonum(a.s), tonum(b.s), tonum(a.m), tonum(b.m))
    print("(-+s) --> %s %s" % (k, x))
    k, x = E.crack2(tonum(a.r), -tonum(a.s), -tonum(b.s), tonum(a.m), tonum(b.m))
    print("(--s) --> %s %s" % (k, x))

def calctxnhash(txn):
    bio = BytesIO()
    w = Writer(bio) 
    txn.encode(w, exclude_witness=True)
    return shasha(bio.getvalue())

def main():
    import argparse
    parser = argparse.ArgumentParser(description='transaction cracker')
    parser.add_argument('ARGS',  nargs='*', type=str)
    args = parser.parse_args()

    transactions = []

    for a in args.ARGS:
        if len(a)==64:
            transactions.append(blockchairapi.gettransaction(unhex(a)))
        else:
            transactions.append(unhex(a))

    crackdata = []

    # first go over all transactions, extracting the 'crackinfo'
    # needed to do the cracking later.
    for txndata in transactions:
        r = Reader(BytesIO(txndata))
        txn = r.readobject(Transaction)
        print("txn: ", b2a_hex(calctxnhash(txn)))

        for i, inp in enumerate(txn.inputs):
            ci = CrackInfo()
            ci.srctxn = inp.txn_hash
            ci.srcindex = inp.output_index
            ci.pubkey = None
            ci.r = None
            ci.s = None
            for tag, value in inp.script:
                if tag == 'data':
                    if len(value) in (33, 65):
                        ci.pubkey = value
                        print("found pubkey", b2a_hex(value))
                    elif 65 < len(value) < 74:
                        ci.r, ci.s = decode_signature(value)
                        print("found signature", b2a_hex(value))

            if not ci.pubkey:
                continue
            ci.m = messagehash(txn, ci, i)

            crackdata.append(ci)
        print()

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

