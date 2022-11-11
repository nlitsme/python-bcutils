# check a list of transactions for crackable keys.
from __future__ import print_function
from io import BytesIO
from binascii import a2b_hex, b2a_hex
from collections import defaultdict
import itertools
from myecdsa import secp256k1

from hashing import shasha, sharip
from bcdataio import Reader, Writer
from txndecoder import Transaction, Script
from bcsigutils import decode_signature, messagehash, witnesshash 

from convert import numfrombytes as tonum
from BitcoinAddress import PublicKey

import blockchairapi
import re
import binascii

E = secp256k1()

def unhex(x):
    x = re.sub(r'\s+--.*', '', x)
    return binascii.a2b_hex(x.replace(" ", "").replace("\n", ""))

class CrackInfo:
    def __repr__(self):
        l = []
        for k in dir(self):
            if k.startswith('_'): continue
            v = getattr(self, k)
            if type(v)==type(self.__repr__):
                continue
            if type(v)==bytes:
                v = b2a_hex(v)
            l.append("%s=%s" % (k, v))
        return ", ".join(l)

    def validate(self):
        r = tonum(self.r)
        s = tonum(self.s)
        m = tonum(self.m)
        p = PublicKey.frompubkey(self.pubkey)

        return E.verify(m, p.point, r, s)
            

def invent_scriptpub(pubkey):
    bio = BytesIO()

    w = Writer(bio) 
    w.writebyte(0x76)  # DUP
    w.writebyte(0xa9)  # HASH160
    w.writebyte(0x14)  # size of addrhash
    w.writebytes(sharip(pubkey))  # the address hash
    w.writebyte(0x88)  # EQUALVERIFY
    w.writebyte(0xac)  # CHECKSIG

    s = Script()
    s.bytecode = bio.getvalue()

    return s

def do_crack(a, b):
    global E
    r = tonum(a.r)
    s1 = tonum(a.s)
    s2 = tonum(b.s)
    m1 = tonum(a.m)
    m2 = tonum(b.m)

    for sa in (1, -1):
        for sb in (1, -1):
            k, x = E.crack2(r, s1, s2, m1, m2)
            if k is None:
                print("r=%s, 1:(%s,%s) 2:(%s,%s), p=%s" % (r, s1, m1, s2, m2, a.pubkey))
            else:
                yield k, x
            s2 = -s2
        s1 = -s1

def do_crack1(a, k):
    global E
    r = tonum(a.r)
    s = tonum(a.s)
    m = tonum(a.m)

    for sa in (1, -1):
        x = E.crack1(r, s, m, k)
        yield x
        s = -s

def calctxnhash(txn):
    bio = BytesIO()
    w = Writer(bio) 
    txn.encode(w, exclude_witness=True)
    return shasha(bio.getvalue())


def extractvalues(script):
    for tag, value in script:
        if tag == 'data':
            if not value:
                pass
            if len(value) in (20, 32):
                yield 'hash', value
            elif len(value) in (33, 65) and value[0] in (2,3,4):
                yield 'pub', value
            elif 50 < len(value) < 74 and value[0] == 0x30:
                yield 'sig', value
            else:
                embedded = Script()
                embedded.bytecode = value
                try:
                    yield from extractvalues(embedded)
                except Exception as e:
                    print("err %s" % e)

def main():
    import argparse
    parser = argparse.ArgumentParser(description='transaction cracker')
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('ARGS',  nargs='*', type=str)
    args = parser.parse_args()

    transactions = []

    if args.ARGS == ["-"]:
        import sys
        for l in sys.stdin.readlines():
            if l and l[0]!='-':
                transactions.append(unhex(l))
    else:
        for a in args.ARGS:
            if len(a)==64:
                transactions.append(blockchairapi.gettransaction(unhex(a)))
            else:
                transactions.append(unhex(a))

    crackdata = []

    txnbyhash = dict()

    def lookupoutput(txnhash, outputindex):
        t = txnbyhash.get(txnhash)
        if t:
            return t.outputs[outputindex]

    # for make index of all transactions
    for txndata in transactions:
        if not txndata: continue
        r = Reader(BytesIO(txndata))
        txn = r.readobject(Transaction)
        txnbyhash[calctxnhash(txn)] = txn

    # then go over all transactions, extracting the 'crackinfo'
    # needed to do the cracking later.
    for txn in txnbyhash.values():
        if args.verbose:
            print("txn: ", b2a_hex(calctxnhash(txn)))
            print(" - %s" % b2a_hex(txndata))

        for i, inp in enumerate(txn.inputs):
            pubs = set()
            sigs = set()

            scripts = [inp.script]
            if txn.witness:
                scripts.append(txn.witness[i])

            for s in scripts:
                for tag, value in extractvalues(s):
                    if tag=='sig':
                        sigs.add(decode_signature(value))
                    elif tag=='pub':
                        pubs.add(value)


            if not pubs:
                print("no publickeys in input")
                continue

            out = lookupoutput(inp.txn_hash, inp.output_index)
            for pub in pubs:
                if txn.witness:
                    if not out:
                        # can't calculate the witnesshash without the btcvalue.
                        if args.verbose:
                            print("missing btcvalue for input %s:%d" % (b2a_hex(inp.txn_hash), inp.output_index))
                        continue
                    m = witnesshash(txn, i, out.btcvalue)
                else:
                    if not out:
                        # we can invent a probable output script
                        outscr = invent_scriptpub(pub)
                    else:
                        outscr = out.script

                    # TODO - backport changes here.
                    m = messagehash(txn, 1, i, outscr)

                for sig in sigs:
                    ci = CrackInfo()
                    ci.srctxn = inp.txn_hash
                    ci.srcindex = inp.output_index
                    ci.pubkey = pub
                    ci.r, ci.s = sig
                    ci.m = m

                    crackdata.append(ci)
                    if args.verbose:
                        if not ci.validate():
                            print("FAIL", ci)
                        else:
                            print("OK", ci)

        if args.verbose:
            print()

    print("found %d crackinfo" % len(crackdata))

    # now sort the crackinfo by pubkey and rvalue.
    by_pk_and_r = defaultdict(list)
    for ci in crackdata:
        by_pk_and_r[(ci.pubkey,ci.r)].append(ci)

    print("found %d r+p pairs" % len(by_pk_and_r))

    # now go over all combinations of duplicate (pubkey+rvalue) pair,
    # and run 'crack'

    knownk = set()
    knownx = set()
    rvallookup = dict()
    for crackable in sorted(by_pk_and_r.values(), key=lambda x:len(x)):
        print("cracking a list of %d items" % len(crackable))
        for a, b in itertools.combinations(crackable, 2):
            found = False
            for k, x in do_crack(a, b):
                if int(k) not in knownk or int(x) not in knownx:
                    print("found: k=%s, x=%s" % (k, x))
                    knownk.add(int(k))
                    rvallookup[a.r] = k
                    knownx.add(int(x))
                    found = True
            if found: break

    print("now doing crack1")
    for crackable in sorted(by_pk_and_r.values(), key=lambda x:len(x)):
        print("cracking a list of %d items" % len(crackable))
        for a in crackable:
            k = rvallookup.get(a.r)
            if k:
                for x in do_crack1(a, k):
                    if int(x) not in knownx:
                        print("found: x=%s" % (x))
                        knownx.add(int(x))


if __name__ == '__main__':
    main()

