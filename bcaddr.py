from __future__ import print_function, division
import argparse
import coininfo
import BitcoinAddress as bca
"""
By Willem Hengeveld <itsme@xs4all.nl>

Tool for converting bitcoin addresses
often bcaddr will auto detect the type of input data, and convert accordingly.
"""

bca.setversions(0, 128)


parser = argparse.ArgumentParser(description='Tool for converting between various representations of bitcoin addresses.')
parser.add_argument('-a', '--address_version',  type=str) # 0x6f for testnet, 0xc4 for testnet-p2sh
parser.add_argument('-w', '--wallet_version',  type=str)
parser.add_argument('--test', help='handle btc testnet addresses', action='store_true')
parser.add_argument('--lite', help='handle litecoin addresses', action='store_true')
parser.add_argument('--doge', help='handle dogecoin addresses', action='store_true')
parser.add_argument('--alt', type=str, help='Altcoin by name')
parser.add_argument('--privkey',  action='store_true')
parser.add_argument('--wallet',  action='store_true')
parser.add_argument('--minikey',  action='store_true')
parser.add_argument('--pubkey',  action='store_true')
parser.add_argument('--hash',  '--addrhash', action='store_true')
parser.add_argument('--address',  action='store_true')
parser.add_argument('--bech32',  action='store_true')
parser.add_argument('--script', action='store_true')
parser.add_argument('--secp256r1', action='store_true')
parser.add_argument('ARGS',  nargs='*', type=str)

# todo: --output <spec>: output only specific item for each input line
# todo: support data from stdin

args = parser.parse_args()
if args.secp256r1:
    bca.B = bca.myecdsa.secp256r1()

if args.address_version is None:
    args.address_version = 0
else:
    args.address_version = int(args.address_version, 0)
if args.wallet_version is None:
    args.wallet_version = 128
else:
    args.wallet_version = int(args.wallet_version, 0)

if args.lite:
    bca.setversions(48, 176)
elif args.doge:
    bca.setversions(30, 128)
elif args.test:
    bca.setversions(0, 0x6f)
elif args.alt:
    coins= coininfo.by_name(args.alt)
    if coins:
        bca.setversions(coins[0].aver,coins[0].wver)
        print("Using %s settings" % coins[0].names)
else:
    bca.setversions(args.address_version, args.wallet_version)

decoder= bca.BitcoinAddress.from_auto

if   args.privkey: decoder= bca.BitcoinAddress.from_privkey
elif args.wallet : decoder= bca.BitcoinAddress.from_wallet 
elif args.minikey: decoder= bca.BitcoinAddress.from_minikey
elif args.pubkey : decoder= bca.BitcoinAddress.from_pubkey
elif args.hash   : decoder= bca.BitcoinAddress.from_hash   
elif args.address: decoder= bca.BitcoinAddress.from_base58
elif args.bech32 : decoder= bca.BitcoinAddress.from_bech32
elif args.script : decoder= bca.BitcoinAddress.from_script

for a in args.ARGS:
    a = a.strip().replace(" ", "")
    addr= decoder(a)
    if addr:
        addr.dump()

