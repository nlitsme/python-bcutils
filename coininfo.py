import re
"""
By Willem Hengeveld <itsme@xs4all.nl>

Database of alt coin parameters
"""
class CoinInfo:
    def __init__(self, **kw):
        for k,v in kw.items():
            setattr(self,k, v)

    def matchname(self, name):
        return re.search(name, self.names, re.IGNORECASE) is not None

    def matchlevel(self, name):
        if re.search(r'\b%s\b' % name, self.names, re.IGNORECASE) is not None:
            return 0
        if re.search(r'\b%sCoin\b' % name, self.names, re.IGNORECASE) is not None:
            return 1
        if re.search(r'\b%s' % name, self.names, re.IGNORECASE) is not None:
            return 2
        if re.search(r'%s' % name, self.names, re.IGNORECASE) is not None:
            return 3
        return 4


# one type is not in this table: 
#    0x05 scriptaddr, , 0xC4 script-test

# note: entries marked with '!' don't follow the rule: wver == aver + 0x80

coins=[
CoinInfo(aver=0x00, wver=0x80, names="IncognitoCoin,HamRadioCoin,Bitcoin,Freicoin,Titcoin,WankCoin,Devcoin,MobiusCoin"),
CoinInfo(aver=0x03, wver=0x83, names="MoonCoin"),
CoinInfo(aver=0x08, wver=0x88, names="Novacoin,42coin"),
CoinInfo(aver=0x0B, wver=0x8B, names="CryptoBullion"),
CoinInfo(aver=0x0E, wver=0x8E, names="Feathercoin"),
CoinInfo(aver=0x0F, wver=0x8F, names="MonetaryUnit"),
CoinInfo(aver=0x10, wver=0x90, names="GabenCoin"),
CoinInfo(aver=0x14, wver=0x94, names="Magicoin"),
CoinInfo(aver=0x15, wver=0x95, names="Catcoin"),
CoinInfo(aver=0x17, wver=0x80, names="Latium"),  # !
CoinInfo(aver=0x17, wver=0x97, names="Anoncoin,Primecoin,Animecoin,Apexcoin,Auroracoin"),
CoinInfo(aver=0x17, wver=0xE6, names="Acoin"),  # !
CoinInfo(aver=0x19, wver=0x99, names="Blackcoin"),
CoinInfo(aver=0x19, wver=0xBF, names="Nubits"),  # !
CoinInfo(aver=0x1A, wver=0x9A, names="BunnyCoin"),
CoinInfo(aver=0x1C, wver=0x9C, names="Corgicoin,Capricoin,CannabisCoin,CanadaeCoin,Cryptoescudo"),
CoinInfo(aver=0x1E, wver=0x9E, names="Dogecoin,Digitalcoin,CassubianDetk,DogecoinDark"),
CoinInfo(aver=0x21, wver=0xA1, names="EmerCoin"),
CoinInfo(aver=0x23, wver=0xA3, names="Fibre,FUDcoin,Fluttercoin,CryptoClub"),
CoinInfo(aver=0x24, wver=0x80, names="Fuelcoin"),  # !
CoinInfo(aver=0x24, wver=0xA4, names="Fujicoin"),
CoinInfo(aver=0x26, wver=0xA6, names="Guldencoin,Goodcoin,USDe,GlobalBoost"),
CoinInfo(aver=0x27, wver=0xA7, names="Guncoin"),
CoinInfo(aver=0x28, wver=0xA8, names="HTML5Coin"),
CoinInfo(aver=0x2B, wver=0xAB, names="Jumbucks,Judgecoin"),
CoinInfo(aver=0x2D, wver=0xAD, names="eKrona"),
CoinInfo(aver=0x2F, wver=0xAF, names="Pesetacoin,Birdcoin"),
CoinInfo(aver=0x30, wver=0xB0, names="IridiumCoin,ImperiumCoin,DeafDollars,MagicInternetMoney,eGulden,Litecoin"),
CoinInfo(aver=0x32, wver=0xB2, names="MarteXcoin,Marscoin,Monocle,TreasureHuntCoin,Megacoin,Myriadcoin"),
CoinInfo(aver=0x32, wver=0xE0, names="Mazacoin"),  # !
CoinInfo(aver=0x33, wver=0x8B, names="MasterDoge"),  # !
CoinInfo(aver=0x34, wver=0x80, names="NameCoin"),  # !
CoinInfo(aver=0x37, wver=0xB7, names="PHCoin,Potcoin,Peercoin,Pandacoin,Paycoin"),
CoinInfo(aver=0x38, wver=0xB8, names="PhoenixCoin"),
CoinInfo(aver=0x3A, wver=0xBA, names="Quark"),
CoinInfo(aver=0x3C, wver=0x80, names="Riecoin"),  # !
CoinInfo(aver=0x3C, wver=0xBC, names="Rimbit"),
CoinInfo(aver=0x3D, wver=0xBD, names="Reddcoin"),
CoinInfo(aver=0x3E, wver=0xBE, names="GridcoinResearch,StealthCoin,Sambacoin"),
CoinInfo(aver=0x3F, wver=0x80, names="SibCoin"),  # !
CoinInfo(aver=0x3F, wver=0xBF, names="SongCoin,Syscoin"),
CoinInfo(aver=0x41, wver=0xC1, names="TittieCoin"),
CoinInfo(aver=0x42, wver=0xC2, names="Topcoin"),
CoinInfo(aver=0x46, wver=0x56, names="VikingCoin"),  # !
CoinInfo(aver=0x47, wver=0xC7, names="Viacoin,Vertcoin"),
CoinInfo(aver=0x49, wver=0xC9, names="WorldCoin,W2Coin"),
CoinInfo(aver=0x4C, wver=0xCC, names="Dash"),
CoinInfo(aver=0x50, wver=0xE0, names="Zetacoin"),  # !
CoinInfo(aver=0x52, wver=0xD2, names="Alphacoin"),
CoinInfo(aver=0x55, wver=0xD5, names="BBQcoin"),
CoinInfo(aver=0x5A, wver=0xAB, names="LiteDoge"),  # !
CoinInfo(aver=0x5C, wver=0xDC, names="EnergyCoin"),
CoinInfo(aver=0x60, wver=0xE0, names="Fastcoin"),
CoinInfo(aver=0x6F, wver=0xEF, names="TestnetBitcoin"),
CoinInfo(aver=0x73, wver=0xF3, names="Omnicoin,Ocupy,Onyxcoin"),
CoinInfo(aver=0x82, wver=0xE0, names="Unobtanium"),  # !
CoinInfo(aver=0x87, wver=0x97, names="WeAreSatoshiCoin"),  # !
CoinInfo(aver=0x8A, wver=0x80, names="iXcoin"),  # !
]

def by_name(name):
    return sorted([c for c in coins if c.matchname(name) ], key=lambda x:x.matchlevel(name))

def by_wallet_version(ver):
    return [c for c in coins if c.wver==ver]

def by_address_version(ver):
    return [c for c in coins if c.aver==ver]

