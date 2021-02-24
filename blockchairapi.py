from binascii import a2b_hex, b2a_hex
import urllib.request
import json

baseurl = "https://api.blockchair.com/bitcoin/raw/transaction/"

def getjson(url):
    with urllib.request.urlopen(url) as response:
        text = response.read()
        return json.loads(text)

def gettransaction(id):
    for _ in range(2):
        try:
            t = getjson(baseurl + b2a_hex(id).decode('ascii'))
            for k, v in t["data"].items():
                if v and v["raw_transaction"]:
                    return a2b_hex(v["raw_transaction"])
        except Exception as e:
            pass

        # reverse id for second pass.
        id = id[::-1]


