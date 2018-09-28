# Bitcoin's keys generator
#
# Usage: python keysGen.py
#
# Requirements: base58, ecdsa

import os, binascii, hashlib, base58, ecdsa

# Hashes ripemd160 fuction
def ripemd160(x):
    d = hashlib.new('ripemd160')
    d.update(x)
    return d

# (MAIN) creates a random bitcoin's key pair
def newPair():
    priv_key = genPriv()
    wif = getWif(priv_key)
    addr = getAddr(getPub(priv_key))
    print("Private Key (WIF):", wif.decode())
    print("Bitcoin Address  :", addr.decode())
    return None

# Generate random private key from system
def genPriv():
    priv_key = os.urandom(32)
    return priv_key

# Convert Private Key to WIF format
def getWif(priv_key):
    fullkey = '80' + binascii.hexlify(priv_key).decode()
    #print(fullkey)
    sha256a = hashlib.sha256(binascii.unhexlify(fullkey)).hexdigest()
    sha256b = hashlib.sha256(binascii.unhexlify(sha256a)).hexdigest()
    wif = base58.b58encode(binascii.unhexlify(fullkey+sha256b[:8]))
    return wif

# Get the Public key from privKey
def getPub(priv_key):
    sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    publ_key = '04' + binascii.hexlify(vk.to_string()).decode()
    return publ_key

# Return bitcoin adress from Public key
def getAddr(publ_key):
    hash160 = ripemd160(hashlib.sha256(binascii.unhexlify(publ_key)).digest()).digest()
    publ_addr_a = b"\x00" + hash160
    checksum = hashlib.sha256(hashlib.sha256(publ_addr_a).digest()).digest()[:4]
    publ_addr_b = base58.b58encode(publ_addr_a + checksum)
    return publ_addr_b

#newPair()
