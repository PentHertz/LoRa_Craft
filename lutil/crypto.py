#    LoRa Cryto utils
#    Copyright (C) 2020  Sebastien Dudek (@FlUxIuS) at @PentHertz

from Crypto.Cipher import AES
from Crypto.Hash import CMAC
import binascii

def JoinAcceptPayload_decrypt(key, hexpkt):
    """
        Decrypt Join Accept payloads
            In(1): String 128 bits key
            In(2): String packet
            Out: String decrypted Join accept packet    
    """
    payload = hexpkt[4:]
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(payload) # logic right? :D

def JoinAcceptPayload_encrypt(key, hexpkt):
    """
        Encrypts Join Accept Payload
            In(1): String 128 bits key
            In(2): String packet
            Out: String encrypted Join accept payload
    """
    payload = hexpkt[4:]
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(payload)

def getPHY_CMAC(key, hexpkt, direction=1):
    """
        Compute MIC with AES CMAC
            In(1): String 128 bits key for CMAC
            In(2): hexstring of the packet
            In(3): Direction (1: network, 0: end device)
            Out: Hexdigest of computed MIC  
    """
    lowoff = -4
    if direction == 0:
        lowoff = -6 # skip the CRC 
    payload = hexpkt[3:lowoff]
    cobj = CMAC.new(key, ciphermod=AES)
    toret = cobj.update(payload).hexdigest()
    return toret[:8]

def checkMIC(key, hexpkt, direction=1):
    """
        Check MIC in the packet
            In(1): String key for CMAC
            In(2): String of the packet
            In(3): Direction (1: network, 0: end device)
            Out: True if key is correct, False otherwise
    """
    mic = hexpkt[-4:]
    if direction == 0:
        mic = hexpkt[-6:-2] # skip the CRC
    try:
        binascii.unhexlify(mic)
    except:
        mic = binascii.hexlify(mic)
    cmic = getPHY_CMAC(key, hexpkt)
    return (mic == cmic)

#TODO: more helpers
