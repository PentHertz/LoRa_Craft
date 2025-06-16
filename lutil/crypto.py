#    LoRa Cryto utils
#    Copyright (C) 2020  Sebastien Dudek (@FlUxIuS) at @PentHertz

from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Util.Padding import pad
import binascii


def JoinAcceptPayload_decrypt(key, hexpkt):
    """
        Decrypt Join Accept payloads
            In(1): String 128 bits key
            In(2): String packet
            Out: String decrypted Join accept packet
    """
    payload = hexpkt[4:]
    if len(payload) % 16 != 0: # remove possible padding or erroned CRC after demod
        payload = payload[:-2]
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(payload)  # logic right? :D


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
        lowoff = -6  # skip the CRC
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
        mic = hexpkt[-6:-2]  # skip the CRC
    try:
        binascii.unhexlify(mic)
    except Exception:
        mic = binascii.hexlify(mic)
    cmic = bytes(getPHY_CMAC(key, hexpkt), 'utf-8')
    print (repr(mic), repr(cmic))
    return (mic == cmic)


def bruteforceJoinMIC(pkt , keylist, direction=1):
    """
        Bruteforce Join procedure AppKey/NwkKey
            In(1): Bytes array of the packet
            In(2): String path of the dictionnary list
            In(3): Direction (1: network, 0: end device)
    """
    f = open(keylist, "r")
    keys = f.readlines()
    for key in keys:
        print ("Testing: ", key)
        key = binascii.unhexlify(key[:-1])
        if checkMIC(key, pkt, direction) is True:
            return ("Found AppKey/NwkKey: ", binascii.hexlify(key))


def checkDATAMIC_10(key, hexpkt, direction=1):
    """
        Checks Data Payload MIC
            In(1): Bytes array of CMAC key
            In(2): Bytes array pf the packet
            In(3): Direction (1: network, 0: end device)
    """
    direct = b"\x00" # uplink
    lowoff = -6
    mic = hexpkt[-6:-2]
    if direction == 0: # don't skip the CRC
        direct = b"\x01"
        lowoff = -4
        mic = hexpkt[-4:]
    Fcnt = hexpkt[9:11]
    b0 = b"\x49"+b"\x00"*4+direct+hexpkt[4:8]+Fcnt+b"\x00\x00"+b"\x00"+str.encode(chr(len(hexpkt[3:lowoff])))
    cobj = CMAC.new(key, ciphermod=AES)
    toret = cobj.update(b0+hexpkt[3:lowoff]).digest()
    cmic = toret[:4]
    return (mic == cmic)


def checkDATAMIC_11(key, hexpkt, direction=1, DLACK=True):
    # TODO: to check against real implem
    """
        Checks Data Payload MIC
            In(1): Bytes array of CMAC key
            In(2): Bytes array of the packet
            In(3): Direction (1: network, 0: end device)
            Int(4): Is the device connected to a network?
    """
    direct = b"\x00" # uplink
    lowoff = -6
    mic = hexpkt[-6:-2]
    if direction == 0: # don't skip the CRC
        direct = b"\x01"
        lowoff = -4
        mic = hexpkt[-4:]
    Fcnt = hexpkt[9:11]
    ConfFCnt = int.from_bytes(b"\x45\x34", "big") % 16
    if DLACK is False: # if not confirmed uplink
        ConfFCnt = "\x00"*2
    b0 = b"\x49"+ ConfFCnt +b"\x00"*2+direct+hexpkt[4:8]+Fcnt+b"\x00\x00"+b"\x00"+str.encode(chr(len(hexpkt[3:lowoff])))
    cobj = CMAC.new(key, ciphermod=AES)
    toret = cobj.update(b0+hexpkt[3:lowoff]).digest()
    cmic = toret[:4]
    return (mic == cmic)


def decryptFRMPayload(key, hexpkt, direction=1):
    """
        Decrypt the Payload
            In(1): Bytes array of key used to encrypt the payload
            In(2): Bytes array of the packet
            In(3): Direction (1: network, 0: end device)
    """
    direct = b"\x00" # uplink
    if direction == 0:
        direct = b"\x01"
    Fcnt = hexpkt[9:11]
    DevAddr = hexpkt[4:8]
    ai = lambda i : b"\x01"+b"\x00"*4+direct+DevAddr+Fcnt+b"\x00\x00"+b"\x00"+str.encode(chr(i))
    FRM_Payload = pad(hexpkt[12:-4], 16) # must be aligned in block of 16 bytes
    K = math.ceil(len(FRM_Payload)/16)
    Si = lambda v_a : AES.new(key, AES.MODE_ECB).encrypt(v_a)
    S = b''.join([Si(x) for x in [ai(y) for y in range(1, K+1)]])
    pld_xor_S = bytes(a ^ b for (a, b) in zip(FRM_Payload, S))
    return pld_xor_S


def bruteforceDATAMIC_10(pkt , keylist, direction=1):
    """
        Decrypt the Payload
            In(1): Bytes array of the packet
            In(2): String path of the dictionnary list
            In(3): Direction (1: network, 0: end device)
    """
    f = open(keylist, "r")
    keys = f.readlines()
    for key in keys:
        print ("Testing: ", key)
        key = binascii.unhexlify(key[:-1])
        if checkDATAMIC_10(key, pkt, direction) is True:
            return ("Found NwkSKey: ", binascii.hexlify(key))
# TODO: more helpers
