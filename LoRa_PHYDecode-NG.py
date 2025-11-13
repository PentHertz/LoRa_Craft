#!/usr/bin/en python

from __future__ import print_function

#    LoRa PHYdecoder - parse LoRa PHY decoded by gr-lora
#    Copyright (C) 2020  Sebastien Dudek (@FlUxIuS) @Penthertz
#    Code base on LoRa Craft project @PentHertz from commit a5f0a9d65c5ddc584035d5f45b52763e3a03a55f


from layers import LoRa
from scapy.layers.inet import UDP
from scapy.sendrecv import sniff
#from scapy.packet import bind_layers, Ether
from scapy.all import *
from scapy.utils import wrpcap
from scapy.utils import rdpcap
from lutil.crypto import *
import argparse
from lutil.fonts import *
import code

# default keys
cur_NwSKey = "2B7E151628AED2A6ABF7158809CF4F3C"
cur_AppSKey = "2B7E151628AED2A6ABF7158809CF4F3C"

lpkt = b"" # last pkt

savepcap = None

def savePCAP(pkt):
    global savepcap
    wrpcap(savepcap, pkt, append=True)

def decodePHY(pkt):
    global lpkt, savepcap
    if pkt != lpkt:
        lpkt = pkt
        decoded = LoRa(pkt[UDP].load)
        direction = 1
        print ()
        if decoded.MType & 0b001 == 0b1:
            direction = 0
            print ("<"+"-"*30)
        if decoded.MType & 0b001 == 0b0:
            print ("-"*30+">")
        print (repr(decoded))
        if savepcap is not None:
            savePCAP(pkt)

        if cur_AppSKey is not None:
            print (Fore.WHITE+Style.BRIGHT + "Deciphered Payload: ", decryptFRMPayload(binascii.unhexlify(cur_AppSKey), bytes(decoded), direction=direction), Style.RESET_ALL)


def filterpkt(pkt, port):
    if pkt.haslayer(UDP):
        if pkt[UDP].dport == port and pkt != lpkt:
            return True
    return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                description='Monitor and decode MAC PHY packets.')
    parser.add_argument('-p', '--port', dest='port', default=40868,
                        help='TAP PORT to listen on (default: UDP 40868)')
    parser.add_argument('-i', '--iface', dest='iface', default='lo',
                        help='Interface to monitor (default: local)')
    parser.add_argument('-v', '--version', dest='version', default='1.1',
                        help='LoRaWAN version (1.1 by default)')
    parser.add_argument('-o', '--output', dest='output', default=None,
                        help='PCAP output filename')
    parser.add_argument('-c', '--intercative', dest='interact', action='store_true',
                        help='Interactive mode')
    parser.add_argument('-n', '--NwSKey', dest='netskey', default=None,
                        help='NwSKey')
    parser.add_argument('-a', '--AppSKey', dest='appskey', default=None,
                        help='AppSKey')

    args = parser.parse_args()
    iface = args.iface
    port = int(args.port)

    cur_NwSKey = args.netskey
    cur_AppSKey = args.appskey

    LoRa.version = args.version # setup LoRaWAN version
    savepcap = args.output

    if args.interact is True:
        bind_layers(UDP, LoRa)
        code.interact(local=locals())
    else:
        sniff(prn=decodePHY,
            lfilter=lambda pkt: filterpkt(pkt, port),
            iface=iface)
