#!/usr/bin/env python

from __future__ import print_function

#    LoRa PHYdecoder - parse LoRa PHY decoded by gr-lora
#    Copyright (C) 2020  Sebastien Dudek (@FlUxIuS) at @PentHertz

from layers import LoRa
from scapy.layers.inet import UDP
from scapy.sendrecv import sniff
import argparse


def decodePHY(pkt):
    decoded = LoRa(pkt[UDP].load)
    print (repr(decoded))


def filterpkt(pkt, port):
    if pkt.haslayer(UDP):
        if pkt[UDP].dport == port:
            return True
    return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                description='Monitor and decode MAC PHY packets.')
    parser.add_argument('-p', '--port', dest='port', default=40868,
                        help='TAP PORT to listen on (default: UDP 40868)')
    parser.add_argument('-i', '--iface', dest='iface', default='lo',
                        help='Interface to monitor (default: local)')

    args = parser.parse_args()
    iface = args.iface
    port = int(args.port)

    sniff(prn=decodePHY,
          lfilter=lambda pkt: filterpkt(pkt, port),
          iface=iface)
