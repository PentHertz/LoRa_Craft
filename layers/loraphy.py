# -*- coding: utf-8 -*-

#    LoRa Scapy layers
#    Copyright (C) 2025  Sebastien Dudek (@FlUxIuS) developped @PentHertz

from scapy.all import *
from scapy.fields import *
import struct

def crc16_loraphy(data, length):
    """LoRaPHY CRC-16 (inspired from https://github.com/tapparelj/gr-lora_sdr/blob/master/lib/crc_verif_impl.cc)"""
    crc = 0x0000
    for i in range(length):
        newByte = data[i]
        for _ in range(8):
            if ((crc & 0x8000) >> 8) ^ (newByte & 0x80):
                crc = (crc << 1) ^ 0x1021
            else:
                crc = crc << 1
            crc &= 0xFFFF
            newByte = (newByte << 1) & 0xFF
    return crc


class LoRaPHY(Packet):
    name = "LoRaPHY"
    fields_desc = [
        BitFieldLenField("PayloadLength", None, 8, length_of="PHYPayload"),
        BitField("CodingRate", 1, 3),
        BitField("CRCPresent", 1, 1),
        BitField("Reserved", 0, 4),
        XBitField("PHDR_CRC", 0, 8),

        StrLenField("PHYPayload", b"",
                    length_from=lambda pkt: pkt.PayloadLength),

        ConditionalField(
            XShortField("PayloadCRC", 0),
            lambda pkt: pkt.CRCPresent == 1
        )
    ]

    def post_build(self, p, pay):
        if self.CRCPresent and self.PayloadCRC == 0:
            payload_len = len(self.PHYPayload)
            if payload_len >= 2:
                payload = bytes(self.PHYPayload)
                crc = crc16_loraphy(payload, payload_len - 2)
                crc = crc ^ payload[payload_len - 1] ^ (payload[payload_len - 2] << 8)
                p = p[:-2] + struct.pack('<H', crc)

        return p + pay

    def extract_padding(self, s):
        return "", s

bind_layers(LoRaPHY, Raw)