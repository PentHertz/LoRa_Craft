# -*- coding: utf-8 -*-

#    LoRa Scapy layers
#    Copyright (C) 2025  Sebastien Dudek (@FlUxIuS) developped @PentHertz

from scapy.all import *
from scapy.fields import *

class LoRaPHY(Packet):
    name = "LoRaPHY"

    fields_desc = [
        BitField("PayloadLength", 0, 8),
        BitField("CodingRate", 1, 3),
        BitField("CRCPresent", 1, 1),
        BitField("Reserved", 0, 4),
        BitField("PHDR_CRC", 0, 8),

        StrLenField("PHYPayload", b"",
                    length_from=lambda pkt: pkt.PayloadLength),

        ConditionalField(
            XShortField("PayloadCRC", 0),
            lambda pkt: pkt.CRCPresent == 1
        )
    ]

    def extract_padding(self, s):
        return "", s

bind_layers(LoRaPHY, Raw)
