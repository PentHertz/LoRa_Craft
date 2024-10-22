# LoRa Craft

LoRa Craft is a small set of tools that aims to provide tools to assess LoRAPHY and LoRaWAN communications.

Available features:

* Capture packet as PCAP and read them
* Parses LoRaPHY and LoRaWAN 1.0 + 1.1 packets
* Supports UpLink as well as DownLink
* Can bruteforce Join-Request and Join-Accept MIC as well as Data Payload MIC
* Can decipher payloads => not tested with real LoRaWAN 1.1 devices yet
* Possible to generate packet at low LoRaPHY layer

## Dependencies

* Python 2 or 3
* Scapy
* GNU Radio 3.8
* gr-lora from [rpp0](https://github.com/rpp0): [link here](https://github.com/rpp0/gr-lora)
* or gr-lorasdr (for TX & RX): [link here](https://github.com/tapparelj/gr-lora_sdr)
* Software-Defined Radio equipment (USRP, bladeRF, RTL-SDR dongle, etc.)

### Receive and decode packets packets

First you need to generate GNU Radio hierachical blocks `lora_txrxdecode.grc`, and `lora_rechan.grc` before running `LoRa_MultiSF_decode_to_UDP.grc` flowgraph located in the `grc` directory.

After that we can run the `LoRa_MultiSF_decode_to_UDP.grc` by connecting one the supported SDR device by the `osmocom Source` block:

![alt text](https://github.com/PentHertz/LoRa_Craft/blob/master/img/LoRaMultiSF.png "Multi channel and SF flowgraph")

Then we can run the decoder script that will automatically parse packet from the socket used by `gr-lora` and display it on the console as follows:

```bash
# python3 LoRa_PHYDecode-NG.py   

------------------------------>
<LoRa  Preamble=0x1 PHDR=0xe312 PHDR_CRC=0x0 MType=Unconfirmed Data Up RFU=0 Major=0 DevAddr=[<DevAddrElem  NwkID=0x6e NwkAddr=0x260117 |>] FCtrl=[<FCtrl_Link  ADR=1 ADRACKReq=0 ACK=0 UpClassB_DownFPending=0 FOptsLen=0 |>] FCnt=0 FPort=1 ULDataPayload="M\x93'\tT\xd6\xa4\x02\x8e\x0e9f\xdc\xfd\xec\x898" MIC=0x8ce72a63 CRC=0x978e |>

------------------------------>
<LoRa  Preamble=0x1 PHDR=0xe312 PHDR_CRC=0x0 MType=Unconfirmed Data Up RFU=0 Major=0 DevAddr=[<DevAddrElem  NwkID=0x6e NwkAddr=0x260117 |>] FCtrl=[<FCtrl_Link  ADR=1 ADRACKReq=0 ACK=0 UpClassB_DownFPending=0 FOptsLen=0 |>] FCnt=1 FPort=1 ULDataPayload='w\xf96\x98\x9f\x1a\x1e\x14\xa3\xac\xb4\xbe_X&\xa1\x81' MIC=0x43f31d41 CRC=0x6b0 |>

<------------------------------
<LoRa  Preamble=0x1 PHDR=0x3219 PHDR_CRC=0x0 MType=Unconfirmed Data Down RFU=0 Major=0 DevAddr=[<DevAddrElem  NwkID=0x6e NwkAddr=0x260117 |>] FCtrl=[<FCtrl_Link  ADR=0 ADRACKReq=0 ACK=0 UpClassB_DownFPending=0 FOptsLen=0 |>] FCnt=0 FPort=1 DLDataPayload="\xb9d\x8c\xf90'" MIC=0xd395a01e |>
```

**Note** we can see 2 uplink packets and 1 downling packet that got parsed by the tool

## Generate packets

To generate packets, you can instantiate a Scapy packet as follows:

```python
>>> from layers.loraphy2wan import *
>>> pkt = LoRa()
>>> pkt
<LoRa  Join_Request_Field=[''] |>
```

And start to fill it.

After crafting your packet, you can use [python-loranode](https://github.com/rpp0/python-loranode) as follows:

```python
>>> from binascii
>>> from loranode import RN2483Controller
>>> to_send = binascii.hexlify(str(pkt))[3:]
>>> c = RN2483Controller("/dev/ttyACM0")  # Choose the correct /dev device here
>>> c.set_sf(7)  # choose your spreading factor here
>>> c.set_bw(150) # choose the bandwidth here
>>> c.set_cr("4/8")  # Set 4/8 coding for example
>>> c.send_p2p(to_send)
```

Note that you should skip the first three bytes (Preamble, PHDR, PHDR_CRC), before sending it with `send_p2p` method.

## LoRa crypto helpers

Few helpers have been implemented to calculate MIC field, encrypt and decrypt packets:

* `JoinAcceptPayload_decrypt`: decrypt Join-accept payloads;
* `JoinAcceptPayload_encrypt`: encrypt Join-accept payloads;
* `getPHY_CMAC`: compute MIC field of a packet using a provided key;
* `checkMIC`: check MIC of a packet against a provided key.
* `checkDATAMIC_1x`: check MIC for FRMPayloads
* `bruteforceDATAMIC_10`: bruteforce MIC for UL/DL FRMPayloads


### Checking MIC for 'Join-request' packets

As an example, to check if the key `000102030405060708090A0B0C0D0E0F` is used to compute MIC on the following Join-request, we can write a little script as follows:

```python
>>> from layers.loraphy2wan import *
>>> from lutil.crypto import *
>>> key = "000102030405060708090A0B0C0D0E0F"
>>> p = '000000006c6f7665636166656d656565746f6f00696953024c49'
>>> pkt = LoRa(binascii.unhexlify(p))
>>> pkt
<LoRa  Preamble=0x0 PHDR=0x0 PHDR_CRC=0x0 MType=Join-request RFU=0 Major=0 Join_Request_Field=[<Join_Request  AppEUI='lovecafe' DevEUI='meeetoo' DevNonce=26985 |>] MIC=0x53024c49 |>
>>> checkMIC(binascii.unhexlify(key), bytes(pkt))
True
```

### Deciphering a 'Join-accept' message

To check if `000102030405060708090A0B0C0D0E0F` key is used to encrypt a Join-accept message, we can combine `JoinAcceptPayload_decrypt` and `checkMIC` as follows:

```python
>>> pkt = "000000200836e287a9805cb7ee9e5fff7c9ee97a"
>>> ja = JoinAcceptPayload_decrypt(binascii.unhexlify(key), binascii.unhexlify(pkt))
>>> ja
'ghi#\x01\x00\xb2\\C\x03\x00\x00{\x06O\x8a'
>>> Join_Accept(ja)
<Join_Accept  JoinAppNonce=0x6fe14a NetID=0x10203 DevAddr=0x68e8cb1 OptNeg=0 RX1DRoffset=0x0 RX2_Data_rate=0x0 RxDelay=0x0 |<Padding  load='\xbejsu' |>>
>>> p = b"\x00\x00\x00\x20"+ja # adding headers
>>> checkMIC(binascii.unhexlify(key), p)
>>> True
```

### Check and bruteforce the MIC of a FRMPayload

We want to check the MIC of the following captured packet containing an UL/DL data:

```python
~>>> pkt
<LoRa  Preamble=0x1 PHDR=0xe312 PHDR_CRC=0x0 MType=Unconfirmed Data Up RFU=0 Major=0 DevAddr=[<DevAddrElem  NwkID=0x6e NwkAddr=0x260117 |>] FCtrl=[<FCtrl_Link  ADR=1 ADRACKReq=0 ACK=0 UpClassB_DownFPending=0 FOptsLen=0 |>] FCnt=0 FPort=1 ULDataPayload="M\x93'\tT\xd6\xa4\x02\x8e\x0e9f\xdc\xfd\xec\x898" MIC=0x8ce72a63 CRC=0x978e |>
```

If we already have the `NwkSkey` that is `2B7E151628AED2A6ABF7158809CF4F3C` for example, we can use one of the `checkDATAMIC_1x` function (depending of LoRaWAN version) to check it:

```python
~>>> checkDATAMIC_10(binascii.unhexlify("2B7E151628AED2A6ABF7158809CF4F3C"), bytes(pkt))
True
```

And see that decoded MIC (`MIC=0x8ce72a63`) with the Scapy layer matches the one processed by `checkDATAMIC_1x` function.

But in case we want to bruteforce this key, we can actually do it using the `bruteforceDATAMIC_1x` function by providing a list of key dictionnary path:

```python
~>>> bruteforceDATAMIC_10(bytes(pkt), "/home/fluxius/Projects/LoRa/tools/LoRa_Craft/resources/keydict.lst")
Testing:  00000000000000000000000000000000

Testing:  00010101010101010101010101010101

Testing:  01234567890123456789012345678901

Testing:  000102030405060708090a0b0c0d0e0f

Testing:  00020202020202020202020202020202

Testing:  00030303030303030303030303030303

Testing:  00040404040404040404040404040404

Testing:  00050505050505050505050505050505

Testing:  00060606060606060606060606060606

Testing:  2B7E151628AED2A6ABF7158809CF4F3C

('Found NwkSKey: ', b'2b7e151628aed2a6abf7158809cf4f3c')
```

**Warning:** the check function also takes a 3rd argument that is the direction of the packet (UL or DL)

And we found the correct key! :) => so we can mess with packet's integrity now.


### Decipher a FRMPayload

If we have been able to retrieve the key used to decipher the FRMPayload, we can try it using the `decryptFRMPayload` function as follows:

```python
~>>> pkt
<LoRa  Preamble=0x1 PHDR=0xe312 PHDR_CRC=0x0 MType=Unconfirmed Data Up RFU=0 Major=0 DevAddr=[<DevAddrElem  NwkID=0x6e NwkAddr=0x260117 |>] FCtrl=[<FCtrl_Link  ADR=1 ADRACKReq=0 ACK=0 UpClassB_DownFPending=0 FOptsLen=0 |>] FCnt=0 FPort=1 ULDataPayload="M\x93'\tT\xd6\xa4\x02\x8e\x0e9f\xdc\xfd\xec\x898" MIC=0x8ce72a63 CRC=0x978e |>
~>>> decryptFRMPayload(binascii.unhexlify("2b7e151628aed2a6abf7158809cf4f3c"), bytes(pkt))
b'<3Trend with Love\xed@W`f/;\xafL\xff\x04\xd0\xb5\xb83'
```

**Warning:** the check function also takes a 3rd argument that is the direction of the packet (UL or DL)

## Further work

* Test MIC bruteforcing and deciphering on LoRaWAN 1.1