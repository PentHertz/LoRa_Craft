# LoRa Craft

LoRa Craft is a small set of tools to receive signals with SDR, decode et craft LoRaWAN packets on top of a **gr-lora** GNU Radio module.

This repository will be completed with other tools soon, depending on needs during assessments :)

## Dependencies

* Python 2 or 3
* Scapy
* GNU Radio 3.8
* gr-lora from [rpp0](https://github.com/rpp0): [link here](https://github.com/rpp0/gr-lora)
* Software-Defined Radio equipment (USRP, bladeRF, RTL-SDR dongle, etc.)

## Receive signal and decode its data

### Receive

To receive a signal, an example of a GRC schema is available in the folder `grc_examples/usrp_LoRa_decode_to_UDP.grc` for USRP, as shown as follows:

![alt text](https://github.com/PentHertz/LoRa_Craft/blob/master/img/completeschema.png "Schema to receive LoRa signal")

The channel frequency, as well as the spreading factor and the bandwidth, must be set correctly to valid values with the help of the FFT and waterfall sinks:

![alt text](https://github.com/PentHertz/LoRa_Craft/blob/master/img/frequencydet_zoomout_sf12bw125.png "Waterfall and FFT sinks")

Note: Multiple frequencies can be used by targets. This would imply to include multiple receivers in GRC.

For more information on how to detect LoRa signal, please take a look at the following post: https://penthertz.com/blog/testing-LoRa-with-SDR-and-handy-tools.html. 

### Decode

Once the receiver is running with the SDR equipment, we use the script `LoRa_PHYDecode.py`:

```bash
$ python LoRa_PHYDecode.py -h                                                                                                                                                                                1 ↵
usage: LoRa_PHYDecode.py [-h] [-p PORT] [-i IFACE]

Monitor and decode MAC PHY packets.

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  TAP PORT to listen on (default: UDP 40868)
  -i IFACE, --iface IFACE
                        Interface to monitor (default: local)
```

By default, the script can be run as follows to decode received LoRa frames:

```bash
$ sudo python LoRa_PHYDecode.py
<LoRa  Preamble=0x1 PHDR=0x631e PHDR_CRC=0x0 MType=Unconfirmed Data Up RFU=0 Major=0 DevAddr=[<DevAddrElem  NwkID=0xad NwkAddr=0x600015 |>] FCtrl=[<FCtrl_UpLink  ADR=0 ADRACKReq=0 ACK=0 ClassB=0 FOptsLen=0 |>] FCnt=0 FPort=2 DataPayload='i\x06D\x94\x97\x08\xce!\xd9' MIC=0x4b516899 CRC=0x96e1 |>
...
<LoRa  Preamble=0x1 PHDR=0x631e PHDR_CRC=0x0 MType=Unconfirmed Data Up RFU=0 Major=0 DevAddr=[<DevAddrElem  NwkID=0xad NwkAddr=0x600015 |>] FCtrl=[<FCtrl_UpLink  ADR=0 ADRACKReq=0 ACK=0 ClassB=0 FOptsLen=0 |>] FCnt=0 FPort=2 DataPayload='penthertz' MIC=0x20a5fcba CRC=0xcdc |>
<LoRa  Preamble=0x0 PHDR=0xd30c PHDR_CRC=0x0 MType=Confirmed Data Up RFU=0 Major=0 DevAddr=[<DevAddrElem  NwkID=0xad NwkAddr=0x600015 |>] FCtrl=[<FCtrl_UpLink  ADR=0 ADRACKReq=0 ACK=0 ClassB=0 FOptsLen=1 |>] FCnt=0 FOpts_up=[<MACCommand_up  CID=LinkCheckReq LinkCheck=[''] |>] FOpts_down=[<MACCommand_down  CID=222 |>] FPort=92 DataPayload='' MIC=0x31c753f |>
<LoRa  Preamble=0x0 PHDR=0xd30c PHDR_CRC=0x0 MType=Confirmed Data Up RFU=0 Major=0 DevAddr=[<DevAddrElem  NwkID=0xad NwkAddr=0x600015 |>] FCtrl=[<FCtrl_UpLink  ADR=0 ADRACKReq=0 ACK=0 ClassB=0 FOptsLen=1 |>] FCnt=0 FOpts_up=[<MACCommand_up  CID=LinkCheckReq LinkCheck=[''] |>] FOpts_down=[<MACCommand_down  CID=222 |>] FPort=92 DataPayload='' MIC=0x31c753f |
```

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

Few helpers have been implemented to calculate MIC field, encrypt and decrypt packet:

* `JoinAcceptPayload_decrypt`: decrypt Join-accept payloads;
* `JoinAcceptPayload_encrypt`: encrypt Join-accept payloads;
* `getPHY_CMAC`: compute MIC field of a packet using a provided key;
* `checkMIC`: check MIC of a packet against a provided key.

As an example, to check if the key `000102030405060708090A0B0C0D0E0F` is used to compute MIC on the following Join-request, we can write a little script as follows:

```python
>>> from layers.loraphy2wan import *
>>> from lutil.crypto import *
>>> key = "000102030405060708090A0B0C0D0E0F"
>>> p = '000000006c6f7665636166656d656565746f6f00696953024c49'
>>> pkt = LoRa(binascii.unhexlify(p))
>>> pkt
<LoRa  Preamble=0x0 PHDR=0x0 PHDR_CRC=0x0 MType=Join-request RFU=0 Major=0 Join_Request_Field=[<Join_Request  AppEUI='lovecafe' DevEUI='meeetoo' DevNonce=26985 |>] MIC=0x53024c49 |>
>>> checkMIC(binascii.unhexlify(key), str(pkt))
True
```

To check if `000102030405060708090A0B0C0D0E0F` key is used to encrypt a Join-accept message, we can combine `JoinAcceptPayload_decrypt` and `checkMIC` as follows:

```python
>>> pkt = "000000200836e287a9805cb7ee9e5fff7c9ee97a"
>>> ja = JoinAcceptPayload_decrypt(binascii.unhexlify(key), binascii.unhexlify(pkt))
>>> ja
'ghi#\x01\x00\xb2\\C\x03\x00\x00{\x06O\x8a'
>>> Join_Accept(ja)
<Join_Accept  JoinAppNonce=0x6fe14a NetID=0x10203 DevAddr=0x68e8cb1 OptNeg=0 RX1DRoffset=0x0 RX2_Data_rate=0x0 RxDelay=0x0 |<Padding  load='\xbejsu' |>>
>>> p = "\x00\x00\x00\x20"+ja # adding headers
>>> checkMIC(key.decode("hex"), p)
>>> True
```

## TODO

* More helpers for other types of payloads
* Implement helpers to transmit signal with dongles more easily
* Transmit packets with SDR
* Support gr-lora from Bastille: [link here](https://github.com/BastilleResearch/gr-lora)

Feel free to contribute if you have cool scripts/tools to share :)! 
