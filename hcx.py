#!/usr/bin/python3

from dataclasses import dataclass

@dataclass
class hcxPMKIDHash:

    pmkid : bytearray
    mac_ap : bytearray
    mac_client : bytearray
    essid : str

    def __repr__(self):

        return f"WPA*01*{self.pmkid.hex()}*{self.mac_ap.hex()}*{self.mac_client.hex()}*{self.essid.encode().hex()}***"

@dataclass
class hcxMessagepairHash:

    mic : bytearray
    mac_ap : bytearray
    mac_client : bytearray
    essid : str
    nonce_ap : bytearray
    eapol_client : bytearray
    messagepair : bytes

    def __repr__(self):

        return f"WPA*02*{self.mic.hex()}*{self.mac_ap.hex()}*{self.mac_client.hex()}*{self.essid.encode().hex()}*{self.nonce_ap.hex()}*{self.eapol_client.hex()}*{self.messagepair.hex()}"

def parseHashline(hashline):

    try:
        split = hashline.split('*')
        
        sig = split[0]
        lineType = int(split[1])
    except:
        return None

    if sig != "WPA":
        return None
    if lineType == 1:
        
        pmkid = bytes.fromhex(split[2])
        mac_ap = bytes.fromhex(split[3])
        mac_client = bytes.fromhex(split[4])
        essid = bytes.fromhex(split[5]).decode()

        return hcxPMKIDHash(pmkid, mac_ap, mac_client, essid)
    elif lineType == 2:

        mic = bytes.fromhex(split[2])
        mac_ap = bytes.fromhex(split[3])
        mac_client = bytes.fromhex(split[4])
        essid = bytes.fromhex(split[5]).decode()
        nonce_ap = bytes.fromhex(split[6])
        eapol_client = bytes.fromhex(split[7])
        messagepair = bytes.fromhex(split[8])

        return hcxMessagepairHash(mic, mac_ap, mac_client, essid, nonce_ap, eapol_client, messagepair)
        
    else:
        print(f"Unsupported hashline format : {sig}*{lineType}")
        print("This parser only supports hashcat 22000 format")
        raise TypeError
