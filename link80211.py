#!/usr/bin/python3

from dataclasses import dataclass

class managementParameterExtractors:

    def ssidExtractor(buffer):

        try:
            return buffer.decode()
        except UnicodeError:
            return None

    def channelExtractor(buffer):

        return int(buffer[0])

    def rsnExtractor(buffer):

        offset = 0
        
        version = int.from_bytes(buffer[offset:2], "little")
        offset += 2

        try:
            groupCipherSuite = magic.RSN_CIPHER_SUITES[int(buffer[offset + 3])]
        except KeyError:
            groupCipherSuite = "Unknown Group Cipher Suite"

        offset += 4
        pairwiseCipherCount = int.from_bytes(buffer[offset:offset+2], "little")
        offset += 2
        #pairwise is pretty much useless to know
        #pairwiseCipherSuiteList = list() 
        for _ in range(pairwiseCipherCount):
            #try:
            #    pairwiseCipherSuite = magic.RSN_CIPHER_SUITES[int(buffer[offset + 3])]
            #except KeyError:
            #    pairwiseCipherSuite = "Unknown"
            #if pairwiseCipherSuite == "Same as Group":
            #    pairwiseCipherSuite = groupCipherSuite
            #pairwiseCipherSuiteList.append(pairwiseCipherSuite)
            offset += 4

        authKeyManagementCount = int.from_bytes(buffer[offset:offset+2], "little")
        offset += 2
        authKeyManagementList = list()

        for _ in range(authKeyManagementCount):
            try:
                authKeyManagementType = magic.RSN_KEY_MANAGEMENT_TYPES[int(buffer[offset+3])]
            except KeyError:
                authKeyManagementType = "Unknown"
            authKeyManagementList.append(authKeyManagementType)
            offset += 4

        return f"WPA2-{authKeyManagementList[0]} ({groupCipherSuite})"
        
    def wpsExtractor(buffer):

        offset = 0

        while offset < len(buffer):

            nextTagId = int.from_bytes(buffer[offset:offset+2], "big")
            offset += 2
            nextTagLen = int.from_bytes(buffer[offset:offset+2], "big")
            offset += 2

            if nextTagId in magic.WPS_IE_TAGS:

                if magic.WPS_IE_TAGS[nextTagId] == "State":

                    stateValue = int.from_bytes(buffer[offset:offset+nextTagLen], "big")

                    if stateValue == 0x2:
                        return True
            offset += nextTagLen

        return False

    def wpaExtractor(buffer):

        return managementParameterExtractors.rsnExtractor(buffer).replace("WPA2", "WPA")

    def vendorSpecificExtractor(buffer):

        oui = buffer[:3]
        tagId = buffer[3]

        if oui == magic.OUI_MICROSOFT:

            try:
                return  magic.MANAGEMENT_MICROSOFT_PARAMS_MAPPINGS[tagId][0], magic.MANAGEMENT_MICROSOFT_PARAMS_MAPPINGS[tagId][1](buffer[4:])
            except KeyError:
                return None, None
            
        else:
            return None, None

class magic:

    OUI_MICROSOFT = b"\x00\x50\xf2"
    
    FRAMECTRL_TYPE_MAPPINGS = {
            0 : "Management",
            1 : "Control",
            2 : "Data",
    }

    FRAMECTRL_MANAGEMENT_SUBTYPE_MAPPINGS = {
            0 : "Association Request",
            1 : "Association Response",
            2 : "Reassociation Request",
            3 : "Reassociation Response",
            4 : "Probe Request",
            5 : "Probe Response",
            6 : "Timing Advertisement",
            8 : "Beacon",
            9 : "ATIM",
            10 : "Disassociation",
            11 : "Authentication",
            12 : "Deauthentication",
            13 : "Action",
            15 : "NACK",
    }

    FRAMECTRL_DATA_SUBTYPE_MAPPINGS = {
            0 : "Data",
            4 : "Null",
            8 : "QoS Data",
            9 : "QoS Data + CF-ACK",
            10 : "QoS Data + CF-ACK + CF-Poll",
            12 : "QoS Null",
    }

    MANAGEMENT_FIXED_PARAMS_LEN = {
            "Beacon"                    : 12,
            "Probe Response"            : 12,
            "Authentication"            : 6,
            "Association Response"      : 6,
            "Probe Request"             : 0,
            "Association Request"       : 4,
            "Reassociation Request"     : 10,
            "Reassociation Response"    : 6,
            "ATIM"                      : 0,
            "Disassociation"            : 2,
    }

    MANAGEMENT_TAGGED_PARAMS_MAPPINGS = { #only interesting
            0   : ("SSID", managementParameterExtractors.ssidExtractor),
            3   : ("DS Parameter Set", managementParameterExtractors.channelExtractor),
            48  : ("RSN", managementParameterExtractors.rsnExtractor),
            221 : ("Vendor-specific", managementParameterExtractors.vendorSpecificExtractor),
    }

    MANAGEMENT_MICROSOFT_PARAMS_MAPPINGS = {

            1   : ("WPA", managementParameterExtractors.wpaExtractor),   
            4   : ("WPS", managementParameterExtractors.wpsExtractor),

    }

    RSN_CIPHER_SUITES = {

            0 : "Same as Group",
            1 : "WEP-40",
            2 : "TKIP",
            4 : "AES (CCMP)",
            5 : "WEP-104",

    }

    RSN_KEY_MANAGEMENT_TYPES = {

            1 : "PMK",
            2 : "PSK",
    }

    WPS_IE_TAGS = {
        
            0x1044 : "State",
    }



@dataclass
class frameCtrl:

    frameVersion    : int
    frameType       : str
    frameSubtype    : str
    toDS            : bool
    fromDS          : bool

@dataclass
class frameManagementBody:

    fixedParams     : bytearray
    taggedParams    : dict

def bytesToFrameCtl(b):

    important = b[0]

    flags = b[1]

    toDS = flags & 0b00000001
    fromDS = (flags & 0b00000010) >> 1

    version = important & 0b00000011
    frameType = magic.FRAMECTRL_TYPE_MAPPINGS[(important & 0b00001100) >> 2]
    try:
        if frameType == "Management":
            frameSubtype = magic.FRAMECTRL_MANAGEMENT_SUBTYPE_MAPPINGS[(important & 0b11110000) >> 4]

        elif frameType == "Data":
            frameSubtype = magic.FRAMECTRL_DATA_SUBTYPE_MAPPINGS[(important & 0b11110000) >> 4]
        else:
            raise ValueError
    except KeyError:
        print(f"Frame subtype : {(important & 0b11110000) >> 4} is not supported by the library")
        raise ValueError

    return frameCtrl(version, frameType, frameSubtype, toDS, fromDS)

class frame():

    def __init__(self, buffer, hasFCS):
        
        self.frameCtrl = bytesToFrameCtl(buffer[0:2])

        self.duration = int.from_bytes(buffer[2:4], "big")
        self.macs = list()
        self.macs.append(buffer[4:10])
        self.macs.append(buffer[10:16])
        self.macs.append(buffer[16:22])

        #22:24 - sequence control
        #(QoS data frames only) 24:26 - qos
        #(if fcs is present) :-4 FCS

        self.srcAddress, self.dstAddress, self.bssid = self.parseMacs()

        if self.frameCtrl.frameSubtype == "QoS Data":
            bodyStartOffset = 26
        else:
            bodyStartOffset = 24

        if hasFCS:
            self.body = buffer[bodyStartOffset:-4]
        else:
            self.body = buffer[bodyStartOffset:]

        if self.frameCtrl.frameType == "Management":

            self.contents = self.parseManagementBody()

    def parseMacs(self):

        if not self.frameCtrl.toDS and not self.frameCtrl.fromDS:
            return self.macs[1], self.macs[0], self.macs[2]
        elif self.frameCtrl.toDS and not self.frameCtrl.fromDS:
            return self.macs[1], self.macs[2], self.macs[0]
        elif not self.frameCtrl.toDS and self.frameCtrl.fromDS:
            return self.macs[2], self.macs[0], self.macs[1]
        else:
            print("WDS function is not supported by the library")
            return None, None, None

    def parseManagementBody(self):

        fixedParamsLen = magic.MANAGEMENT_FIXED_PARAMS_LEN[self.frameCtrl.frameSubtype]

        fixedParams = self.body[:fixedParamsLen]

        nextParamOffset = fixedParamsLen

        taggedParams = {}

        while nextParamOffset < len(self.body):
            tagId = int(self.body[nextParamOffset])
            tagLen = int(self.body[nextParamOffset+1])

            if tagId in magic.MANAGEMENT_TAGGED_PARAMS_MAPPINGS:

                if tagId == 221:

                    vendorTagId, vendorTagvalue = magic.MANAGEMENT_TAGGED_PARAMS_MAPPINGS[tagId][1](self.body[nextParamOffset+2:nextParamOffset+2+tagLen])

                    if vendorTagvalue:
                        taggedParams[vendorTagId] = vendorTagvalue

                else:
                    value = magic.MANAGEMENT_TAGGED_PARAMS_MAPPINGS[tagId][1](self.body[nextParamOffset+2:nextParamOffset+2+tagLen])
                    if value:
                        taggedParams[magic.MANAGEMENT_TAGGED_PARAMS_MAPPINGS[tagId][0]] = value

            nextParamOffset += tagLen + 2

        return frameManagementBody(fixedParams, taggedParams)
