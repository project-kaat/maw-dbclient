#!/usr/bin/python3

class fieldExtractors:

    FLAGS_FIELD_VALUEMASK = {
            
            "CFP"               :       0b00000001,
            "SHORTPREAMBLE"     :       0b00000010,
            "WEP"               :       0b00000100,
            "FRAGMENTATION"     :       0b00001000,
            "FCS"               :       0b00010000,
            "DATAPAD"           :       0b00100000,
            "BADFCS"            :       0b01000000,
            "SHORTGI"           :       0b10000000,

    }

    def _bgFreqToChan(freq):

        if freq == 2484:
            return 14

        return int(((freq - 2412) / 5) + 1)

    def skipField(buffer, offset, dataSize, dataAlignment):
    
        if offset % dataAlignment != 0:
            offset += dataAlignment - (offset % dataAlignment)
    
        offset += dataSize

        return None, offset
    
    def ignoreField(buffer, offset):
    
        return None, offset
    
    def extractChannelField(buffer, offset):
    
        if offset % 2 != 0:
            offset += 1

        freq = int.from_bytes(buffer[offset:offset+2], "little")
        flags = int.from_bytes(buffer[offset+2:offset+4], "little")

        return fieldExtractors._bgFreqToChan(freq), offset+4
    
    def extractSignalField(buffer, offset):
    
        sig = buffer[offset]

        if sig > 100: #sign byte
            value = -int(sig - 100)
        else:
            value = sig

        return value, offset+1

    def extractTsft(buffer, offset):


        if offset % 8 != 0:

            offset += 8 - (offset % 8)

        timestamp = int.from_bytes(buffer[offset:offset+8], "little")

        return timestamp, offset+8

    def extractFlags(buffer, offset):

        flagByte = int(buffer[offset])

        retDict = {}

        for flag, mask in fieldExtractors.FLAGS_FIELD_VALUEMASK.items():
            retDict[flag] = (flagByte & mask) > 0

        return retDict, offset+1

class magic:

    """
    PRESENT_FIELDS = {
        FLAG                 : (maskValue, extractorCallback, *optionalArgsForCallback)
    }
    """
    PRESENT_FIELDS = {
        "TSFT"               : (0b00000000000000000000000000000001, fieldExtractors.extractTsft),
        "FLAGS"              : (0b00000000000000000000000000000010, fieldExtractors.extractFlags),
        "RATE"               : (0b00000000000000000000000000000100, fieldExtractors.skipField, (1, 1)),
        "CHAN"               : (0b00000000000000000000000000001000, fieldExtractors.extractChannelField),
        "FHSS"               : (0b00000000000000000000000000010000, fieldExtractors.skipField, (2, 1)),
        "DBMSIG"             : (0b00000000000000000000000000100000, fieldExtractors.extractSignalField),
        "DBMNOISE"           : (0b00000000000000000000000001000000, fieldExtractors.skipField, (1, 1)),
        "LCKQUALITY"         : (0b00000000000000000000000010000000, fieldExtractors.skipField, (2, 2)),
        "TXATTENUATION"      : (0b00000000000000000000000100000000, fieldExtractors.skipField, (2, 2)),
        "DBTXATTENUATION"    : (0b00000000000000000000001000000000, fieldExtractors.skipField, (2, 2)),
        "DBMTXPOWER"         : (0b00000000000000000000010000000000, fieldExtractors.skipField, (1, 1)),
        "ANTENNA"            : (0b00000000000000000000100000000000, fieldExtractors.skipField, (1, 1)),
        "DBSIG"              : (0b00000000000000000001000000000000, fieldExtractors.skipField, (1, 1)),
        "DBNOISE"            : (0b00000000000000000010000000000000, fieldExtractors.skipField, (1, 1)),
        "RXFLAGS"            : (0b00000000000000000100000000000000, fieldExtractors.skipField, (2 ,2)),
        "TXFLAGS"            : (0b00000000000000001000000000000000, fieldExtractors.skipField, (2, 2)),
        "DATARETRIES"        : (0b00000000000000100000000000000000, fieldExtractors.skipField, (1, 1)),
        "CHANPLUS"           : (0b00000000000001000000000000000000, fieldExtractors.skipField, (8, 4)),
        "MCS"                : (0b00000000000010000000000000000000, fieldExtractors.skipField, (3, 1)),
        "AMPDU"              : (0b00000000000100000000000000000000, fieldExtractors.skipField, (8, 4)),
        "VHT"                : (0b00000000001000000000000000000000, fieldExtractors.skipField, (12, 2)),
        "FRAMETIMESTAMP"     : (0b00000000010000000000000000000000, fieldExtractors.skipField, (12, 8)),
        "HE"                 : (0b00000000100000000000000000000000, fieldExtractors.skipField, (12, 2)),
        "HEMU"               : (0b00000001000000000000000000000000, fieldExtractors.skipField, (6, 2)),
        "PSDU"               : (0b00000100000000000000000000000000, fieldExtractors.skipField, (1, 1)),
        "LSIG"               : (0b00001000000000000000000000000000, fieldExtractors.skipField, (4, 2)),
        "TLVS"               : (0b00010000000000000000000000000000, fieldExtractors.ignoreField),
        "RADIOTAPNSNEXT"     : (0b00100000000000000000000000000000, fieldExtractors.ignoreField),
        "VENDORNSNEXT"       : (0b01000000000000000000000000000000, fieldExtractors.ignoreField),
        "EXT"                : (0b10000000000000000000000000000000, fieldExtractors.ignoreField),
    }


class radiotapHeader():

    def __init__(self, buffer):

        self.length = int.from_bytes(buffer[2:4], "little")

        self.body = buffer[0:self.length]

        self.present = self.getPresentWords()

        self.contents = self.parseWithPresentWords()

    def getPresentWords(self):

        curOffset = 4

        retList = list()

        while True:

            retList.append(int.from_bytes(self.body[curOffset:curOffset+4], "little"))
            if not self._isPresentFlagSet(retList[-1], magic.PRESENT_FIELDS["EXT"][0]):
                break
            else:
                curOffset += 4

        return retList

    def parseWithPresentWords(self):

        retDict = dict()

        curOffset = len(self.present) * 4 + 4
        buffer = self.body

        for word in self.present:
            
            for key, values in magic.PRESENT_FIELDS.items():
                if key == "EXT":
                    break
                if self._isPresentFlagSet(word, values[0]):

                    parserFunc = values[1]
                    if len(values) > 2: #optional args
                        res, newOffset = parserFunc(buffer, curOffset, *values[2])
                    else:
                        res, newOffset = parserFunc(buffer, curOffset)

                    retDict[key] = res
                    curOffset = newOffset

        return retDict


    def _isPresentFlagSet(self, presentWord, flagMask):

        return presentWord & flagMask
