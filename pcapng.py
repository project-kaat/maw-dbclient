#!/usr/bin/python3

class magic:

    BLOCK_TYPE_SECTION_HEADER=0x0a0d0d0a
    BLOCK_TYPE_INTERFACE_DESCRIPTION=0x00000001
    BLOCK_TYPE_SIMPLE_PACKET=0x000000003
    BLOCK_TYPE_NAME_RESOLUTION=0x00000004
    BLOCK_TYPE_INTERFACE_STATISTICS=0x00000005
    BLOCK_TYPE_ENHANCED_PACKET=0x00000006

    BLOCK_TYPE_CUSTOM_PRIMARY=0x00000bad
    BLOCK_TYPE_CUSTOM_SECONDARY=0x40000bad



class block:

    def __init__(self, blockType, blockBody):

        self.type = blockType
        self.body = blockBody

class sectionHeaderBlock(block):

    def __init__(self, blockType, blockBody):

        super().__init__(blockType, blockBody)

        self.byteOrderMagic = self.body[:4]
        self.majorVersion = int.from_bytes(self.body[4:6], "little")
        self.minorVersion = int.from_bytes(self.body[6:8], "little")
        self.sectionLength = int.from_bytes(self.body[8:16], "little")

        #if self.sectionLength % 4 != 0:
        #    raise ValueError

        self.contents = self.body[16:] 

class interfaceDescriptionBlock(block):

    def __init__(self, blockType, blockBody):

        super().__init__(blockType, blockBody)

        self.linkType = int.from_bytes(self.body[:2], "little")
        self.reserved = self.body[2:4]
        self.snapLen = int.from_bytes(self.body[4:8], "little")

class enhancedPacketBlock(block):

    def __init__(self, blockType, blockBody):

        super().__init__(blockType, blockBody)

        self.interfaceId = int.from_bytes(self.body[:4], "little")
        self.timestampHigh = int.from_bytes(self.body[4:8], "little")
        self.timestampLow = int.from_bytes(self.body[8:12], "little")
        self.timestamp = (self.timestampHigh << 32) + self.timestampLow
        self.capturedLength = int.from_bytes(self.body[12:16], "little")
        self.originalLength = int.from_bytes(self.body[16:20], "little")
        self.contents = self.body[20:20+self.capturedLength] #trailing (padding) null-bytes are not included

class customBlock(block):

    def __init__(self, blockType, blockBody):

        super().__init__(blockType, blockBody)

        self.privateEnterpriseNumber = int.from_bytes(self.body[:4], "little")
        self.customData = self.body[4:]

class pcapngFile():

    def __init__(self, fname, scanIntoMemory=False):

        self.filestream = open(fname, "rb")

        if scanIntoMemory:

            self.contents = list()

            fileEnded = False
            while not fileEnded:
                nb = self.nextBlock()
                if nb == None:
                    fileEnded = True
                else:
                    self.contents.append(nb)


    def nextBlock(self):


        blockType = int.from_bytes(self.filestream.read(4), "little")
        blockSize = int.from_bytes(self.filestream.read(4), "little")

        if blockType == 0 or blockSize == 0:
            return None #end of file
        
        if blockSize % 4 != 0 or blockSize < 12:
        
            raise ValueError
        
        blockBody = self.filestream.read(blockSize - 8) #block type field and first block size field are stripped
        
        if int.from_bytes(blockBody[-4:], "little") != blockSize:
        
            raise ValueError

        blockBody[:-4] #trailing block size field is stripped

        if blockType == magic.BLOCK_TYPE_SECTION_HEADER:
            return sectionHeaderBlock(blockType, blockBody)
        elif blockType == magic.BLOCK_TYPE_INTERFACE_DESCRIPTION:
            return interfaceDescriptionBlock(blockType, blockBody)
        elif blockType == magic.BLOCK_TYPE_ENHANCED_PACKET:
            return enhancedPacketBlock(blockType, blockBody)
        elif blockType == magic.BLOCK_TYPE_CUSTOM_PRIMARY or blockType == magic.BLOCK_TYPE_CUSTOM_SECONDARY:
            return customBlock(blockType, blockBody)
        else:
            print(f"Unhandled block type: {hex(blockType)}")
            return block(blockType, blockBody)
