#!/usr/bin/python3

from dataclasses import dataclass
import log

@dataclass
class finalAPEntry:

    bssid : str
    essid : list[str] = None
    channel : int = None
    wps : bool = False
    security : list[str] = None
    location : list[str] = None
    roaming : bool = False
    lastTimeSeen : int = None
    pmkid : str = None
    messagepair : list[str] = None

class export:

    def exportXML(filepath, aplist):

        log.info(f"Exporting to XML {filepath}")

        try:
            outFile = open(filepath, "wb")
        except Exception as e:
            log.error(f"Failed to open {filepath} for writing. ({e})")
            return

        import xml.etree.ElementTree as et

        root = et.Element('root')

        for ap in aplist.values():

            apElement = et.Element('network')
            apElement.attrib['bssid']=ap.bssid.hex()

            if len(ap.essid) > 0:
                essidRoot = et.SubElement(apElement, 'essids')

                for essid in ap.essid:

                    essidElement = et.SubElement(essidRoot, 'essid')
                    essidElement.text = essid

            if ap.channel is not None:
                chanElement = et.SubElement(apElement, 'channel')
                chanElement.text = str(ap.channel)

            if ap.wps is not None:

                apElement.attrib['wps']=str(ap.wps)

            if len(ap.security) > 0:

                secRoot = et.SubElement(apElement, 'securityOptions')

                for securityStr in ap.security:

                    secElement = et.SubElement(secRoot, 'security')
                    secElement.text = securityStr

            if len(ap.location) > 0:

                locationRoot = et.SubElement(apElement, 'locations')

                for loc in ap.location:

                    locElement = et.SubElement(locationRoot, 'location')
                    locElement.text = str(loc)

            if ap.lastTimeSeen is not None:

                ltsElement = et.SubElement(apElement, 'lastTimeSeen')
                ltsElement.text = str(ap.lastTimeSeen)

            if ap.isRoaming:

                apElement.attrib['roaming']=str(ap.isRoaming)

            if ap.pmkid is not None or len(ap.eapolMessagepairs) > 0:

                hashesRoot = et.SubElement(apElement, 'hashes')

                if ap.pmkid:
                    pmkidElement = et.SubElement(hashesRoot, 'pmkid')
                    pmkidElement.text = str(ap.pmkid)

                if len(ap.eapolMessagepairs) > 0:

                    pairsRoot = et.SubElement(hashesRoot, 'eapolMessagepairs')

                    for pair in ap.eapolMessagepairs:

                        pairElement = et.SubElement(pairsRoot, 'messagepair')
                        pairElement.text = str(pair)

            root.append(apElement)
        tree = et.ElementTree(root)

        tree.write(outFile)

        outFile.close()

    def exportCSV(outputFilepath, apList):
        log.info(f"Exporting to CSV ({filename})")
    
        try:
            outputCSV = open(filename, 'w')
        except Exception as e:
            log.error(f"Failed to open {filename} for writing. ({e})")
            return
        
        for ap in apEntryList.values():
            outputCSV.write(f"{converters.apEntryToCSV(ap)}\n")
        
        outputCSV.close()

class imprt:

    def importXML(inputFile):

        import xml.etree.ElementTree as et

        retList = list()

        tree = et.parse(inputFile)

        root = tree.getroot()

        for networkElement in root.findall("network"):

            fields = dict()

            fields['bssid'] = networkElement.get('bssid')
            if networkElement.find("essids"):
                fields['essid'] = list()
                for essid in networkElement.findall("essids/essid"):
                    fields['essid'].append(essid.text)
            if networkElement.findall("channel"):
                fields['channel'] = int(networkElement.findall("channel")[0].text)
            if networkElement.get('wps'):
                fields['wps'] = bool(networkElement.get('wps'))
            if networkElement.findall("securityOptions"):
                fields['security'] = list()
                for sec in networkElement.findall("securityOptions/security"):
                    fields['security'].append(sec.text)
            if networkElement.findall("locations"):
                fields['location'] = list()
                for loc in networkElement.findall("locations/location"):
                    fields['location'].append(loc.text)
            if networkElement.findall("lastTimeSeen"):
                fields['lastTimeSeen'] = int(networkElement.findall("lastTimeSeen")[0].text)
            if networkElement.findall("hashes/pmkid"):
                fields['pmkid'] = networkElement.findall("hashes/pmkid")[0].text
            if networkElement.findall("hashes/eapolMessagepairs"):
                fields['messagepair'] = list()
                for mp in networkElement.findall("hashes/eapolMessagepairs/messagepair"):
                    fields['messagepair'].append(mp.text)

            if networkElement.get('roaming'):
                fields['roaming'] = bool(networkElement.get('roaming'))

            retList.append(finalAPEntry(**fields))

            
        return retList

            
    def importCSV(inputFile):

        retList = list()
        
        try:
            inputCSV = open(inputFile, "r")
        except Exception as e:
            log.error(f"Failed to open {inputFile} for reading. ({e})")
            return

        for i in inputCSV.readlines():

            part = inputCSV.partition(",")
        inputCSV.close()

        return retList



class converters:

    def delimitBssid(bssid : str):

        try:
            bssid = bssid[0:2] + ':' + bssid[2:4] + ':' +bssid[4:6] + ':' +bssid[6:8] + ':' +bssid[8:10] + ':' +bssid[10:12]
        except:
            return None

        return bssid


    def listToCSVList(l : list):
    
        retList = "["
    
        if len(l) > 0:
            retList += f"'{l[0]}'"
    
        for item in l[1:]:
            retList += f",'{item}'"
    
        retList += "]"
    
        return retList
    
    def apEntryToCSV(entry : finalAPEntry):
    
        csvRow = f"{entry.bssid.hex()},"
    
        essidList = converters.listToCSVList(entry.essid)
    
        csvRow += f"{essidList},"
    
        if entry.channel is not None:
    
            csvRow += f"{entry.channel}"
    
        csvRow += ","
    
        if entry.wps is not None:
            csvRow += f"{entry.wps}"
    
        csvRow += ","
    
        securityList = converters.listToCSVList(entry.security)
    
        csvRow += f"{securityList},"
    
        locationList = converters.listToCSVList(entry.location)
    
        csvRow += f"{locationList},"
    
        if entry.lastTimeSeen is not None:
            csvRow += f"{entry.lastTimeSeen}"
    
        csvRow += ","
    
        if entry.isRoaming is not None:
            csvRow += f"{entry.isRoaming}"
    
        csvRow += ","
    
        if entry.pmkid is not None:
            csvRow += f"{entry.pmkid}"
    
        csvRow += ","
    
        eapolMPList = converters.listToCSVList(entry.eapolMessagepairs)
    
        csvRow += f"{eapolMPList},"
    
        return csvRow
