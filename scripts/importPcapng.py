#!/usr/bin/python3
import sys

sys.path.append("../")

import pcapng
import radiotap
import link80211
import log
import nmea
import hcx
import location
from apEntry import export

from dataclasses  import dataclass
from time import gmtime
from subprocess import Popen, DEVNULL
from os import remove, path
import argparse

argumentParser = argparse.ArgumentParser()
argumentParser.add_argument('input_file', metavar="INPUT", type=str, help=".pcapng file(s) to process", nargs="+")
argumentParser.add_argument('-o', "--output", metavar="output_filename", type=str)
argumentParser.add_argument("--csv", action="store_true", help="output the result in csv")
argumentParser.add_argument("--xml", action="store_true", help="output the result in xml")
argumentParser.add_argument("-v", "--verbosity", type=int, metavar="VERBOSITY", help="set verbosity (0=quiet, 1=error, 2=warning, 3=info(default), 4=debug)")
argumentParser.add_argument("--nohash", action="store_true", help="do not attempt to process password hashes")
argumentParser.add_argument("--nolocation", action="store_true", help="do not attempt to process embedded location messages")
argumentParser.add_argument("--utcOffset", type=int, metavar="UTC_OFFSET", help="add N (-N is possible too) hours to !PCAPNG ENHANCED PACKET! timestamps (useful if location and capture packets use different timezones)")

args = argumentParser.parse_args()


@dataclass
class tmpAPEntry:

    bssid : bytearray
    essid : list[str] = None
    channel : int = None
    wps : bool = False
    security : list[str] = None
    location : list[str] = None
    lastTimeSeen : float = None
    isRoaming : bool = False
    pmkid : hcx.hcxPMKIDHash = None
    eapolMessagepairs : list[hcx.hcxMessagepairHash] = None

@dataclass
class wlanPacket:

    timestamp : int
    radiotapHeader : radiotap.radiotapHeader
    link80211Frame : link80211.frame

HCXDUMPTOOL_GPS_PEN = 2705772074

LOCATION_RELATION_TIME_WINDOW = 1 #(*2+1)seconds
LOCATION_DEVIATION_THRESHOLD = 200 #metres

tmpAPList = dict()

try:
    if args.verbosity:
        log.setLogLevel(args.verbosity)
except ValueError:
    log.error(f"Invalid verbosity value: {args.verbosity}")
    log.info(f"Falling back to default loglevel ({log.LOGLEVEL_DEFAULT})")

def processFile(file):
    pcapScanner = pcapng.pcapngFile(file)
    
    locations = list()
    packetBlocks = list()
    
    try:
        nb = pcapScanner.nextBlock()
    except ValueError:
        log.error(f"Failed to parse {file}. Possibly not a valid pcapng.")
        sys.exit(1)
    
    
    log.info(f"Started to process PCAPNG  ({file})")
    
    while nb != None:
    
        if not args.nolocation and isinstance(nb, pcapng.customBlock) and nb.privateEnterpriseNumber == HCXDUMPTOOL_GPS_PEN:
            sentenceType = nmea.getSentenceType(nb.customData)
            if sentenceType == "RMC":
                loc = nmea.parseNmeaRMCSentence(nb.customData)
                if loc:
                    locations.append(loc)
                else:
                    log.warning("Failed to interpret nmea RMC sentence. Skipping")
            elif sentenceType == None:
                log.warning("Failed to parse custom pcapng block as nmea sentence. Skipping")
        elif isinstance(nb, pcapng.enhancedPacketBlock):
            if args.utcOffset:
                nb.timestamp = nb.timestamp + (args.utcOffset * 3600000000)
            packetBlocks.append(nb) #for later sorting into AP_INFO and AP_AUTH packets
        #else discard
    
        try:
            nb = pcapScanner.nextBlock()
        except ValueError:
            log.error(f"Failed to parse {file} midway through the file. Possibly a parser error or an invalid pcapng file")
            sys.exit(1)
    
    managementPackets = list()
    
    """
    managementPackets = [ 
        (radiotap, 802.11)
    ]
    """
    
    log.info("Parsing the frames")
    
    for packet in packetBlocks:
    
        timestamp = round(packet.timestamp / 1000000)
    
        try:
            rh = radiotap.radiotapHeader(packet.contents)

            l80211 = link80211.frame(packet.contents[rh.length:], rh.contents["FLAGS"]["FCS"]) #<- need to know if FCS is present to parse 802.11 frame correctly
        except ValueError:
            continue

        if l80211.frameCtrl.frameType == "Management":
    
            if l80211.frameCtrl.frameSubtype == "Probe Request":
                #ignore Probe requests (sent by clients that are looking for specific essid's)
                continue
    
            managementPackets.append(wlanPacket(timestamp, rh, l80211))
    
    log.info("Creating temporary AP entries")
    
    for packet in managementPackets:
    
        signalFlag = False #if this packet's signal value is the strongest so far, location values will be prioritized
    
        bssid = packet.link80211Frame.bssid
    
        if bssid not in tmpAPList:
            #create new entry
            tmpAPList[bssid] = tmpAPEntry(bssid, lastTimeSeen = packet.timestamp)
            tmpAPList[bssid].essid = list()
            tmpAPList[bssid].security = list()
            tmpAPList[bssid].location = list()
            tmpAPList[bssid].eapolMessagepairs = list()
    
        #update values if necessary
    
        if "SSID" in packet.link80211Frame.contents.taggedParams:
            ssid = packet.link80211Frame.contents.taggedParams["SSID"]
            if len(ssid) < 1 or "\x00" in ssid:
                ssid = "NO_ESSID"
            if ssid not in tmpAPList[bssid].essid:
                tmpAPList[bssid].essid.append(ssid)
                if not tmpAPList[bssid].isRoaming and len(tmpAPList[bssid].essid) > 1 and "\x00" not in tmpAPList[bssid].essid:
                    #roaming detected
                    log.info(f"Station {bssid.hex()} ({ssid}) appears to be roaming")
                    tmpAPList[bssid].isRoaming = True
    
        if "WPS" in packet.link80211Frame.contents.taggedParams:
    
                wps = packet.link80211Frame.contents.taggedParams["WPS"]
                tmpAPList[bssid].wps = wps
    
        if "RSN" in packet.link80211Frame.contents.taggedParams:
    
            if packet.link80211Frame.contents.taggedParams["RSN"] not in tmpAPList[bssid].security:
    
                tmpAPList[bssid].security.append(packet.link80211Frame.contents.taggedParams["RSN"])
    
        if "WPA" in packet.link80211Frame.contents.taggedParams:
    
            if packet.link80211Frame.contents.taggedParams["WPA"] not in tmpAPList[bssid].security:
                tmpAPList[bssid].security.append(packet.link80211Frame.contents.taggedParams["WPA"])
    
        if "DS Parameter Set" in packet.link80211Frame.contents.taggedParams:
    
            tmpAPList[bssid].channel = packet.link80211Frame.contents.taggedParams["DS Parameter Set"]
    
        if packet.timestamp > tmpAPList[bssid].lastTimeSeen:
            tmpAPList[bssid].lastTimeSeen = packet.timestamp
    
        #find related location
    
        if not args.nolocation:
            """
            tmpAPEntry.location = [
                { SIG : (location),
                  SIG2 : (location),
                } <- for every unique location pool
            ] this whole dictionary will be averaged together with signal strength values as weights during the dedicated location pass for each ap
            """
            relatedLocations = list()

            #step 1: find all locations related to this frame by comparing timestamps
            for loc in locations:
    
                if abs(packet.timestamp - loc.timestamp) <= LOCATION_RELATION_TIME_WINDOW:
                    relatedLocations.append(loc)

            log.debug(f"found {len(relatedLocations)} location candidates for ap {bssid}")

            #step 2: sort unique locations into pools
            for loc in relatedLocations:

                uniquePool=True
                poolIndex=-1
                for pool in tmpAPList[bssid].location:
                    poolIndex+=1
                    
                    notFromThisPool=False
                    poolLocations = list()
                    for i in pool.values():
                        poolLocations.extend(i)
                    for oldLocation in poolLocations:
                        if location.distanceMetres(oldLocation, loc) >= LOCATION_DEVIATION_THRESHOLD:
                            notFromThisPool=True
                            break
                    if notFromThisPool:
                        continue
                    else:
                        uniquePool=False
                        targetPoolIndex=poolIndex
                        break
                if uniquePool:
                    #create pool
                    tmpAPList[bssid].location.append({"NOSIG" : list()})
                    targetPoolIndex=-1                             
                #insert into pool
                if "DBMSIG" in packet.radiotapHeader.contents:
                    sig = packet.radiotapHeader.contents['DBMSIG']
                    if sig not in tmpAPList[bssid].location[targetPoolIndex]:
                        tmpAPList[bssid].location[targetPoolIndex][sig] = list()
                    tmpAPList[bssid].location[targetPoolIndex][sig].append(loc)
                else:
                    tmpAPList[bssid].location[targetPoolIndex]["NOSIG"].append(loc)

            log.debug(f"{bssid} has {len(tmpAPList[bssid].location)} unique location pools")


    
                #                if len(tmpAPList[bssid].location) == 0:
                #                    tmpAPList[bssid].location.append(loc)
                #    
                #                else:
                #    
                #                    if loc not in tmpAPList[bssid].location:
                #                        mightBeUnique = True
                #    
                #                        for oldLoc in tmpAPList[bssid].location:
                #    
                #                            if location.distanceMetres(oldLoc, loc) <= LOCATION_DEVIATION_THRESHOLD:
                #                                mightBeUnique = False
                #                                break
                #                        if mightBeUnique:
                #                            log.info(f"Station {bssid} appears to be roaming")
                #                            tmpAPList[bssid].isRoaming = True
                #                            tmpAPList[bssid].location.append(loc)
                #    
                #                        #if not unique and not roaming...
                #                        elif not tmpAPList[bssid].isRoaming:
                #                            if signalFlag: #take new location if signal is stronger
                #                                tmpAPList[bssid].location[0] = loc
                #                            else: #or average with the old one if signal is weaker
                #                                newloc = location.averageLocations(tmpAPList[bssid].location[0], loc)
                #                                tmpAPList[bssid].location[0] = newloc
    
    if not args.nohash:
        log.info("Processing captured hashes")
        
        hashFilePath = f"/tmp/{file}.22000"
        if path.isfile(hashFilePath):
            remove(hashFilePath)
        
        Popen(("hcxpcapngtool", file, "-o", hashFilePath), stdout=DEVNULL).wait()
        
        hashes = list()
        
        try:
            hashFile = open(hashFilePath, "r") 
        except Exception as e:
            log.error(f"Failed to open the hashfile. ({e})")
            sys.exit(1)
        hashLines = hashFile.readlines()
        
        for hashLine in hashLines:
        
            h = hcx.parseHashline(hashLine)
            if h is not None:
                hashes.append(h)
        
        hashFile.close()
        
        if path.isfile(hashFilePath):
            remove(hashFilePath)
        
        for h in hashes:
        
            if h.mac_ap not in tmpAPList:
                log.warning("Captured hash is for an unknown AP")
                log.info(f"Creating an entry for AP {h.essid}")
                tmpAPList[h.mac_ap] = tmpAPEntry(h.mac_ap, essid.append(h.essid))
        
            if isinstance(h, hcx.hcxPMKIDHash):
                tmpAPList[h.mac_ap].pmkid = h
            elif isinstance(h, hcx.hcxMessagepairHash):
                tmpAPList[h.mac_ap].eapolMessagepairs.append(h) 
        
            if len(tmpAPList[h.mac_ap].eapolMessagepairs) > 1:
                log.info(f"Station {tmpAPList[h.mac_ap].essid} has multiple eapol pairs")

for f in args.input_file:
    processFile(f)

#location pass 
if not args.nolocation:

    log.info("Approximating locations")

    for ap in tmpAPList.values():

        if len(ap.location):

            log.debug(f"averaging locations for {ap.bssid}")

            weightedUniqueLocations = list()
            for pool in ap.location:
                log.debug(f"working on {pool}")
                weightedLocation = location.averageLocationPool(pool)
                log.debug(f"weighted is {weightedLocation}")
                if weightedLocation is not None:
                    weightedUniqueLocations.append(weightedLocation)
                else:
                    log.warning(f"Failed to calculate weighted average of location values for ap {ap.bssid}")
            tmpAPList[ap.bssid].location = weightedUniqueLocations

#export stage

shouldExport = args.csv or args.xml
if shouldExport:

    if not args.output:
        fallbackFilepath = args.input_file.removesuffix(".pcapng")
        log.warning(f"Export filename was not specified. Will use {fallbackFilepath}")

        exportPrefix = fallbackFilepath
    else:
        exportPrefix = args.output

    if args.csv:
        export.exportCSV(f"{exportPrefix}.csv", tmpAPList)
    if args.xml:
        export.exportXML(f"{exportPrefix}.xml", tmpAPList)
else:
    log.warning("No export format specified. Skipping export stage")
