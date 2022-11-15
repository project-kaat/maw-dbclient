#!/usr/bin/python3

import sys
sys.path.append("../")

import argparse
import simplekml
from db import tryConnectDb
import log
from datetime import datetime
from location import strToLoc
import apEntry

argumentParser = argparse.ArgumentParser()
argumentParser.add_argument('db_address', metavar="DB", type=str, help="db connection address in form: user@host:port")
argumentParser.add_argument('output_file', metavar="OUTPUT", type=str, help="output kml file")
argumentParser.add_argument("--nopass", action="store_true", help="don't ask for the database password")
argumentParser.add_argument("--noroaming", action="store_true", help="don't put AP's that are marked as ROAMING into the output file")
argumentParser.add_argument("--noprotected", action="store_true", help="only output AP's that are either OPEN or have a password available in the database")

args = argumentParser.parse_args()

def addKmlExtIfNotPresent(path):

    if path[-4:] != ".kml":
        return path + ".kml"
    return path

def createAPDescription(bssid, essid, channel, security, wps, last_time_seen, roaming, cracked, password):

    friendlyBssid = apEntry.converters.delimitBssid(bssid.upper())
    retStr = f"bssid: {friendlyBssid}\n"

    if len(essid) > 0:
        for ssid in essid:
            retStr += f"essid: {ssid[0]}\n"

    if channel:
        retStr += f"channel: {channel}\n"

    if len(security) > 0:
        for sec in security:
            retStr += f"security: {sec[0]}\n"
    else:
        retStr += "security: OPEN\n"

    if last_time_seen:
        retStr += f"last_time_seen: {last_time_seen.__str__()}\n"

    retStr += f"wps: {wps}\n"
    
    if password:
        retStr += f"psk: {password[0]}\n"

    return retStr


outkml = simplekml.Kml()
outkml.document.name = f"MAW access points ({datetime.now().__str__()})"
if not args.noroaming:
    roamingFolder = outkml.document.newfolder(name="roaming")
if not args.noprotected:
    protectedFolder = outkml.document.newfolder(name="protected")
accessibleFolder = outkml.document.newfolder(name="accessible")
try:
    outkml.save(addKmlExtIfNotPresent(args.output_file))
except Exception as e:
    log.error(f"Failed to create output file {args.output_file}. ({e})")
    sys.exit(1)

dbConnection = tryConnectDb(args.db_address, args.nopass)

cur = dbConnection.cursor()

cur.execute("SELECT bssid, channel, last_time_seen, wps, roaming, cracked FROM network WHERE bssid IN (SELECT bssid FROM location)") #grab networks that have at least one location

aps = cur.fetchall()

for ap in aps:

    #fetch everything

    bssid = ap[0]
    channel = ap[1]
    last_time_seen = ap[2]
    wps = ap[3]
    roaming = ap[4]
    cracked = ap[5]
    
    if roaming and args.noroaming:
        continue

    cur.execute(f"SELECT value FROM location JOIN network ON network.bssid=location.bssid WHERE network.bssid='{bssid}'")
    locStrings = cur.fetchall()

    if len(locStrings) < 1:
        #nothing to put on the map
        #also shouldn't occur
        log.warning(f"No location data for bssid {bssid}. (even though database said there was)")
        continue

    location = []

    for s in locStrings:
        location.append(strToLoc(s[0]))
    
    cur.execute(f"SELECT value FROM security JOIN security_network_link ON security_network_link.security_id = security.id JOIN network ON security_network_link.bssid = network.bssid WHERE network.bssid='{bssid}'")
    security = cur.fetchall()

    if args.noprotected and not cracked and len(security)>0:
        continue

    cur.execute(f"SELECT value FROM essid JOIN network ON network.bssid=essid.bssid WHERE network.bssid='{bssid}'")
    essid = cur.fetchall()
    if len(essid) > 1:
        log.info(f"{bssid} has multiple essids")

    password = None
    if cracked:
        cur.execute(f"SELECT value FROM password JOIN network ON network.bssid = password.bssid WHERE network.bssid='{bssid}'")
        password = cur.fetchall()

    #add a point to the map
    
    if len(essid) < 1:
        friendlyName = bssid
    else:
        friendlyName = essid[0][0]
    description = createAPDescription(bssid, essid, channel, security, wps, last_time_seen, roaming, cracked, password)
    if roaming:
        for loc in location:
            roamingFolder.newpoint(name=friendlyName, description=description, coords=[(loc.long, loc.lat)])
            log.info(f"added a roaming point for {bssid}")

    elif not cracked and len(security) > 0:
        protectedFolder.newpoint(name=friendlyName, description=description, coords=[(location[0].long, location[0].lat)])
        log.info(f"added a protected point for {bssid}")
    else:
        accessibleFolder.newpoint(name=friendlyName, description=description, coords=[(location[0].long, location[0].lat)])
        log.info(f"added an accessible point for {bssid}")

try:
    outkml.save(addKmlExtIfNotPresent(args.output_file))
except Exception as e:
    log.error(f"Failed to write to file {args.output_file}. ({e})")
    sys.exit(1)
