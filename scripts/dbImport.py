#!/usr/bin/python3

import sys
sys.path.append("../")

import argparse
import mimetypes
import log
from apEntry import imprt, finalAPEntry
from time import mktime
from datetime import datetime
from location import location, distanceMetres, strToLoc, averageLocations
from db import tryConnectDb, sanitizeString

LOCATION_DEVIATION_THRESHOLD=200

argumentParser = argparse.ArgumentParser()
argumentParser.add_argument('input_file', metavar="INPUT", type=str, help="supported file format to import into db")
argumentParser.add_argument('db_address', metavar="DB", type=str, help="db connection address in form: user@host:port")
argumentParser.add_argument("--csv", action="store_true", help="force interpret INPUT as csv")
argumentParser.add_argument("--xml", action="store_true", help="force interpret INPUT as xml")
argumentParser.add_argument("--nopass", action="store_true", help="don't ask for the database password")

args = argumentParser.parse_args()

FILETYPE_TO_PARSER_MAPPINGS = {
        "csv" : imprt.importCSV,
        "xml" : imprt.importXML,
}

def sanitizeString(string):

    counter = 0
    for c in string:
        if c == '\'' or c == '\"':
            string = string[:counter] + '\\' + string[counter:]
        counter += 1

    return string

def updateRoaming(cursor, bssid, value):

    cursor.execute(f"UPDATE network SET roaming={str(value).upper()} WHERE bssid = '{bssid}'")

def updateChannel(cursor, bssid, value):

    cursor.execute(f"UPDATE network SET channel={value} WHERE bssid = '{bssid}'")

def updateWps(cursor, bssid, value):

    cursor.execute(f"UPDATE network SET wps={str(value).upper()} WHERE bssid = '{bssid}'")

def updateLastTimeSeen(cursor, bssid, value):

    dateTimeString = (datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S"))
    cursor.execute(f"UPDATE network SET last_time_seen='{dateTimeString}' WHERE bssid = '{bssid}'")

def updateLocation(locationId, newLocationValue):

    cursor.execute(f"UPDATE location SET value={'newLocationValue'} WHERE id = {locationId}")

def addPmkid(cursor, bssid, value):

    cursor.execute(f"INSERT INTO pmkid (value,bssid) VALUES('{value}','{bssid}')")

def addEssid(cursor, bssid, value):

    value = sanitizeString(value)
    cursor.execute(f"INSERT INTO essid (value,bssid) VALUES('{value}','{bssid}')")

def addLocation(cursor, bssid, value):

    cursor.execute(f"INSERT INTO location (value,bssid) VALUES('{value}','{bssid}')")

def addMessagepair(cursor, bssid, value):

    cursor.execute(f"INSERT INTO messagepair (value,bssid) VALUES('{value}','{bssid}')")

def addSecurity(cursor, bssid, value):

    cursor.execute(f"SELECT id FROM security WHERE value = '{value}'")
    if cursor.rowcount == 0:
        cursor.execute(f"INSERT INTO security (value) VALUES('{value}')")
        cursor.execute(f"SELECT id FROM security WHERE value = '{value}'")

    secId = cursor.fetchone()[0]

    cursor.execute(f"INSERT INTO security_network_link (bssid, security_id) VALUES('{ap.bssid}', {secId})")

def addNetwork(cursor, bssid):

    cursor.execute(f"INSERT INTO network (bssid) VALUES('{bssid}')")

def networkUpdateProcess(ap, cursor):

    cursor.execute(f"SELECT bssid, channel, wps, last_time_seen, roaming FROM network WHERE bssid = '{ap.bssid}'")
            
    bssid, chan, wps, lastTimeSeen, roaming = cursor.fetchone()

    if ap.channel is not None and chan != ap.channel:
        updateChannel(cursor, ap.bssid, ap.channel)
    if ap.wps is not None and wps != ap.wps:
        updateWps(cursor, ap.bssid, ap.wps)
    if ap.lastTimeSeen is not None:
        if lastTimeSeen is None or mktime(lastTimeSeen.timetuple()) < ap.lastTimeSeen:
            updateLastTimeSeen(cursor, ap.bssid, ap.lastTimeSeen)

    if ap.essid is not None and len(ap.essid) > 0:
        cursor.execute(f"SELECT value FROM essid WHERE bssid='{ap.bssid}'")
        essidList = list()
        
        for i in cursor:
            essidList.append(*i)

        for newEssid in ap.essid:
            if newEssid not in essidList:
                addEssid(cursor, ap.bssid, newEssid)
                log.debug(f"Inserted new essid: {newEssid}")

    if ap.location is not None and len(ap.location) > 0:
        cursor.execute(f"SELECT id, value FROM location WHERE bssid='{ap.bssid}'")
        locationList = list()

        for i in cursor:
            locationList.append((i[0], strToLoc(i[1]))) #store id and location in a tuple

        locationInsertCount = 0
        for newLocation in ap.location:
            
            unique = True
            for oldLoc in locationList:
                newLoc = strToLoc(newLocation)
                dist =  distanceMetres(newLoc, oldLoc[1])
                if dist <= LOCATION_DEVIATION_THRESHOLD:
                    unique = False
                    updateLocation(oldLoc[0], averageLocations(newLoc, oldLoc)) #linear average for db imports
                    break
            if unique:
                addLocation(cursor, ap.bssid, newLocation)
                locationInsertCount += 1
                if not roaming and len(locationList) + locationInsertCount > 1:
                    log.info(f"Station {ap.bssid} appears to be roaming")
                    updateRoaming(cursor, ap.bssid, True)
                    roaming = True

            
        log.debug(f"Inserted {locationInsertCount} new locations")

    if ap.pmkid is not None:
        cursor.execute(f"SELECT value FROM pmkid WHERE bssid='{ap.bssid}'")
        if cursor.rowcount < 1:
            addPmkid(cursor, ap.bssid, ap.pmkid)

    if ap.messagepair is not None and len(ap.messagepair) > 0:
        cursor.execute(f"SELECT value FROM messagepair WHERE bssid='{ap.bssid}'")
        mpList = list()

        for i in cursor:
            mpList.append(*i)

        for newMP in ap.messagepair:
            if newMP not in mpList:
                addMessagepair(cursor, ap.bssid, newMP)

    if ap.security is not None and len(ap.security) > 0:

        cursor.execute(f"SELECT security.value FROM network LEFT OUTER JOIN security_network_link ON network.bssid=security_network_link.bssid LEFT OUTER JOIN security ON security_network_link.security_id = security.id WHERE network.bssid = '{ap.bssid}'")

        secList = list()

        for i in cursor:
            secList.append(*i)

        for newSec in ap.security:

            if newSec not in secList:

                addSecurity(cursor, ap.bssid, newSec)

    if ap.roaming and roaming != True:

        updateRoaming(cursor, ap.bssid, True)

#check input file

parserFunction = None

if args.csv:
    parserFunction = FILETYPE_TO_PARSER_MAPPINGS["csv"] 
elif args.xml:
    parserFunction = FILETYPE_TO_PARSER_MAPPINGS["xml"]
else:
    mime, _ = mimetypes.guess_type(args.input_file)
    if mime == "text/csv":
        parserFunction = FILETYPE_TO_PARSER_MAPPINGS["csv"] 
    elif mime == "application/xml":
        parserFunction = FILETYPE_TO_PARSER_MAPPINGS["xml"]
    else:
        log.error("Failed to detect input file type. Try --csv or --xml")
        sys.exit(1)

#connect to db

dbConnection = tryConnectDb(args.db_address, args.nopass)
cursor = dbConnection.cursor()

#parse input

apList = parserFunction(args.input_file)

#import

for ap in apList:
    
    #check if bssid already present
    cursor.execute(f"SELECT bssid FROM network WHERE bssid = '{ap.bssid}'")
    if cursor.rowcount == 1: #if exists, update
        log.info(f"Updating entry for bssid {ap.bssid}")

        networkUpdateProcess(ap, cursor)
    elif cursor.rowcount > 1:

        log.error(f"The database has multiple records for ap {ap.bssid}. Can't continue")
        sys.exit(1)
    else: #else, create entry and populate values

        log.info(f"Creating entry for bssid {ap.bssid}")
        addNetwork(cursor, ap.bssid)
        networkUpdateProcess(ap, cursor)

dbConnection.commit()
dbConnection.close()
