#!/usr/bin/python3

from datetime import datetime
from pytz import utc
from location import location
#@dataclass
#class nmeaGASentence:
#
#    daySeconds : int
#    lat : float
#    long : float


def getSentenceType(sentence):
    try:
        start = sentence.partition(b'$')[2]
        toEnd = start.partition(b'*')[0].decode() 
        return toEnd[2:5]
    except (ValueError, TypeError, IndexError):
        return None

def dmToFloat(dm):

    dotPtr = 0

    for c in dm:

        if c == ".":
            break
        else:
            dotPtr += 1

    return int(dm[:dotPtr-2]) + (float(dm[dotPtr-2:]) / 60)

def parseNmeaRMCSentence(sentence):

    start = sentence.partition(b"RMC")[2]
    toEnd = start.partition(b'*')[0].decode()

    split = toEnd.split(',')

    try:
        utcTime = split[1]
        badLat = split[3]
        badLon = split[5]
        date = split[9]

        timestamp = utc.localize(datetime( year = 2000 + int(date[4:6]),
            month = int(date[2:4]),
            day = int(date[:2]),
            hour = int(utcTime[:2]),
            minute = int(utcTime[2:4]),
            second = int(utcTime[4:6]),
            )).timestamp()

        lat = dmToFloat(badLat)
        lon = dmToFloat(badLon)

    except (ValueError, TypeError, IndexError):

        return None

    return location(timestamp, lat, lon)

#def parseNmeaGASentence(sentence):
#
#    start = sentence.partition(b"GGA")[2]
#    toEnd = start.partition(b'*')[0].decode()
#
#    split = toEnd.split(',')
#
#    print(split)
#
#    utcTime = split[1]
#    badLat = split[2]
#    badLon = split[4]
#
#    print(f"utcTime = {utcTime}\nbadLat = {badLat}\nbadLon = {badLon}")
#
#    daySeconds = int(utcTime[0:2]) * 3600 + int(utcTime[2:4]) * 60 + int(utcTime[4:6])
#
#    lat = dmToFloat(badLat)
#    lon = dmToFloat(badLon)
#
#    return nmeaGASentence(daySeconds, lat, lon)
