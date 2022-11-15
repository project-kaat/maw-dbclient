#!/usr/bin/python3

import sys
sys.path.append("../")

import argparse
from db import tryConnectDb, sanitizeString
import log
from dataclasses import dataclass

@dataclass
class bssidAndPassword:

    bssid : str
    password : str

argumentParser = argparse.ArgumentParser()
argumentParser.add_argument('input_file', metavar="INPUT", type=str, help="file containing output of hashcat --show (-) for stdin")
argumentParser.add_argument('db_address', metavar="DB", type=str, help="db connection address in form: user@host:port")
argumentParser.add_argument("--nopass", action="store_true", help="don't ask for the database password")

args = argumentParser.parse_args()

def parseHashcatOutputLine(line : str):

    """
    format:
    something_irrelevant:bssid_ap:bssid_sta:essid:psk
    """

    lineSplit = line.split(':')

    bssid = lineSplit[1]
    password = lineSplit[4]

    return bssidAndPassword(bssid, password)

if args.input_file == "-":
    hashcatLines = sys.stdin.readlines()
else:
    try:
        with open(args.input_file, "r") as inputFile:
            hashcatLines = inputFile.readlines()
    except Exception as e:
        log.error(f"Failed to open file {args.input_file} for reading. ({e})")
        sys.exit(1)

dbConnection = tryConnectDb(args.db_address, args.nopass)
cursor = dbConnection.cursor()

for line in hashcatLines:
    bap = parseHashcatOutputLine(line)
    if not bap:
        log.warning(f"Failed to parse {line}")
        continue
    try:
        cursor.execute(f"UPDATE network SET cracked = TRUE where bssid = '{bap.bssid}'")
        cursor.execute(f"INSERT into password (bssid, value) VALUES('{bap.bssid}', '{sanitizeString(bap.password)}')")
        log.info(f"Inserted {bap.bssid} with password {bap.password}")
    except Exception as e:
        log.warning(f"Failed to insert {bap.bssid} with password {bap.password}. ({e})")
        continue

dbConnection.commit()
dbConnection.close()


