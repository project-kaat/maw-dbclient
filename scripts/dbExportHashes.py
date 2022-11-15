#!/usr/bin/python3

import sys
sys.path.append("../")

import argparse
import log
from db import tryConnectDb

argumentParser = argparse.ArgumentParser()
argumentParser.add_argument('db_address', metavar="DB", type=str, help="db connection address in form: user@host:port")
argumentParser.add_argument('output_prefix', metavar="OUTPUT", type=str, help="output file prefix (without extension)")
argumentParser.add_argument("--nopass", action="store_true", help="don't ask for the database password")
argumentParser.add_argument("--includecracked", action="store_true", help="include already cracked hashes too")
argumentParser.add_argument("--hashcat22000", action="store_true", help="output in hashcat 22000 format (.22000 extension)")

args = argumentParser.parse_args()

#check if any output format specified
if not args.hashcat22000:
    log.error("Specify at least one output format")
    sys.exit(1)

dbConnection = tryConnectDb(args.db_address, args.nopass)
cursor = dbConnection.cursor()

#get hashes
if args.includecracked:
    cursor.execute(f"SELECT value FROM pmkid")
    pmkidHashes = cursor.fetchall()
    cursor.execute(f"SELECT value FROM messagepair")
    mpHashes = cursor.fetchall()
else:
    cursor.execute(f"SELECT value FROM pmkid WHERE bssid NOT IN (select bssid FROM network WHERE cracked = TRUE)")
    pmkidHashes = cursor.fetchall()
    cursor.execute(f"SELECT value FROM messagepair WHERE bssid NOT IN (select bssid FROM network WHERE cracked = TRUE)")
    mpHashes = cursor.fetchall()

#export
if args.hashcat22000:
    try:
        with open(f"{args.output_prefix}.22000", "w") as outFile:
            for pmkid in pmkidHashes:
                outFile.write(f"{pmkid[0]}\n")
            for messagepair in mpHashes:
                outFile.write(f"{messagepair[0]}\n")
    except Exception as e:
        log.error(f"Failed to open {args.output_prefix}.22000. ({e})")
        sys.exit(1)
    

