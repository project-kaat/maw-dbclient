#!/usr/bin/python3

import sys
sys.path.append("../")

import argparse
from db import tryConnectDb, sanitizeString
import log
from dataclasses import dataclass

@dataclass
class essidAndPassword:

    essid : str
    password : str

argumentParser = argparse.ArgumentParser()
argumentParser.add_argument('input_file', metavar="INPUT", type=str, help="file containing output of hashcat --show (-) for stdin")
argumentParser.add_argument('db_address', metavar="DB", type=str, help="db connection address in form: user@host:port")
argumentParser.add_argument("--nopass", action="store_true", help="don't ask for the database password")

args = argumentParser.parse_args()

def parseJohnOutputLine(line : str):

    """
    format:
    $WPAPSK$essid#something_irrelevant:psk
    """

    lineSplit = line.split('$')

    essid = lineSplit[2].partition('#')[0]

    password = lineSplit[2].partition('#')[2].split(':')[-1]

    return essidAndPassword(essid, password)

if args.input_file == "-":
    johnLines = sys.stdin.readlines()
else:
    try:
        with open(args.input_file, "r") as inputFile:
            johnLines = inputFile.readlines()
    except Exception as e:
        log.error(f"Failed to open file {args.input_file} for reading. ({e})")
        sys.exit(1)

dbConnection = tryConnectDb(args.db_address, args.nopass)
cursor = dbConnection.cursor()

for line in johnLines:
    eap = parseJohnOutputLine(line)
    if not eap:
        log.warning(f"Failed to parse {line}")
        continue
    try:
        cursor.execute(f"SELECT bssid FROM essid WHERE value = '{eap.essid}'")
        bssids = cursor.fetchall()
        if len(bssids) > 1:
            log.warning(f"essid {eap.essid} has multiple bssid candidates. Leaving it up to you")
            continue
        bssid = bssids[0][0]
        cursor.execute(f"UPDATE network SET cracked = TRUE where bssid = '{bssid}'")
        cursor.execute(f"INSERT into password (bssid, value) VALUES('{bssid}', '{sanitizeString(eap.password)}')")
        log.info(f"Inserted {bssid} with password {eap.password}")
    except Exception as e:
        log.warning(f"Failed to insert {bssid} with password {eap.password}. ({e})")
        continue

dbConnection.commit()
dbConnection.close()


