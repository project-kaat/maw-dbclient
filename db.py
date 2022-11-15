#!/usr/bin/python3

import mariadb
import log
import sys
from getpass import getpass

def sanitizeString(string):

    string = string.strip("\n\r")

    counter = 0
    for c in string:
        if c == '\'' or c == '\"':
            string = string[:counter] + '\\' + string[counter:]
        counter += 1

    return string

def tryConnectDb(addr, nopass=False):

    connectionArgs = {'database':"maw"}

    if '@' in addr:
        part = addr.partition('@')
        user = part[0]
        addr = part[2]
        connectionArgs['user'] = user
    if ':' in addr:
        part = addr.partition(':')
        port = int(part[2])
        addr = part[0]
        connectionArgs['port'] = port

    connectionArgs['host'] = addr

    if not nopass:
        passwd = getpass("Password for DB access: ")
        connectionArgs['password'] = passwd

    try:
        con = mariadb.connect(**connectionArgs)
    except mariadb.Error as e:
        log.error(f"Failed to access the database. ({e})")
        sys.exit(1)

    log.info("Successfully connected to the database")
    return con

