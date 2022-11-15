#!/usr/bin/python3
import sys

LOGLEVEL_QUIET      = 0
LOGLEVEL_ERR        = 1
LOGLEVEL_WARNING    = 2
LOGLEVEL_INFO       = 3
LOGLEVEL_DEBUG      = 4

COLOR_RED = '\033[31m'
COLOR_YELLOW = '\033[33m'
COLOR_BLUE = '\033[34m'
COLOR_RESET = '\033[0m'

LOGLEVEL_DEFAULT = LOGLEVEL_INFO


LOGLEVEL = LOGLEVEL_DEFAULT

def setLogLevel(level):

    if level < LOGLEVEL_QUIET or level > LOGLEVEL_DEBUG:
        raise ValueError

    LOGLEVEL = level

def info(msg):

    if LOGLEVEL >= LOGLEVEL_INFO:

        print(f"[{COLOR_BLUE}*{COLOR_RESET}] {msg}")

def error(msg):

    if LOGLEVEL >= LOGLEVEL_ERR:

        print(f"[{COLOR_RED}E{COLOR_RESET}] {COLOR_RED}{msg}{COLOR_RESET}", file=sys.stderr) 

def warning(msg):

    if LOGLEVEL >= LOGLEVEL_WARNING:

        print(f"[{COLOR_YELLOW}!{COLOR_RESET}] {msg}")

def debug(msg):

    if LOGLEVEL >= LOGLEVEL_DEBUG:
        print(f"DEBUG: {msg}")
