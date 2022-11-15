# MAW db client software

## Description

[Part of the MAW project](https://github.com/project-kaat/maw)

This is a set of scripts that work with the MAW database. Main purpose of this software is to populate the db with captured data and work with the hashes from there.

It also correlates GPS location data and uses some simple logic to determine each AP's approximate location when possible.

Currently, hcxpcapngtool is needed to extract captured hashes from .pcapng files (it works well and there is no real reason to reimplement it).

**Workflow example:**

    1. Feed the captured .pcapng files to scripts/parsePcapng.py
    2. Use the parsePcapng.py output files with scripts/dbImport.py to populate the database
    3. Export hashes for cracking with scripts/dbExportHashes.py
    4. Import cracked passwords into the database with scripts/dbImportHashcat.py
    5. Export available AP info (as well as location data and cracked passwords) to a kml format with scripts/dbExportKml.py for using with a map viewer software (Google Maps, OsmAnd, whatever)
    
## Dependencies

**python**
```
simplekml # for kml output
mariadb   # for database interaction
```

**extra**
```
hcxpcapngtool # for extracting hashes from pcapng files
```
