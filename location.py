#!/usr/bin/python3

from math import cos, asin, sqrt, pi
from dataclasses import dataclass
import numpy as np

def distanceMetres(loc1, loc2): #haversine implementation

    p = pi/180
    a = 0.5 - cos((loc2.lat - loc1.lat)*p)/2 + cos(loc1.lat*p) * (1-cos((loc2.long-loc1.long)*p))/2
    return (12742 * asin(sqrt(a))) * 1000

def averageLocations(loc1, loc2):

    newLat = (loc1.lat + loc2.lat) /2
    newLong = (loc1.long + loc2.long) / 2

    return location(0, newLat, newLong)

def averageLocationPool(uniqueLocationPool):

    values = list()
    weights = list()

    for sig, locations in uniqueLocationPool.items():

        if not len(locations):
            continue

        if sig == "NOSIG":
            weights.append(-99)
        else:
            weights.append(100+sig)

        averageOfSignal = locations[0]
        for loc in locations[1:]:
            averageOfSignal = averageLocations(averageOfSignal, loc)

        values.append((averageOfSignal.lat, averageOfSignal.long))

    if len(values) > 1:
        weighted = np.average(values, weights=weights, axis=0)

        return location(0, weighted[0], weighted[1])
    else:
        return location(0, values[0][0], values[0][1])



    
@dataclass
class location:

    timestamp : int
    lat : float
    long : float

    def __repr__(self):

        return f"{self.lat},{self.long}"

def strToLoc(s):

    part = s.partition(",")

    return location(0, float(part[0]), float(part[2]))
