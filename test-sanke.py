#!/usr/bin/env python3

import asyncio
import os
import tempfile
import traceback

import rcv

def case(options, ballots):
    fo = ",".join(options)
    fb = "\n".join(ballots)
    print(f"Options: {fo}")
    print(f"Ballots:\n{fb}", flush=True)
    async def t():
        svg_bytes = await rcv.result_diagram(
            options,
            {str(i): b for i, b in enumerate(ballots)},
        )
        assert svg_bytes is not None
    try:
        asyncio.run(t())
    except Exception:
        traceback.print_exc()
    print("")

#case(["OwO",], ["","0","",],)

#case(["OwO","UwU"], ["","0","1","0,1","1,0","1,0","0,1","1","",],)

#case(["OwO","UwU","@w@"], ["0,1,2","2,1,0",],)
#case(["OwO","UwU","@w@"], ["0,1,2","2,1,0","1"],)
#case(["OwO","UwU","@w@"], ["0,1,2","2,1,0","1","2","2","1"],)
#case(["OwO","UwU","@w@"], ["0,1,2","2,1,0","1","2","2","1",],)

#case(["OwO","UwU","@w@","XwX"], ["0,1,2","2,1,0","1","2","2","1","3,1"],)
#case(["OwO","UwU","@w@","XwX"], ["0,1,2","2,1,0","1","2","2","1","3,1,0"],)

#import sys
#sys.exit()

case(["Aasdadfgstyjtyjtysdstydnhjdtyejty","Bdgfdsgdfdfgdfdgf","C","D","E","F","G","H","I","J"], [
    "0,1,2",
    "2,1,0",
    "1",
    "2",
    "2",
    "1",
    "3,1,0",
    "0,1,2,3,4,5,6,7,8,9",
    "0,1,2,3,4,5,6,7,8,9",
    "9,8,7,6,5,4,3,2,1,0",
    "9,8,7,6,5,4,3,2,1,0",
    "5,6,3,7,1,0,9,8,2,4",
    "8,6,1,3,0,5,9,4,2,7",
],)
