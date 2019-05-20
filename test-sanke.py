#!/usr/bin/env python3

import asyncio
import os
import tempfile

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
    asyncio.run(t())
    print("")

case(["OwO",], ["","0","",],)

case(["OwO","UwU"], ["","0","1","0,1","1,0","1,0","0,1","1","",],)

case(["OwO","UwU","@w@"], ["0,1,2","2,1,0",],)
case(["OwO","UwU","@w@"], ["0,1,2","2,1,0","1"],)
case(["OwO","UwU","@w@"], ["0,1,2","2,1,0","1","2","2","1"],)
case(["OwO","UwU","@w@"], ["0,1,2","2,1,0","1","2","2","1",],)

case(["OwO","UwU","@w@","XwX"], ["0,1,2","2,1,0","1","2","2","1","3,1"],)
case(["OwO","UwU","@w@","XwX"], ["0,1,2","2,1,0","1","2","2","1","3,1,0"],)
