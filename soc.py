#!/usr/bin/env python3

# By: Matthew Bourn
# On: 2020-10-20
# ©: GNU GPLv3
# Do: at your own risk; copy, modify, share, give me a nod.  Don't sell.

##### Imports #####
import sys
import argparse

import socVars as v
import socFuncsIPs as ips
import socFuncsDoms as doms
import socFuncsHashs as hashes

from socVars import rst as rst
from socVars import bang as bang
from socVars import plus as plus
from socVars import title as title

from socVars import RED as RED
from socVars import BLUE as BLUE
from socVars import GREEN as GREEN
from socVars import YELLOW as YELLOW

##### In Progress #####
# TODO: Set up multiple processes
# TODO: Set up CheckPhish for domains
###################################################################################################
def main(argv):
    # Handle the args
    desc = "This program searches for basic OSINT data on either an IP or a hash."
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("-i", "--ip", help="The IP whose reputation to search")
    parser.add_argument("-H", "--hash", help="The hash whose reputation to search")
    parser.add_argument("-d", "--domain", help="The domain whose reputation to search")
    args = parser.parse_args()

    if args.hash:
        hashes.testHash(args.hash)
        hashes.hashIA(args.hash,v.iaToken,v.iaUrl)
        doms.genIL(args.hash,v.ilToken,v.ilUrl)
        hashes.hashVT(args.hash,v.vtToken,v.vtUrlHash)
        hashes.hashHA(args.hash,v.haToken,v.haUrlBase,v.haHUA,v.haHType,v.haHAAccept)
        hashes.hashMB(args.hash,v.mbToken,v.mbUrl,v.mbPostQ)
        hashes.hashMS(args.hash,v.msToken,v.msUrl)

    elif args.ip:
        ips.testIP(args.ip)
        ips.ipII(args.ip,v.iiEAddy,v.iiUrl)
        ips.ipGEO(args.ip,v.ipaUrl)
        ips.ipHP(args.ip,v.hpToken,v.hpUrl)
        doms.genIL(args.ip,v.ilToken,v.ilUrl)
        ips.ipIQ(args.ip,v.iqUrl)
        ips.ipTR(args.ip,v.trUrl)
        ips.ipFS(args.ip,v.fsToken,v.fsUrl)
        ips.ipVT(args.ip,v.vtToken,v.vtUrlIP)

    elif args.domain:
        doms.domWX(args.domain,v.wxToken,v.wxUrl)
        doms.domPT(args.domain,v.ptToken,v.ptUA,v.ptUrl)
        doms.genIL(args.domain,v.ilToken,v.ilUrl)
        doms.domHA(args.domain,v.haToken,v.haSecret,v.haHUA,v.haUrlV1)
        doms.domVT(args.domain,v.vtToken,v.vtUrlDom)
    else:
        print(bang+ " Something went wrong.  Please try again.")
        print("\n")
        sys.exit(1)

    print("\n[-] " +title+ "----- FINISHED -----" +rst+ " [-]")
    print("\n")


###################################################################################################
##### MAIN #####
###################################################################################################
if __name__ == "__main__":
    main(sys.argv[1:])
