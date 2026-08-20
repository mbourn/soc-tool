# By: Matthew Bourn
# On: 2020-10-20
# ©: GNU GPLv3
# Do: at your own risk; copy, modify, share, give me a nod.  Don't sell.

# VARIABLES #
###################################################################################################
##### Imports #####
###################################################################################################

## Standard Modules
from colorama import Fore as fr
from colorama import Back as bk
from colorama import Style as styl

###################################################################################################
##### Variables #####
###################################################################################################

##### Define Text Colors #####
RED = fr.RED+styl.BRIGHT
BLUE = fr.BLUE+styl.BRIGHT
GREEN = fr.GREEN+styl.BRIGHT
YELLOW = fr.YELLOW+styl.BRIGHT

rst = styl.RESET_ALL
bang = RED+ '[!]' +rst
plus = GREEN+ '[+]' +rst
title = bk.WHITE+styl.DIM+fr.BLACK

###################################################################################################
## IP-API.com ##
ipaUrl = "http://ip-api.com/json/"

###################################################################################################
## IOCLists ##
ilToken = "YOUR TOKEN HERE"
ilUrl = "https://api.ioclists.com/v1/indicator/entries?indicator="

###################################################################################################
## Phish Tank ##
# The documentation is terrible
## Request URL must be "httpS" not "http"
## Request URL must be "https://checkurl.phishtank.com/checkurl/index.php?url=xxxx"
## Translate this to English https://blog.csdn.net/m0_37605407/article/details/105236971
ptToken = "YOUR TOKEN HERE"
ptUrl = "https://checkurl.phishtank.com/checkurl/index.php?url="
ptUA = "phishtank/YOUR ACCOUNT NAME"

###################################################################################################
# TODO
## CheckPhish API ##
# https://checkphish.ai/docs/checkphish-api/
cpToken = "YOUR TOEKN HERE"
cpUrl = ""

###################################################################################################
## WhoisXML API ##
wxToken = "YOUR TOKEN HERE"
wxUrl = "https://domain-reputation.whoisxmlapi.com/api/v1?apiKey="

###################################################################################################
## IP Quality Score ## 
# https://www.ipqualityscore.com/documentation/proxy-detection/best-practices
iqToken = "YOUR TOKEN HERE"
iqUrlBase = "https://ipqualityscore.com/api/json/ip/"
iqUrl = iqUrlBase+iqToken+ "/"

###################################################################################################
## IP Intelligence ##
# https://getipintel.net/free-proxy-vpn-tor-detection-api/
iiEAddy = "YOUR EMAIL HERE"
iiUrl = "http://check.getipintel.net/check.php?ip="

###################################################################################################
## Malware Bazaar ##
mbToken = "YOUR TOKEN HERE"
mbUrl = "https://mb-api.abuse.ch/api/v1/"
mbPostQ = '"query": "get_info"'

###################################################################################################
## MalShare ##
msToken = "YOUR TOKEN HERE"
msUrl = "https://malshare.com/api.php?api_key=" +msToken+ "&action=search&query="

###################################################################################################
## VirusTotal ##
vtToken = "YOUR TOKEN HERE"
vtUrlIP = "https://www.virustotal.com/api/v3/ip_addresses/"
vtUrlHash = "https://www.virustotal.com/api/v3/files/"
vtUrlDom = "https://www.virustotal.com/api/v3/domains/"

###################################################################################################
## Operation Honeypot ##
hpToken = "YOUR TOKEN HERE"
hpUrl = ".dnsbl.httpbl.org"

###################################################################################################
## FarSight ##
## They require you to reconfirm your free account every month
fsToken = "YOUR TOKEN HERE"
fsUrl = "https://api.dnsdb.info/dnsdb/v2/lookup/rdata/ip/"

###################################################################################################
## Intezer Analyze ##
iaToken = "YOUR TOKEN HERE"
iaUrl = "https://analyze.intezer.com/api/v2-0"

###################################################################################################
## Hybrid-Analysis ##
haToken = "YOUR TOKEN HERE"
haSecret = "YOUR SECRET HERE"
haUrlBase = "http://www.hybrid-analysis.com/api/v2/search/hash?_timestamp="
haUrlV1 = "https://www.hybrid-analysis.com/api/search?query="
haHUA = "Falcon Sandbox"
haHAAccept = "application/json"
haHType = "applicatoin/x-www-form-urlencoded"

###################################################################################################
## TOR Project ##
trUrl = "https://onionoo.torproject.org/summary?limit=1&search="




