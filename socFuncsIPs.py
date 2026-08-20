# By: Matthew Bourn
# On: 2020-10-20
# ©: GNU GPLv3
# Do: at your own risk; copy, modify, share, give me a nod.  Don't sell.

# IPS #
###################################################################################################
##### Imports #####
###################################################################################################

## Standard Modules
import sys
import json
import requests
import argparse
import ipaddress
import subprocess

## Custom Modules
import socLists

from socVars import rst as rst
from socVars import bang as bang
from socVars import plus as plus
from socVars import title as title

from socVars import RED as RED
from socVars import BLUE as BLUE
from socVars import GREEN as GREEN
from socVars import YELLOW as YELLOW

###################################################################################################
##### Functions #####
###################################################################################################
def errSoft(m,e):
    print(bang+ " Something went wrong when " +m)
    print(bang+ " " +str(e))
    print(bang+ " Skipping!")

def errHard(m,e):
    print(bang+ " " +m)
    print(bang+ " Quitting!")
    sys.exit(1)

## Use common module to confirm we were given a proper IP
def testIP(ip):
    print("\n[-] " +title+"----- Testing for valid IP -----" +rst+ " [-]")
    try:
        out = ipaddress.ip_address(ip)
    except ValueError as e:
        print(bang+ str(e))
        print(bang+ " Quitting!")
        sys.exit(1)
    print(plus+ "               " +GREEN+ "VALID" +rst)

###################################################################################################
## IP-API.com Geolocation
def ipGEO(ip,url):
    print("\n[-] " +title+ "----- Checking IP-API for Geolocation -----" +rst+ " [-]")
    urlFull = url+ip
    try:
        res = requests.get(urlFull)
    except ValueError as e:
        m = "contacting IP-API's API"
        errSoft(m,e)
        return None

    try:
        resJS = json.loads(res.content.decode('utf-8'))
    except ValueError as e:
        m = "parsing response into json"
        errSoft(m,e)
        return None

    if resJS['status'] == 'success':
        print(plus+ "Country:\t" +GREEN+resJS["country"]+rst)
        print(plus+ "Region:\t" +GREEN+resJS["regionName"]+rst)
        print(plus+ "City:\t" +GREEN+resJS["city"]+rst)
    else:
        m = "with the API request"
        errSoft(m,resJS)
        return None

###################################################################################################
## Farsight DB: passive DNS 
def ipFS(ip,token,url):
    print("\n[-] " +title+ "----- Checking Farsight DNSDB for IP -----" +rst+ " [-]")
    urlFull = url+ip+ "/ANY"
    try:
        res = requests.get(urlFull, headers={'X-API-Key': token},)
    except ValueError as e:
        m = 'trying to search for the hash'
        errSoft(m,e)
        return None

    # Fix their messed up JSON and create a dict
    try:
        resJS = json.loads('{"results":['+res.content.decode('utf-8').replace("\n","").replace("}{","},{")+"]}")['results'][+1:-1]
    except ValueError as e:
        m = 'trying to parse the response'
        errSoft(m,e)
        return None

    print(plus+ " Resolutions: ")
    resStr = plus+plus+ " "

    # If no resolutions were returned
    if len(resJS) == 0:
        print(bang+ " No domain names found in FarSight")
    
    # If there are fewer than 5 resolutions
    elif len(resJS) < 5:
        for obj in resJS:
            resStr+= BLUE+obj['obj']['rrname']+rst+ " | "
        print(resStr)

    # If there are more than 4 resolutions
    elif len(resJS) > 4:
        i = 1
        for obj in resJS:
            resStr+= obj['obj']['rrname']+ " | "
            if i%4 == 0:
                print(resStr)
                resStr = plus+plus+ " "
                i = 0
            i+=1
        if len(resStr) > 20:
            print(resStr)

    # Something weird happened
    else:
        print(bang+ " Something weird happened.  Here's the raw output:")
        print(res.content)

###################################################################################################
## VirusTotal: One stop shop
def ipVT(ip,token,url):
    print("\n[-] " +title+ "----- Checking VirusTotal for IP -----" +rst+ " [-]")
    
    # Create auth header
    apiAuth = '{"x-apikey": "' +token+ '"}'
    hdrs = json.loads(apiAuth)

    # Get basic info from the API
    try:
        res = requests.get(url+ip, headers=hdrs)
    except ValueError as e:
        m = 'querying the API for basic IP info'
        errSoft(m,e)
        return None

    # Parse the response into JSON
    try:
        resJS = json.loads(res.content.decode('utf-8'))
    except ValueError as e:
        print(res)
        m = 'trying to parse the response into JSON'
        errSoft(m,e)
        return None

    # Print select WHOIS data
    if "whois" in resJS['data']['attributes']:
        print(plus+ " WHOIS Data")
        for i in resJS['data']['attributes']['whois'].split('\n'):
            if i.split(":")[0] in ['CIDR','RegDate','OrgName','City','Country']:
                print(plus+plus+ "\t" +i)
    else:
        print(plus+ GREEN+" No WHOIS Data" +rst+ " Available from VirusTotal")

    # Community thoughts on the IP
    if resJS['data']['attributes']['total_votes']['malicious'] > 0:
        print(plus+ ' Community votes of "Malicious": ' +RED+ str(resJS['data']['attributes']['total_votes']['malicious'])+rst)
    else:
        print(plus+ ' Community votes of "Malicious": ' +GREEN+ str(resJS['data']['attributes']['total_votes']['malicious'])+rst)

    # Get and print some sample detections
    dets = []
    for i in resJS['data']['attributes']['last_analysis_results']:
        if resJS['data']['attributes']['last_analysis_results'][i]['category'] in ['malicious','suspicious']:
            dets.append((str(i),resJS['data']['attributes']['last_analysis_results'][i]['category']))

    if len(dets) > 0 and len(dets) < 6:
        print(plus+ " Detections: " +RED+str(len(dets))+rst)
        for i in range(0,len(dets)):
            print(plus+plus+ "\t" +dets[i][0]+ "- " +RED+dets[i][1]+rst)
    elif len(dets) > 5:
        print(plus+ " Detections: " +RED+str(len(dets))+rst)
        for i in range(0,4):
            print(plus+plus+ "\t"  +dets[i][0]+ "- " +RED+dets[i][1]+rst)
    elif len(dets) == 0:
        print(plus+ " All engines marked the IP " +GREEN+ "HARMLESS" +rst)
    else:
        m = "trying to count the number of detections"
        errSoft(m,resJS)
        return None

    # Get DNS resolutions
    try:
        res = requests.get(url+ip+"/resolutions", headers=hdrs)
    except ValueError as e:
        m = "querying the API for DNS resolutions"
        errSoft(m,e)
        return None

    # Parse the response into JSON
    try:
        resJS = json.loads(res.content.decode('utf-8'))
    except ValueError as e:
        print(res)
        m = "trying to parse the response into JSON"
        errSoft(m,e)
        return None

    # Display results
    if len(resJS['data']) == 0:
        print(plus+ GREEN+ " No DNS Data" +rst+ " available from VirusTotal") 
    elif len(resJS['data']) > 0 and len(resJS['data']) < 6:
        print(plus+ " Number of Resolutions: " +GREEN+ str(len(resJS['data'])) +rst)
        for i in resJS['data']:
            print(plus+plus+ "\t" +BLUE+i['attributes']['host_name']+rst)
    elif len(resJS['data']) > 5:
        print(plus+ " Number of Resolutions: " +GREEN+ str(len(resJS['data'])) +rst)
        for i in range(0,5):
            print(plus+plus+ "\t" +BLUE+resJS['data'][i]['attributes']['host_name']+rst)
    else:
        m = "when trying to display DNS resolutions"
        errSoft(m,resJS)
        return None

    # Get communicating files
    try:
        res = requests.get(url+ip+ "/communicating_files", headers=hdrs)
    except ValueError as e:
        m = 'querying the API for basic IP info'
        errSoft(m,e)
        return None

    # Parse the response into JSON
    try:
        resJS = json.loads(res.content.decode('utf-8'))
    except ValueError as e:
        print(res)
        m = "trying to parse the response into JSON"
        errSoft(m,e)
        return None

    dets = []
    for i in resJS['data']:
        if i['attributes']['last_analysis_stats']['malicious'] > 0:
            dets.append(i)

    if len(dets) == 0:
        print(plus+ GREEN+ " No malicious files" +rst+ " communicate with this IP")
    elif len(dets) > 0 and len(dets) < 6:
        print(plus+ " Malicious files communicating with this IP: " +RED+str(len(dets))+rst)
        for i in dets:
            if "meaningful_name" in i['attributes']:
                print(plus+plus+ " Malicious file name: " +RED+ i['attributes']['meaningful_name']+rst)
            elif "names" in i['attributes'] and len(i['attributes']['names']) > 0:
                print(plus+plus+ " Malicious file name: " +RED+ i['attributes']['names'][0]+rst)
            else:
                print(plus+plus+ " VT has not saved a name for this file")
            print(plus+plus+ " Flagged by " +RED+ str(i['attributes']['last_analysis_stats']['malicious'])+rst+ " engines.")
    elif len(dets) > 5:
        print(plus+ " Malicious files communicating with this IP: " +RED+str(len(dets))+rst)
        for i in range(0,5):
            if "meaningful_name" in dets[i]['attributes']:
                print(plus+plus+ " Malicious file name: " +RED+ dets[i]['attributes']['meaningful_name']+rst)
            elif "names" in dets[i]['attributes'] and len(dets[i]['attributes']['names']) > 0:
                print(plus+plus+ " Malicious file name: " +RED+ dets[i]['attributes']['names'][0]+rst)
            else:
                print(plus+plus+ " VT has not saved a name for this file")
            print(plus+plus+ " Flagged by " +RED+ str(dets[i]['attributes']['last_analysis_stats']['malicious'])+rst+ " engines.")
    else:
        print(bang+ " Something when wrong when parsing malicious files communicating with this IP")
        print(dets)

    print(plus+ BLUE+" https://www.virustotal.com/gui/ip-address/" +ip+rst+ "\n")

###################################################################################################
## Project HoneyPot: IP attack pattern analysis
## Uses hpMeanings list from socLists the module
def ipHP(ip,token,url):
    print("\n[-] " +title+ "----- Checking Project HoneyPot for IP -----" +rst+ " [-]")
    # Get list of HoneyPot descriptors
    descList = []

    # Query Project HoneyPot
    ipRev = '.'.join(reversed(ip.split('.')))
    url = token+ "." +ipRev+url
    # TODO Figure out how to do this without subprocess
    try:
        res = subprocess.Popen(["host", url], stdout=subprocess.PIPE).stdout.read()
    except ValueError as e:
        m = 'querying the API'
        errSoft(m,e)
        return None
    
    # Parse the answer and respond appropriately
    try:
        answer = res.decode('utf-8').split('\n')[0].split(" ")[-1]
    except ValueError as e:
        m = 'trying to parse the answer'
        errSoft(m,e)
        return None

    ## IP not found
    if "NXDOMAIN" in answer:
        print(plus+ " IP is " +RED+ "NOT" +rst+ " in the Project HoneyPot Database")

    ## IP found
    elif answer.split(".")[0] == "127":
        print(plus+ " Threat lvl: " +RED +answer.split(".")[1] +rst)
        print(plus+ " Last active: " +RED +answer.split(".")[2] +rst)
        mean = [i for i in socLists.hpMeanings if i[0] == int(answer.split(".")[3])]
        print(plus+ " Description: " +RED +mean[0][1] +rst)
    
    ## Unknown resposne
    else:
        print(bang+ " Unrecognized response: " + answer)

###################################################################################################
## IP Intelligence: Identify VPN, Proxy, TOR exits
## Uses iiErrs list from the socLists module
def ipII(ip,eAddy,url):
    # http://check.getipintel.net/check.php?ip=194.156.98.46&contact=name@domain.org
    print("\n[-] " +title+ "----- Checking IP Intel if IP is TOR/VPN/Proxy Exit -----" +rst+ " [-]")
    print(bang+ " This is an experimental service and returns inconsistent results")
    urlFull = url+ip+ "&contact=" +eAddy
    
    # Query the API
    try:
        res = requests.get(urlFull)
    except ValueError as e:
        m = " querying the API"
        errSoft(m,e)
        return None
    # Parse the results
    try:
        num = int(float(res.content.decode('utf-8')) * 100)
    except ValueError as e:
        m = " parsing the results"
        errSoft(m,e)
        return None

    # Display the results
    if int(float(res.content.decode('utf-8'))) < 0:
        print(bang+ " Error code: " +RED+res.content.decode('utf-8')+rst+ " - " + socLists.iiErrs[abs(int(res.content.decode('utf-8'))) - 1])
    elif num > 100:
        print(bang+ " Unknown error")
        print(bang+ " " +res)
    elif num > 89:
        print(plus+ " The IP's score is (higher is worse): " +RED+str(num)+rst)
        print(plus+plus+ " There is a " +RED+ "HIGH" +rst+ " probability that this is a TOR/VPN/Proxy exit")
    elif num < 90:
        print(plus+ " The IP's score is: " +GREEN+str(num)+rst)
        print(plus+plus+ " There is a " +GREEN+ "LOW" +rst+ " probability that this is a TOR/VPN/Proxy exit")
    else:
        m = " displaying the results"
        errSoft(m,res)
        return None


###################################################################################################
## IP IQ Score: IP behavioral profile
def ipIQ(ip,url):
    print("\n[-] " +title+ "----- Checking IP Quality Score for IP -----" +rst+ " [-]")
    ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36&user_language=en-US;"
    args = {'strictness': '0', 'allow_public_access_points': 'true', 'user_agent': ua} 
    urlFull = url+ip
    profiles = ["is_crawler","mobile","host","proxy","vpn","tor","active_vpn","active_tor","device_brand","device_model","recent_abuse","bot_status"]

    try:
        res = requests.get(urlFull, params=args).content.decode('utf-8')
    except ValueError as e:
        m = "qeurying the API"
        errSoft(m,e)
        return None
    try:
        resJS = json.loads(res)
    except ValueError as e:
        m = "parsing the response into JSON"
        errSoft(m,e)
        return None
    try:
        if "success" in resJS and resJS['success'] == True:
            print(plus+ " IP Profile Report:")
            for i in resJS:
                if i in profiles and resJS[i] == True:
                    print(plus+plus+ " " +i.capitalize()+ ": " +RED+ "TRUE" +rst)
                elif i in profiles and resJS[i] == False:
                    print(plus+plus+ " " +i.capitalize()+ ": " +GREEN+ "False" +rst)
        else:
            print(bang+ " No profile report available for this IP")
            print(resJS)
    except ValueError as e:
        print(resJS)
        m = "working with the response JSON object"
        errSoft(m,e)
        return None

###################################################################################################
## TOR Relay/Exit List
def ipTR(ip,url):
    # curl -kL "https://onionoo.torproject.org/summary?limit=4&search=1.174.24.139"
    print("\n[-] " +title+ "----- Checking IP With TOR Project -----" +rst+ " [-]")

    # Query the API
    urlFull = url+ip
    try:
        res = requests.get(urlFull).content.decode('utf-8')
    except ValueError as e:
        m = " querying the API"
        errSoft(m,e)
        return None

    # Convert the response to a JSON object
    try:
        resJS = json.loads(res)
    except ValueError as e:
        m = " converting response to JSON"
        errSoft(m,e)
        return None

    # Display the results
    print(plus+ " TOR relay/exit list last updated: " +GREEN+resJS['relays_published'])
    if len(resJS['relays']) > 0:
        print(plus+plus+RED+ "\tCONFIRMED" +rst+ " TOR node")
        print(plus+plus+ "\tNode Name: " +resJS['relays'][0]['n'])
        print(plus+plus+ "\tFingerprint: " +resJS['relays'][0]['f'])
    else:
        print(bang+ " IP is " +GREEN+ "NOT" +rst+ " listed by TOR as a node")
    







