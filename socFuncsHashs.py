# By: Matthew Bourn
# On: 2020-10-20
# ©: GNU GPLv3
# Do: at your own risk; copy, modify, share, give me a nod.  Don't sell.

# HASHES #
###################################################################################################
##### Imports #####
###################################################################################################

## Standard Modules
import sys
import json
import urllib
import pprint
import requests
import datetime as dt
import subprocess

from requests import ReadTimeout, ConnectTimeout, HTTPError, Timeout, ConnectionError

## Custom Mondules
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

## Use HashID to check if the provided hash is valid
def testHash(h):
    print("\n[-] " +title+ "----- Testing hash -----" +rst+ " [-]")
    # TODO: Find a way to call hashid without resorting to subprocess
    try:
        res = subprocess.Popen(["hashid", h], stdout=subprocess.PIPE).stdout.read()
    except ValueError as e:
        print(bang+ " Do you have hashid installed? 'pip install hashid'")
        print(bang+ e)
        return
    hashes = res.decode('utf-8').split('\n')
    print(plus+ " Hash looks like:")
    if "Unknown hash" not in hashes[1]:
        i = 1
        outStr = plus+plus+ "\t|"
        for h in hashes[+1:-1]:
            outStr += h.replace("[+]","")+ "|"
            if i % 5 == 0:
                print(outStr)
                outStr = plus+plus+ "\t|"
            i += 1
        print(outStr)

        if '[+] SHA-1 ' not in hashes and '[+] SHA-256 ' not in hashes and '[+] MD5 ' not in hashes:
            print(bang+ " OSINT providers only accept MD5, SHA-1, or SHA-256")
            m= "Please try again with one of those hash types"
            e=''
            errHard(m,e)
    elif 'Unknown hash' in hashes[1]:
        print(bang+ " Unknown hash type")
        print(bang+ " OSINT providers only accept MD5, SHA-1, or SHA-256")
        m= "Please try again with one of those hash types"
        e=''
        errHard(m,e)

###################################################################################################
## Malware Bazaar Malware Library
def hashMB(hsh,token,url,postQuery):
    print("\n[-] " +title+ "----- Checking Malware Bazaar for hash -----" +rst+ " [-]")
    postData = {"query": "get_info", "hash": hsh}
    postHeaders = {"API-KEY": token}

    try: 
        res = json.loads(requests.post(url, headers=postHeaders, data=postData).content.decode('utf-8'))
    except ValueError as e:
        m = 'querying the API'
        errSoft(m,e)
        return None

    #{\n    "query_status": "hash_not_found"\n}
    if "query_status" in res and res['query_status'] == 'hash_not_found':
        print(bang+ " File is " +RED+ "NOT" +rst+ " in the Malware Bazaar library")
    # "data": [0]["first_seen/file_type_mime/intelligence": {service: [detection"]
    elif "data" in res:
        print(plus+ " File Name: " +res['data'][0]['file_name'])
        print(plus+ " File Type: " +res['data'][0]['file_type_mime'])
        print(plus+ " First Seen: " +res['data'][0]['first_seen'])
        if res['data'][0]['intelligence']['clamav'] == None:
            print(plus+ " File is available, but there are no Clamav detections")
        elif len(res['data'][0]['intelligence']['clamav']) > 0 and len(res['data'][0]['intelligence']['clamav']) < 6:
            print(plus+ " Detections:")
            for i in range(0,len(res['data'][0]['intelligence']['clamav'])-1):
                print(plus+plus+ "\t" +RED+ res['data'][0]['intelligence']['clamav'][i] +rst)
        elif len(es['data'][0]['intelligence']['clamav']) > 5:
            print(plus+ " Detections:")
            for i in range(0,4):
                print(plus+plus+ "\t" +RED+ res['data'][0]['intelligence']['clamav'][i] +rst)
        print(plus+ " Analysis: " +BLUE+ "https://bazaar.abuse.ch/sample/" +res['data'][0]['sha256_hash']+ "/" +rst)
    else:
        m = "parsing the response"
        errSoft(m,res)
        return None


###################################################################################################
## MalShare Malware Library
def hashMS(hsh,token,url):
    print("\n[-] " +title+ "----- Checking MalShare for hash -----" +rst+ " [-]")

    # Build URL
    url = url+hsh
    
    # Query the API, parse the response into JSON
    # MalShare frequently takes a very long time, or never, responds
    # Timeout added to prevent this
    try:
        res = requests.get(url, timeout=15)
    except ValueError as e:
        m = "querying the API and parsing the resposne"
        errSoft(m,e)
        return None
    except requests.exceptions.ReadTimeout as e:
        m = "querying the API: the connection timed out"
        errSoft(m,e)
        return None

    
    # Conver the response to JSON
    try:
        resJS = json.loads(res.content.decode('utf-8'))
    except ValueError as e:
        m = "converting the response to JSON"
        errSoft(m,e)
        return None



    # Parse and display the results
    if len(resJS) == 0:
        print(bang+ " File is " +RED+ "NOT" +rst+ " in the MalShare library")
    elif 'sha1' in resJS[0]:
        print(plus+ " Arch type: " +RED +resJS[0]['type'] +rst)
        print(plus+ " Uploaded: " +RED +str(dt.datetime.fromtimestamp(resJS[0]['added'])) +rst)
        print(plus+ " Src URL: " +RED +resJS[0]['source'].replace('.','[DOT]') +rst)
        print(plus+ " Analysis: " +BLUE+ "https://malshare.com/search.php?query=" +hsh +rst)
    else:
        m = 'parsing the resposne'
        errSoft(m,res)
        return None

###################################################################################################
## Hybrid-Analysis Hash Reputation
def hashHA(hsh,token,url,ua,hType,hAccept):
    print("\n[-] " +title+ "----- Checking Hybrid-Analysis for hash -----" +rst+ " [-]")
    #  Either pass the URL query parameters apikey and secret or use 'Basic Auth' with the API key and secret as the username and password

    # Build the parts for the POST request
    tsNow = str(round(dt.datetime.now().timestamp()))
    postData = 'hash=' +hsh
    postHeaders = json.loads('{"accept":"' +hAccept+ '","user-agent":"' +ua+ '","Content-Type":"' +hType+ '","api-key":"' +token+ '"}')
    urlBuilt = "https://www.hybrid-analysis.com/api/v2/search/hash" #url#+tsNow
    # Query the API
    try:
        res = requests.post(urlBuilt, headers=postHeaders, data=postData).json()
    except ValueError as e:
        m = 'querying the API'
        errSoft(m,e)
        return None

    print(hsh)
    print(postData)
    print(res)
    # Has HA seen this file before?
    if 'verdict' in res:
        print(plus+ " Verdict: " +res[0]['verdict'])
        print(plus+ " AV Detetions: " +str(res[0]['av_detect']))
        print(plus+ " Threat Level: " +str(res[0]['threat_level']))
        print(plus+ " Malware Family: " +res[0]['vx_family'])
        print(plus+ " Analysis URL: " +BLUE+ "https://www.hybrid-analysis.com/sample/" +res[0]['sha256'] +rst)
    else:
        print(bang+ " File has " +RED+ "NOT" +rst+ " been analyzed by Hybrid Analysis")


###################################################################################################
## VirusTotal Hash Reputation
def hashVT(hsh,token,url):
    print("\n[-] " +title+ "----- Checking VirusTotal for hash -----" +rst+ " [-]")
    apiAuth = '{"x-apikey": "' +token+ '"}'
    hdrs = json.loads(apiAuth)

    # Query the API
    try:
        res = requests.get(url+hsh, headers=hdrs, timeout=15).content.decode('utf-8').strip()
    except ValueError as e:
        m= 'querying the API'
        errSoft(m,e)
        return None

    # Parse the response
    try:
        jsn = json.loads(res)
    except ValueError as e:
        m = 'converting the response to JSON'
        errSoft(m,e)
        return None

    # Test to see if the file has been seen by VT and if it was flagged by any engines
    dets = []
    unDets = []
    if 'error' in jsn and jsn["error"]["code"] == "NotFoundError":
        print(bang+ " File has " +RED+ "NOT" +rst+ " been analyzed by VirusTotal")
    else:
        try:
            dets = [i for i in jsn["data"]["attributes"]["last_analysis_results"] if jsn["data"]["attributes"]["last_analysis_results"][i]["category"] == "malicious"]
            unDets = [i for i in jsn["data"]["attributes"]["last_analysis_results"] if jsn["data"]["attributes"]["last_analysis_results"][i]["category"] == "undetected"]
        except ValueError as e:
            m ='loading the analysis results into lists'
            print(jsn)
            errSoft(m,e)
            return None

    # If there are more than 5 detections, only print the first 5 to prevent the screen from being blown out
    if len(dets) > 5:
        print(plus+ " Number of detections: " + str(len(dets)))
        examples = []
        print(plus+ " Example Types:")
        for i in range(0,5):
            print(plus+plus+ "\t" +dets[i]+ ": " +RED+ jsn["data"]["attributes"]["last_analysis_results"][dets[i]]["result"] +rst)
        print(plus+ " Analysis URL: " +BLUE+ "https://www.virustotal.com/gui/file/" +jsn["data"]["attributes"]["sha256"]+ "/detection" +rst)

    # If there are 5 of fewer detections, print all of them
    elif len(dets) > 0 and len(dets) < 6:
        print(plus+ " Number of detections: " +RED+str(len(dets))+rst)
        examples = []
        print(plus+ " Example Types:")
        for i in range(0,len(dets)):
            print(plus+plus+ "\t" +dets[i]+ ": " +RED+ jsn["data"]["attributes"]["last_analysis_results"][dets[i]]["result"] +rst)
        print(plus+ " Analysis URL: " +BLUE+ "https://www.virustotal.com/gui/file/" +jsn["data"]["attributes"]["sha256"]+ "/detection" +rst)

    # If the file has been analyzed and there were no hits from any engines
    elif len(dets) == 0 and len(unDets) > 0:
        print(plus+ " File was analyzed by " +GREEN +str(len(unDets)) +rst+ " engines and flagged by " +GREEN+ "NONE" +rst+ " of them")
        print(plus+ " Analysis URL: " +BLUE+ "https://www.virustotal.com/gui/file/" +jsn["data"]["attributes"]["sha256"]+ "/detection"+rst)

###################################################################################################
## Intezer Analysis Hash Analysis
def hashIA(hsh,token,url):
    print("\n[-] " +title+ "----- Checking Intezer Analyze for hash -----" +rst+ " [-]")
    print(bang+ " NOTE: You may receive a FALSE NEGATIVE if the query takes too long")
    try:
        response = requests.post(url + '/get-access-token', json={'api_key': token})
        response.raise_for_status()
        session = requests.session()
        session.headers['Authorization'] = session.headers['Authorization'] = 'Bearer %s' % response.json()['result']
    except ValueError as e:
        m = 'trying to get a session token'
        errSoft(m,e)
        return None

    try:
        res = session.get(url+ "/files/" +hsh).json()
    except ValueError as e:
        m = 'trying to search for the hash'
        errSoft(m,e)
        return None

    if 'error' in res:
        print(bang+ " File has " +RED+ "NOT" +rst+ " been analyzed by Intezer Analyze")
    elif res['result']['verdict'] == 'trusted':
        print(plus+ " Verdict: " +GREEN+ "TRUSTED" +rst)
        print(plus+ " Last Analyzed: " +RED+res['result']['analysis_time']+rst)
        print(plus+ " Analysis: " +BLUE+res['result']['analysis_url']+rst)
    elif res['result']['verdict'] == 'malicious':
        print(plus+ " Verdict: " +RED+res['result']['verdict']+rst)
        if "family_name" in res['result']:
            print(plus+ " Family: " +RED+res['result']['family_name']+rst)
        print(plus+ " Analysis: " +BLUE+res['result']['analysis_url']+rst)
    elif res['result']['verdict'] == "not_supported":
        print(bang+ " File not supported")
        print(bang+ " Reason: " +res['result']['sub_verdict'])
    elif res['result']['verdict'] == "suspicious":
        print(plus+ " Verdict: " +YELLOW+ "SUSPICIOUS" +rst)
        print(plus+ " Last Analyzed: " +RED+res['result']['analysis_time']+rst)
        print(plus+ " Analysis: " +BLUE+res['result']['verdict']+rst)
    elif res['result']['verdict'] == "unknown":
        print(plus+ " Verdict: " +YELLOW+ "UNKNOWN" +rst)
        print(plus+ " Subverdict: " +YELLOW+ res['result']['sub_verdict']+rst)
        print(plus+ " Last Analyzed: " +RED+res['result']['analysis_time']+rst)
        print(plus+ " Analysis: " +BLUE+res['result']['analysis_url']+rst)
    else:
        print(bang+ " Unrecognized response:")
        pprint.pprint(res)


