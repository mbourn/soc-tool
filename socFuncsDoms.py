# By: Matthew Bourn
# On: 2020-10-20
# ©: GNU GPLv3
# Do: at your own risk; copy, modify, share, give me a nod.  Don't sell.

# TODO: analytics27.techsmith.com breaks VT


# DOMAINS #
###################################################################################################
##### Imports #####
###################################################################################################

## Standard Modules
import re
import sys
import json
import requests
import datetime as dt

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

## Univerasal Reputation Checker IOC Lists
def genIL(ioc,token,url):
    print("\n[-] " +title+ "----- Checking IOC Lists for Atomic -----" +rst+ " [-]")
    apiAuth = '{"X-API-KEY": "' +token+ '","accept":"application/json"}'
    hdrs = json.loads(apiAuth)
    urlFull = url+ioc

    tags = []
    descs = []
    feeds = []

    # Query the API
    try:
        res = requests.get(urlFull, headers=hdrs)
    except ValueError as e:
        m = " querying the API"
        errSoft(m,e)
        return None

    # Parse reply into JSON
    try:
        resJS = json.loads(res.content.decode('utf-8'))
    except ValueError as e:
        m = " parsing the response into JSON"
        errSoft(m,e)
        return None

    # Display the results
    # If the response is not what we expected
    if "search_results" not in resJS:
        print(resJS)
        m = " the response: unrecognized format"
        errSoft(m,resJS)

    # If the query worked but there were no results
    elif len(resJS['search_results']) == 0:
        print(plus+GREEN+ " NO" +rst+ " IOC Lists sources have flagged this atomic")

    # Otherwise display the results
    else:
        for i in resJS['search_results']:
            # Get the pieces
            ts = re.findall(r"#(\w+)",i['raw'])
            ds = re.findall(r"--.*$",i['raw'])

            # Put the pieces into their lists
            feeds.append(i['feedname'])
            for t in ts:
                tags.append(t)
            for d in ds:
                descs.append(d)
        
        # Remove the repeat entries
        tags = list(set(tags))
        descs = list(set(descs))
        feeds = list(set(feeds))

        # Print the results
        ## Tags
        print(plus+ " Number of tags: " +RED+str(len(tags))+rst)
        if len(tags) > 0 and len(tags) < 6:
            for i in tags:
                print(plus+plus+RED+ "\t#" +i+rst)
        elif len(tags) > 5:
            for i in range(0,5):
                print(plus+plus+RED+ "\t#" +tags[i]+rst)

        ## Descriptions
        ### If there's Cyrillic, don't display it
        print(plus+ " Number of descriptions: " +RED+str(len(descs))+rst)
        if len(descs) > 0 and len(descs) < 6:
            for i in descs:
                if re.search('[а-яА-Я]',i):
                    print(plus+plus+ "\t" +re.findall(r"/.*$",i)[0])
                else:
                    print(plus+plus+ "\t" +i)
        elif len(descs) > 5:
            for i in range(0,5):
                if re.search('[а-яА-Я]',descs[i]):
                    print(plus+plus+ "\t" +re.findall(r"/.*$",descs[i])[0])
                else:
                    print(plus+plus+ "\t" +descs[i])

        ## Feeds
        print(plus+ " Number of feeds: " +RED+str(len(feeds))+rst)
        if len(feeds) > 0 and len(feeds) < 6:
            for i in feeds:
                print(plus+plus+ "\tFound in feed: " +RED+i+rst)
        elif len(feeds) > 5:
            for i in range(0,5):
                print(plus+plus+ "\tFound in feed: " +RED+feeds[i]+rst)





###################################################################################################
## VirusTotal Domain Reputation
def domVT(dom,token,url):
    print("\n[-] " +title+ "----- Checking Virus Total for Domain -----" +rst+ " [-]")
    
    # Create auth header
    apiAuth = '{"x-apikey": "' +token+ '"}'
    hdrs = json.loads(apiAuth)

    # Strip HTTP(S):// from domain if present and trailing "/"
    dom = re.sub("http://", "", dom, flags=re.I)
    dom = re.sub("https://", "", dom, flags=re.I)
    if "/" in dom[-1:]:
        dom = dom[:-1]


    # Get basic info from the API
    try:
        res = requests.get(url+dom, headers=hdrs)
    except ValueError as e:
        m = 'querying the API for basic domain info'
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
    if "error" in resJS:
        print(bang+ " An error was returned from the API")
        print(bang+ " " +resJS['error']['message'])
        return None
    elif "whois" in resJS['data']['attributes'] and resJS['data']['attributes']['whois'] is not "":
        print(plus+ " Select WHOIS Info")
        for i in resJS['data']['attributes']['whois'].split('\n'):
            if i.split(":")[0] in ['CIDR','RegDate','OrgName','City','Country','Domain Status','Creation Date']:
                print(plus+plus+ "\t" +i)
    else:
        print(plus+ GREEN+" No WHOIS Data" +rst+ " Available from VirusTotal")

    # Print categories
    if "creation_date" in resJS['data']['attributes'] and resJS['data']['attributes']['creation_date'] is not "":
        print(plus+ " Registered: " +RED +str(dt.datetime.fromtimestamp(resJS['data']['attributes']['creation_date'])) +rst)
    
    if "categories" in resJS['data']['attributes'] and len(resJS['data']['attributes']['categories']) > 0:
        print(plus+ " Categories: ")
        for i in resJS['data']['attributes']['categories']:
            print(plus+plus+ "\t" +i+ " - " +RED+resJS['data']['attributes']['categories'][i]+rst)

    # Print stats
    cats = ["harmless","malicious","suspicious"]
    print(plus+ " Statistics:")
    for i in cats:
        if i == "malicious" and resJS['data']['attributes']['last_analysis_stats'][i] > 0:
            print(plus+plus+ "\t" +i+ ": " +RED+str(resJS['data']['attributes']['last_analysis_stats'][i])+rst)
        elif i == "malicious" and resJS['data']['attributes']['last_analysis_stats'][i] == 0:
            print(plus+plus+ "\t" +i+ ": " +GREEN+str(resJS['data']['attributes']['last_analysis_stats'][i])+rst)
        elif i == "suspicious" and resJS['data']['attributes']['last_analysis_stats'][i] > 0:
            print(plus+plus+ "\t" +i+ ": " +RED+str(resJS['data']['attributes']['last_analysis_stats'][i])+rst)
        elif i == "suspicious" and resJS['data']['attributes']['last_analysis_stats'][i] == 0:
            print(plus+plus+ "\t" +i+ ": " +GREEN+str(resJS['data']['attributes']['last_analysis_stats'][i])+rst)
        elif i == "harmless" and resJS['data']['attributes']['last_analysis_stats'][i] > 0:
            print(plus+plus+ "\t" +i+ ": " +GREEN+str(resJS['data']['attributes']['last_analysis_stats'][i])+rst)
        elif i == "harmless" and resJS['data']['attributes']['last_analysis_stats'][i] == 0:
            print(plus+plus+ "\t" +i+ ": " +RED+str(resJS['data']['attributes']['last_analysis_stats'][i])+rst)

    # Community thoughts on the IP
    if resJS['data']['attributes']['total_votes']['malicious'] > 0:
        print(plus+ ' Community votes of "Malicious": ' +RED+ str(resJS['data']['attributes']['total_votes']['malicious'])+rst)
    else:
        print(plus+ ' Community votes of "Malicious": ' +GREEN+ str(resJS['data']['attributes']['total_votes']['malicious'])+rst)

    # Get sources flagging domain as malicious
    if resJS['data']['attributes']['last_analysis_stats']['malicious'] > 0:
        dets = []
        unDets = []
        if 'error' in resJS and resJS["error"]["code"] == "NotFoundError":
            print(bang+ " Domain has " +RED+ "NOT" +rst+ "been analyzed by VirusTotal")
        else:
            try:
                dets = [i for i in resJS["data"]["attributes"]["last_analysis_results"] if resJS["data"]["attributes"]["last_analysis_results"][i]["category"] == "malicious"]
                unDets = [i for i in resJS["data"]["attributes"]["last_analysis_results"] if resJS["data"]["attributes"]["last_analysis_results"][i]["category"] == "undetected"]
            except ValueError as e:
                m ='loading the analysis results into lists'
                print(resJS)
                errSoft(m,e)
                return None

        # If there are more than 5 detections, only print the first 5 to prevent the screen from being blown out
        if len(dets) > 5:
            print(plus+ " Number of detections: " + str(len(dets)))
            examples = []
            print(plus+ " Example Types:")
            for i in range(0,5):
                print(plus+plus+ "\t" +dets[i]+ ": " +RED+ resJS["data"]["attributes"]["last_analysis_results"][dets[i]]["result"] +rst)
            #print(plus+ " Analysis URL: " +BLUE+ "https://www.virustotal.com/gui/file/" +resJS["data"]["attributes"]["sha256"]+ "/detection" +rst)

        # If there are 5 of fewer detections, print all of them
        elif len(dets) > 0 and len(dets) < 6:
            print(plus+ " Number of detections: " +RED+str(len(dets))+rst)
            examples = []
            print(plus+ " Example Types:")
            for i in range(0,len(dets)-1):
                print(plus+plus+ "\t" +dets[i]+ ": " +RED+ resJS["data"]["attributes"]["last_analysis_results"][dets[i]]["result"] +rst)
            #print(plus+ " Analysis URL: " +BLUE+ "https://www.virustotal.com/gui/file/" +resJS["data"]["attributes"]["sha256"]+ "/detection" +rst)

    # Get communicating files
    try:
        res = requests.get(url+dom+ "/communicating_files", headers=hdrs)
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

    print(plus+ BLUE+ " https://www.virustotal.com/gui/domain/" +dom+ "/detection" +rst)

###################################################################################################
## WhoisXML Domain Reputations
def domWX(dom,token,url):
    print("\n[-] " +title+ "----- Checking WhoisXML for Domain -----" +rst+ " [-]")

    # Create auth header
    args = '{"apiKey": "' +token+ '","domainName": "' +dom+ '"}'
    hdrs = json.loads(args)
    urlFull = url+token+ "&domainName=" +dom

    # Get basic info from the API
    try:
        res = requests.get(urlFull)
    except ValueError as e:
        m = 'querying the API for basic domain info'
        errSoft(m,e)
        return None

    # Parse the response into JSON
    try:
        resJS = json.loads(res.content.decode('utf-8'))
    except ValueError as e:
        m = 'trying to parse the response into JSON'
        errSoft(m,e)
        return None

    if "code" in resJS:
        m = "querying the API"
        errSoft(m,resJS['messages'])
        return None

    # Display results
    print(plus+ " Reputation score (lower is worse):")
    if resJS['reputationScore'] < 65:
        print(plus+plus+RED+ "\t" + str(resJS['reputationScore']) +rst)
    elif resJS['reputationScore'] > 64 and resJS['reputationScore'] < 85:
        print(plus+plus+YELLOW+ "\t" + str(resJS['reputationScore']) +rst)
    elif resJS['reputationScore'] > 84:
        print(plus+plus+GREEN+ "\t" + str(resJS['reputationScore']) +rst)
    else:
        print(bang+ " Something went wrong")
        print(resJS)

    for i in resJS['testResults']:
        if i['test'] == "WHOIS Domain check":
            print(plus+ " Warnings:")
            for j in i['warnings']:
                print(plus+plus+RED+ "\t" +j+rst)

###################################################################################################
## Hybrid-Analysis Domain Lookup
def domHA(dom,token,sec,ua,url):
    print("\n[-] " +title+ "----- Checking Hybrid-Analysis for Domain -----" +rst+ " [-]")
    hdrs = {'User-Agent': ua}

    # Strip HTTP(S):// from domain if present
    dom = re.sub("http://", "", dom, flags=re.I)
    dom = re.sub("https://", "", dom, flags=re.I)
    urlFull = url+ "domain:" +dom

    # Create session and send query
    try:
        session = requests.Session()
        session.auth = (token, sec)
        res = session.get(urlFull, headers = hdrs)
    except ValueError as e:
        m = " creating the session object and sending the query"
        errSoft(m,e)
        return None

    # Convert resposne to JSON
    try:
        resJS = json.loads(res.content.decode('utf-8'))
    except ValueError as e:
        m = " converting resposne to JSON"
        errSoft(m,e)
        return None

    # Parse and print output
    if len(resJS['response']['result']) == 0:
        print(plus+GREEN+ " No malicious files" +rst+ " are known to Hybrid-Analysis to communicate with this domain")
    elif len(resJS['response']['result']) > 0 and len(resJS['response']['result']) < 6:
        print(plus+ " Communicating file: " +RED+ str(len(resJS['response']['result']))+rst)
        for i in resJS['response']['result']:
            print(plus+ " File Name: " +RED+i['submitname']+rst)
            print(plus+plus+ "\tMalware Family: " +RED+str(i['vxfamily'])+rst)
            print(plus+plus+ "\tThreat Score: " +RED+str(i['threatscore'])+rst)
            print(plus+plus+ "\tURL: " +BLUE+ "https://www.hybrid-analysis.com/sample/" +i['sha256']+rst)
    elif len(resJS['response']['result']) > 5:
        print(plus+ " Communicating file: " +RED+ str(len(resJS['response']['result']))+rst)
        for i in range(0,4):
            print(plus+ " File Name: " +RED+resJS['response']['result'][i]['submitname']+rst)
            print(plus+plus+ "\tMalware Family: " +RED+str(resJS['response']['result'][i]['vxfamily'])+rst)
            print(plus+plus+ "\tThreat Score: " +RED+str(resJS['response']['result'][i]['threatscore'])+rst)
            print(plus+plus+ "\tURL: " +BLUE+ "https://www.hybrid-analysis.com/sample/" +resJS['response']['result'][i]['sha256']+rst)

###################################################################################################
## PhishTank Domain Reputation
def domPT(dom,token,ua,url):
    print("\n[-] " +title+ "----- Checking PhishTank for Domain -----" +rst+ " [-]")

    # Make sure the domain starts with "http://"
    if not dom.startswith("http"):
        print(bang+ " Adding " +RED+"'http://'"+rst+ " to the domain string")
        dom = "http://" +dom

    # Build the headers
    hdrs = {"User-Agent": ua}
    urlFull = url+dom
    pData = {'url': dom, 'format': 'json', 'app_key': token}

    # Query the API
    try:
        res = requests.post(urlFull, headers = hdrs, data = pData)
    except ValueError as e:
        m = " querying the API"
        errSoft(m,e)
        return None

    # Parse the results into JSON
    try:
        resJS = json.loads(res.content.decode('utf-8'))
    except ValueError as e:
        m = " parsing the results into JSON"
        errSoft(m,e)
        return None

    # Display the results
    if "results" not in resJS:
        m = " sending request"
        errSoft(m,resJS)
        return None

    elif resJS['results']['in_database'] == False:
        print(bang+ " The domain has " +RED+ "NOT been analyzed" +rst+ " by PhishTank")
    elif resJS['results']['valid'] == True:
        print(plus+ " Confirmed: " +RED+ "Phishing Domain" +rst)
        print(plus+plus+ "Analyzed on: " +resJS['results']['verified_at'])
        print(plus+plus+BLUE+ "\t" +resJS['results']['phish_detail_page']+rst)
    elif resJS['results']['valid'] == False and resJS['results']['in_database']:
        print(plus+ " Domain has been seen by PhishTank, but is " +YELLOW+ "UNCONFIRMED"+rst)
        print(plus+plus+BLUE+ resJS['results']['phish_detail_page']+rst)
    else:
        m = " parsing the results"
        errSoft(m,resJS)
        return None


