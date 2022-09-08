#!/usr/bin/env python
import sys, subprocess, re
#global variable
ipPattern = re.compile(r'(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})')

def whoisIP(ipAdr): #run whois
	myCmd = ["whois", ipAdr]
	whoisData=[]
	ouput= subprocess.run(myCmd, capture_output=True, text=True)
	keepData=['NetRange:','CIDR:','NetName:','Organization:','Address:','City:','StateProv:','PostalCode:','Country:']
	results=ouput.stdout.split("\n")
	for line in results:
		for i in range(len(keepData)):
			if(line.startswith(keepData[i]) ):
				whoisData.append(line.strip())
	return whoisData
def hostName(webAdr):
	myCmd = ["host", webAdr]
	output=subprocess.run(myCmd, capture_output=True, text=True)
	ipAddr=output.stdout.split("\n")
	ip=ipPattern.search(ipAddr[0])[0]
	return ip
def nslookName(webAdr):
	nsInfo = []
	nsAInfo = []
	nsMXInfo = []
	nsNSInfo = []
	nsPTRInfo = []
	#A results
	myCmd = ["nslookup", "-type=a", webAdr]
	output=subprocess.run(myCmd, capture_output=True, text=True)
	results=output.stdout.split("\n")
	for line in results:
		if(line.startswith("Address:")):
			nsAInfo.append(line.strip())
	nsAInfo.pop(0)
	#MX results
	myCmd = ["nslookup", "-type=mx", webAdr]
	output=subprocess.run(myCmd, capture_output=True, text=True)
	results=output.stdout.split("\n")
	startLine = "Non-authoritative answer:"
	endLine = "Authoritative answers can be found from:"
	appendBool = False
	for line in results:
		if(line == startline):
			appendBool = True
		nsMXInfo.append(line.strip())
	print(nsMXInfo)
	
	
	
	return nsInfo


searchFor = sys.argv[1]
ipAdr = ''
webName = searchFor

hostReturn = hostName(webName)
ipAdr = hostReturn
print(hostReturn)
whoisReturn = whoisIP(ipAdr)
print(whoisReturn)
nsResult = nslookName(webName)
print(nsResult)

