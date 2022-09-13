#!/usr/bin/env python
'''
Run the script with the website you want to scan as an additional argument
additional argument "a", "all", or "more" (not case senestive) if you want 
to run a louder scan using nmap and theharvester aswell
'''
import sys, subprocess, re

moreResults = False

def whoisCMD(ipAdr): #run whois command
	myCmd = ["whois", ipAdr]
	whoisData=[]
	ouput= subprocess.run(myCmd, capture_output=True, text=True)
	keepData=['NetRange:','CIDR:','NetName:','Organization:','Address:','City:','StateProv:','PostalCode:','Country:']
	results=ouput.stdout.split("\n")
	for line in results:
		for i in range(len(keepData)):
			if(line.startswith(keepData[i]) ):
				addline = " ".join(line.split())
				whoisData.append(addline)
	return whoisData
def hostCMD(webAdr): #run host command
	hostInfo = []
	myCmd = ["host", webAdr]
	output=subprocess.run(myCmd, capture_output=True, text=True)
	results=output.stdout.split("\n")
	for line in results:
		if(line.strip() != ''):
			hostInfo.append(line.strip())
	return hostInfo
def nslookCMD(webAdr): #run nslookup command
	nslookInfo = []
	aInfo = []
	mxInfo = []
	nsInfo = []
	ptrInfo = []
	#A results
	myCmd = ["nslookup", "-type=a", webAdr]
	output=subprocess.run(myCmd, capture_output=True, text=True)
	results=output.stdout.split("\n")
	for line in results:
		if(line.startswith("Address:")):
			aInfo.append(line.strip())
	aInfo.pop(0)
	#MX results
	myCmd = ["nslookup", "-type=mx", webAdr]
	output=subprocess.run(myCmd, capture_output=True, text=True)
	results=output.stdout.split("\n")
	startLine = "Non-authoritative answer:"
	addBool = False
	for line in results:
		if(line == startLine):
			addBool = True
		if(addBool == True and line.strip() != ''):
				mxInfo.append(line.strip())
	if(mxInfo[-1] == "Authoritative answers can be found from:"):
		mxInfo.pop(-1)
	#NS results
	myCmd = ["nslookup", "-type=ns", webAdr]
	output=subprocess.run(myCmd, capture_output=True, text=True)
	results=output.stdout.split("\n")
	startLine = "Non-authoritative answer:"
	addBool = False
	for line in results:
		if(line == startLine):
			addBool = True
		if(addBool == True and line.strip() != ''):
				nsInfo.append(line.strip())
	#PTR info
	myCmd = ["nslookup", "-type=ptr", webAdr]
	output=subprocess.run(myCmd, capture_output=True, text=True)
	results=output.stdout.split("\n")
	startLine = "Non-authoritative answer:"
	addBool = False
	for line in results:
		if(line == startLine):
			addBool = True
		if(addBool == True and line.strip() != ''):
			ptrInfo.append(line.strip())
		if("mail addr =" in line):
			addBool = False		
	#combine all results	
	nslookInfo.append("A results")
	for i in range(len(aInfo)):
		nslookInfo.append(aInfo[i])
	nslookInfo.append("MX results")
	for i in range(len(mxInfo)):
		nslookInfo.append(mxInfo[i])
	nslookInfo.append("NS results")
	for i in range(len(nsInfo)):
		nslookInfo.append(nsInfo[i])
	nslookInfo.append("PTR results")
	for i in range(len(ptrInfo)):
		nslookInfo.append(ptrInfo[i])	
	return nslookInfo
def digCMD(webAdr): #run dig +short command
	myCmd = ["dig", "+short", webAdr]
	output=subprocess.run(myCmd, capture_output=True, text=True)
	digIP = str(output.stdout)
	return digIP.strip()
def nmapScan(ipAdr): #nmap scan with the ip address
	boolCapture = False
	capture = []
	myCmd = ["nmap", ipAdr]
	ouput= subprocess.run(myCmd, capture_output=True, text=True)
	results=ouput.stdout.split("\n")
	for line in results:
		if( boolCapture == True and line != "" ):
			capture.append(line.strip())
		if("PORT" in line):
			boolCapture = True
	if capture:
		capture.pop(-1)
	return capture
def theHarvester(domainName): #run theHarvester
	my_cmd=["theHarvester","-d",domainName,"-l","500","-b","bing"]
	output=subprocess.run(my_cmd,capture_output=True, text=True )
	result=output.stdout.split('\n')
	print("\n------------------------------\nresult from theHarvester using 'Bing' as the search Engine ")
	result=result[15:]
	results=""
	for i in range(len(result)):
		results+=result[i]
		results+='\n'
	print(results)
	return

webName = sys.argv[1]
if( len(sys.argv) >= 3 ):
	scanOpt = sys.argv[2]
	if(scanOpt.casefold() =="a".casefold() or scanOpt.casefold() =="all".casefold() or scanOpt.casefold() =="more".casefold()):
		moreResults = True
#used to compare the IPs from different commands
#uses the IP from dig as a baseline.
allSameIP = True
hostDigIP = True
hostNsIP = True
DigNsIP = True
ipPattern = re.compile(r'(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})')
#run the host, dig, nslookup commands
hostReturn = hostCMD(webName)
digReturn = digCMD(webName)
nsResult = nslookCMD(webName)
hostIP = ipPattern.search(hostReturn[0])[0]
nsIP = ipPattern.search(nsResult[1])[0]
#run the whois command/commands
whoisDig = whoisCMD(digReturn)
#if all IPs are the same only require 1 whois result (uses ip from dig)
if(digReturn == hostIP and digReturn == nsIP):
	allSameIP = True
else:
	#if not check to see which ones don't match (start with the ip from host)
	if(hostIP != digReturn):
		hostDigIP = False
		whoisHost = whoisCMD(hostIP)
	#check if the ip from nslookup matches the ones from both dig and host
	if(hostIP != nsIP):
		hostNsIP = False
	if(digReturn != nsIP):
		DigNsIP = False
	if(hostNsIP == False and DigNsIP == False):
		whoisNS = whoisCMD(nsIP)
if(moreResults == True):
	nmapReturn1 = nmapScan(digReturn)
	if(digReturn != hostIP):
		nmapReturn2 = nmapScan(hostIP)
print("\nDIG cmd result\n" + '\t'+digReturn)
print("HOST cmd result")
for i in range(len(hostReturn)):
	print('\t'+hostReturn[i])
print("NSLOOKUP cmd result")
for i in range(len(nsResult)):
	if(nsResult[i] == "A results" or nsResult[i] == "MX results" or nsResult[i] == "NS results" or nsResult[i] == "PTR results"):
		print('\t'+nsResult[i])
	else:
		print('\t\t'+nsResult[i])
print("WHOIS (" + digReturn+")")
for i in range(len(whoisDig)):
	print('\t'+whoisDig[i])
#if the other IP addresses dont match the one from dig output their whois data as well
if(allSameIP == False):
	if(hostDigIP == False):
		print("WHOIS (" + hostIP+")")
		for i in range(len(whoisHost)):
			print('\t'+whoisHost[i])
	if(DigNsIP == False and hostNsIP == False):
		print("WHOIS (" + hostIP+")")
		for i in range(len(whoisNS)):
			print('\t'+whoisNS[i])
if(moreResults == True):
	print("\n--------------------More scan results--------------------\n")
	print("NAMP scan (" + digReturn + ")")
	for i in range(len(nmapReturn1)):
		print("\t"+nmapReturn1[i])
	if(digReturn != hostIP):
		print("NAMP scan (" + hostIP + ")")
		for i in range(len(nmapReturn2)):
			print('\t'+nmapReturn2[i])
	theHarvester(webName)
