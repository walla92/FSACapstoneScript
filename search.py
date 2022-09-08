#!/usr/bin/env python
import sys, subprocess, re
#global variable
ipPattern = re.compile(r'(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})')

def whoisCMD(ipAdr): #run whois
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
def hostCMD(webAdr):
	hostInfo = []
	myCmd = ["host", webAdr]
	output=subprocess.run(myCmd, capture_output=True, text=True)
	results=output.stdout.split("\n")
	for line in results:
		if(line.strip() != ''):
			hostInfo.append(line.strip())
	return hostInfo
def nslookCMD(webAdr):
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
def digCMD(webAdr):
	myCmd = ["dig", "+short", webAdr]
	output=subprocess.run(myCmd, capture_output=True, text=True)
	digIP = str(output.stdout)
	return digIP.strip()


webName = sys.argv[1]
hostReturn = hostCMD(webName)
digReturn = digCMD(webName)
nsResult = nslookCMD(webName)
hostIP = ipPattern.search(hostReturn[0])[0]
whoisHost = whoisCMD(hostIP)
whoisDig = whoisCMD(digReturn)

print("DIG cmd result\n" + '\t'+digReturn)
print("HOST cmd result")
for i in range(len(hostReturn)):
	print('\t'+hostReturn[i])
print("WHOIS (" + digReturn+")")
for i in range(len(whoisDig)):
	print('\t'+whoisDig[i])
if(digReturn != hostIP):
	print("WHOIS (" + hostIP+")")
	for i in range(len(whoisHost)):
		print('\t'+whoisHost[i])
print("NSLOOKUP cmd result")
for i in range(len(nsResult)):
	if(nsResult[i] == "A results" or nsResult[i] == "MX results" or nsResult[i] == "NS results" or nsResult[i] == "PTR results"):
		print('\t'+nsResult[i])
	else:
		print('\t\t'+nsResult[i])
