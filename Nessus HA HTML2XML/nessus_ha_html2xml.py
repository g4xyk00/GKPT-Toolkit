#!/usr/bin/python

# Usage: python nessus_ha_html2xml.py nessus.html > nessus.xml
# Author: g4xyk00

import sys
import re

regexHTML = re.compile(r'<[^>]+>')

def remove_tags(text):
    return regexHTML.sub('', text)

filePath = sys.argv[1];
file = open(filePath)
flagFail = '#d43f3a' #d43f3a=FAILED, 3fae49=PASSED
flagCom = '<h6'
flagSec = 'details-header';
compliance = 0 # 1=FAILED, 2=SKIPPED, 3=PASSED
config = []
seq = ['info', 'solution', 'seealso', 'reference', 'audit', 'policy', 'host']
#0=Info, 1=Solution, 2=See Also, 3=References, 4=Audit File, 5=Policy Value, 6 = Host
startSeq = False
seqNum = -1;
redundant = '<div xmlns="" style="line-height: 20px; padding: 0 0 20px 0;">'

print "<configs>"

for line in file:
	if flagCom in line:
		compliance+=1

	if compliance < 2:
		if flagFail in line:
			if seqNum == len(seq)-1:
				print "</" + seq[seqNum] + ">"

			seqNum = -1
			print "<config>"
			print "<compliance>failed</compliance>"
			name = re.search('\">(.*)</', line)
			if name is not None:
				print "<name>" + name.group(1) + "</name>"
		
		if flagSec in line:
			line = ""
			if seqNum < len(seq)-1:
				if seqNum >= 0:
					print "</" + seq[seqNum] + ">"

				seqNum += 1
				startSeq = True
			else:
				seqNum = -1
				startSeq = False


		if seqNum >= 0:
			if startSeq == True:
				print "<" + seq[seqNum] + ">"
				startSeq = False

			if redundant in line:
				line.replace(redundant, "")
			
			if seqNum == 6:
				if "h2" in line:
					line = remove_tags(line).strip()
					print "\t<ip>" + line + "</ip>"
				else:
					line = remove_tags(line).strip()
					if len(line) > 0:
						print "\t<current>" + line + "</current>"

			else:
				line = remove_tags(line)
				line = line.strip()

				#print "DEBUG: ",seqNum
				if len(line) > 0:
					print "\t" + line


print "</" + seq[seqNum] + ">"
print "</config>"
print "</configs>"