#!/usr/bin/python3

""" 
	Python script to report bad IPs to AbuseIPDB in bulk
"""

__author__ = "Shubham Hibare"
__version__ = "1.0"
__maintainer__ = "Shubham Hibare"
__email__ = "shubham@hibare.in"

import requests
import json
import csv
import sys
import os
import argparse
import ipaddress
import time
import datetime
import string
import random

# generate filename
def filenameGenerator(size=6, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
    return ''.join(random.choice(chars) for _ in range(size))+".csv"

# function to validate an IP address
def validateIP(ipaddressToValidate):
	"""
		Description: validates an IP address
		Input: IP to be validated (string)
		Return: True or False (boolean)
	"""
	try:
		ipaddress.ip_address(ipaddressToValidate)
		return True
	except Exception as e:
		return False

def prepData(APIKey, inputFileName, category, comment):
	"""
		Description: post IPs to abuseIPDB
		Input: APIKey 		 - abuseIPDB API key (string)
			   inputFileName - input file containing IPs, one per line (string)
			   category 	 - IP submission category (string)
			   comment 	 - comment for IP (string)
		Return: none
	"""
	inputIPList = []
	validIPs = []
	invalidIPs = []
	fileNames = []
	fields = ['IP','Categories','ReportDate','Comment']
	step = 5
	tempDir = 'temp/'
	
	reportedDate = datetime.datetime.now().isoformat()

	try:

		# check for temporary directory
		if not os.path.exists(tempDir):
			os.mkdir(tempDir)

		# open input file and read all IPs in a list
		inputFile = open(inputFileName, 'r')
		inputIPList = inputFile.readlines()
		inputFile.close()

		# remove duplicates
		inputIPList = set(inputIPList)

		# loop through the input file
		for ip in inputIPList:
			
			ip = ip.rstrip('\n')
			
			if ip:
				if validateIP(ip):
					validIPs.append(ip)
				else:
					invalidIPs.append(ip)
					
		for index in range(0, len(validIPs), step):
            # get chunk of IPs
			ipsList = validIPs[index:index+step]

			try:
				# generate filename
				filename = filenameGenerator()
				fileNames.append(filename)

				# write IP list to file
				fileHandler = open(tempDir+filename, 'w')

				writer = csv.DictWriter(fileHandler, fieldnames=fields)

				writer.writeheader()

				for ip in ipsList:
					writer.writerow({'IP': str(ip), 'Categories': str(category), 'ReportDate': str(reportedDate), 'Comment': str(comment)})
			
			except Exception as e:
				print("Exception: "+str(e))

			finally:
				fileHandler.close()
		print(fileNames)
	except Exception as e:
		print("Exception : "+str(e))

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-k', '--APIKey', type=str, metavar='<AbuseIPDB API key>', help='Enter AbuseIPDB API key', required=True)
	parser.add_argument('-f', '--inputfilename', type=str, metavar='<input filename>', help='Input file name', required=True)
	args = parser.parse_args()
	
	# check if file exists and readable
	if os.path.isfile(args.inputfilename) and os.access(args.inputfilename, os.R_OK):
		reportingCategories = {
						3: 'Fraud Orders', 
						4: 'DDoS Attack', 
						5: 'FTP Brute-Force', 
						6: 'Ping of Death', 
						7: 'Phishing', 
						8: 'Fraud VoIP', 
						9: 'Open Proxy', 
						10: 'Web Spam', 
						11: 'Email Spam', 
						12: 'Blog Spam', 
						13: 'VPN IP', 
						14: 'Port Scan', 
						15: 'Hacking', 
						16: 'SQL Injection', 
						17: 'Spoofing', 
						18: 'Brute-Force', 
						19: 'Bad Web Bot', 
						20: 'Exploited Host', 
						21: 'Web App Attack', 
						22: 'SSH', 
						23: 'IoT Targeted'
					}
		
		# read category
		for key, value in reportingCategories.items():
			print("{0} -> {1}".format(key,value))

		category = input('Enter category separated by comma [ex: 18,22]: ')

		#validate input categories
		splitCategory = category.split(",")
		for cat in splitCategory:
			if cat.isdigit() and int(cat) >= 3 and int(cat)<=23:
				pass
			else:
				print("Invalid category: {0}".format(cat))
				sys.exit()


		# read comment
		comment = input('\nEnter comment: ')

		print("\nPlease verify:")
		print("Category: {0}".format(category))
		print("comment: {0}".format(comment))
		proced = input("\nContinue [y/n]? ")

		if proced == "y":
			# call getIPDetails function
			prepData(args.APIKey, args.inputfilename, category, comment)
		else:
			print("abort")
	else:
		print("Error : either the file [{0}] does not exists or is not readable".format(args.inputfilename))
	