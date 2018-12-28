#!/usr/bin/python3

""" 
	Python script to report bad IPs to AbuseIPDB in bulk
"""

__author__ = "Shubham Hibare"
__version__ = "2.0"
__maintainer__ = "Shubham Hibare"
__email__ = "shubham@hibare.in"

import requests
import csv
import sys
import os
import argparse
import ipaddress
import datetime
import string
import random
import json


# global variabled
steps = 100
tempDir = 'temp/'

# generate filename
def filenameGenerator(size=12, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
	"""
		Description: generate randon filename with .csv extension
		Input: size (optional), chars (opional)
		Return: filename
	"""
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


# function to prepare data
def prepData(inputFileName, category, comment):
	"""
		Description: prepates data to submit 
		Input: inputFileName - input file containing IPs, one per line (string)
			   category 	 - IP submission category (string)
			   comment 	 - comment for IP (string)
		Return: status and filenames list
	"""
	global steps
	global tempDir

	inputIPList = []
	validIPs = []
	invalidIPs = []
	fileNames = []
	fields = ['IP','Categories','ReportDate','Comment']
	
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
					
		for index in range(0, len(validIPs), steps):
            # get chunk of IPs
			ipsList = validIPs[index:index+steps]

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
				print("[!] Exception: "+str(e))

			finally:
				fileHandler.close()
		
		# print invalid IPs
		if len(invalidIPs) > 0:
			print("\n[!] Invalid IPs")
			for ip in invalidIPs:
				print(ip)

		return True, fileNames
	except Exception as e:
		return False, str(e)

# function to submit data
def submitData(filename, APIKey):
	"""
		Description: Submit prepared data to AbuseIPDB API endpoint
		Input: filname having prepared data and API key
		Return: None
	"""
	headers = {
		'Key': APIKey,
		'Accept': 'application/json',
	}

	files = {
		'csv': (filename, open(filename, 'rb')),
	}

	try:

		response = requests.post('https://api.abuseipdb.com/api/v2/bulk-report', headers=headers, files=files)

		resposeData = json.loads(response.text)
		
		if response.status_code == 200:

			if "errors" in resposeData.keys():
				print("\n[!] Error in processing file {}".format(filename))

			elif "data" in resposeData.keys():
				print("\n[!] Processed file {}".format(filename))
				print("Saved reports: {}".format(resposeData.get('data').get('savedReports')))

				errors = resposeData.get('data').get('invalidReports')

				if len(errors) > 0:
					print("[!] Error occurred for following IPs")
					for errorData in errors:
						print("{} - {}".format(errorData.get('input'), errorData.get('error')))
		
		else:
			print("\n[!] Error in request ... ")
			errors = resposeData.get('errors')
			for error in errors:
				print("{}".format(error.get('detail')))

	except Exception as e:
		print("[!] Exception: {}".format(e))


if __name__ == '__main__':
	# global tempDir

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

		category = input('\nEnter category separated by comma [ex: 18,22]: ')

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
			print("")
			# prep data 
			status, data = prepData(args.inputfilename, category, comment)
			
			if status:

				# check for data
				if len(data) > 0:
					# save current directory and change to temp directory
					cwd = os.getcwd()
					os.chdir(tempDir)

					try:
						# submit data
						for filename in data:
							submitData(filename, args.APIKey)
					except Exception as e:
						print("[!] Exception: {}".format(e))
					
					finally:
						os.chdir(cwd)
				else:
					print("\n[!] Nothing to submit")

			else:
				print("[!] Error: {}".format(data))

		else:
			print("abort")
	else:
		print("[!] Error : either the file [{0}] does not exists or is not readable".format(args.inputfilename))
	