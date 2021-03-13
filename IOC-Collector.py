#!/usr/bin/python3


import os, time, re
from os import path
from datetime import datetime


'''
Author:		Jack Power
Desc:		A tool to allow you to manually add IOCs found to a local csv file
Version:	1.0
'''

# Initialize a folder to save these to
dir_name_initalize = '/' + datetime.today().strftime('%Y-%m-%d') + '/'	# Initiate the directory e.g. /2021-03-13/
try:
	create_folder_intialize = os.mkdir(os.getcwd() + str(dir_name_initalize))		# Create that directory if it doesn't exist
except FileExistsError:
	pass

path_to_daily_files = os.getcwd() + dir_name_initalize 

# Initialize all CSV files
file_name_initalize_IP = datetime.today().strftime('%Y-%m-%d') + "-IP-IOCs.csv"	# Initiate File name e.g 2021-03-13-IP-IOCs
file_name_initalize_Hash = datetime.today().strftime('%Y-%m-%d') + "-Hash-IOCs.csv"	# Initiate File name e.g 2021-03-13-Hash-IOCs
file_name_initalize_PF = datetime.today().strftime('%Y-%m-%d') + "-ProcessFile-IOCs.csv"	# Initiate File name e.g 2021-03-13-ProcessFile-IOCs
file_name_initalize_DNS = datetime.today().strftime('%Y-%m-%d') + "-DNS-IOCs.csv"	# Initiate File name e.g 2021-03-13-DNS-IOCs
# Initialize full paths to CSV files
full_path_to_csv_IP = path_to_daily_files + file_name_initalize_IP
full_path_to_csv_Hash = path_to_daily_files + file_name_initalize_Hash
full_path_to_csv_PF = path_to_daily_files + file_name_initalize_PF
full_path_to_csv_DNS = path_to_daily_files + file_name_initalize_DNS

def check_if_daily_files_created():
	# Check if each or any of the files exist for the current day
	if not path.exists(full_path_to_csv_IP):
		create_IP_CSV()
	if not path.exists(full_path_to_csv_Hash):
		create_Hash_CSV()
	if not path.exists(full_path_to_csv_PF):
		create_PF_CSV()
	if not path.exists(full_path_to_csv_DNS):
		create_DNS_CSV()
def create_IP_CSV():
	print('\t[+] Creating ' + str(full_path_to_csv_IP))
	time.sleep(0.5)
	csv_IP_file = open(full_path_to_csv_IP, 'w')
	csv_IP_file.write('IP Indicators of Compromise:\n')
	return csv_IP_file
def create_Hash_CSV():
	print('\t[+] Creating ' + str(full_path_to_csv_Hash))
	time.sleep(0.5)
	csv_Hash_file = open(full_path_to_csv_Hash, 'w')
	csv_Hash_file.write('Hash Indicators of Compromise:\n')
	return csv_Hash_file
def create_PF_CSV():
	print('\t[+] Creating ' + str(full_path_to_csv_PF))
	time.sleep(0.5)
	csv_PF_file = open(full_path_to_csv_PF, 'w')
	csv_PF_file.write('Process File Indicators of Compromise:\n')
	return csv_PF_file
def create_DNS_CSV():
	print('\t[+] Creating ' + str(full_path_to_csv_DNS))
	time.sleep(0.5)
	csv_DNS_file = open(full_path_to_csv_DNS, 'w')
	csv_DNS_file.write('DNS Indicators of Compromise:\n')
	return csv_DNS_file
# List Types of IOCs to submit (IP, Hash, Process File,  DNS Query)
def list_IOC_types():
	os.system('clear')
	print('|	Listing IOC Types 	|')
	print('\n')
	print('--------| Input| IOC Type |---') 
	print('------------------------------')
	print('[*]	| Ip   | IP Address')
	print('[*]	| Hs   | Hash Value')
	print('[*]	| Pf   | Process File')
	print('[*] 	| Dns  | DNS Query')
	print('------------------------------')
	print('\tq to quit')
	print('\n')
	choice = input('\033[1;32m IOC-Collector:~$ \033[0m')
	choose_IOC_type(choice)
def choose_IOC_type(choice):
	if choice == 'IP' or choice == 'Ip' or choice == 'ip':
		Add_IP_IOC()
	if choice == 'HS' or choice == 'Hs' or choice == 'hs':
		Add_Hash_IOC()
	if choice == 'PF' or choice == 'Pf' or choice == 'pf':
		Add_ProcessFile_IOC()
	if choice == 'DNS' or choice == 'Dns' or choice == 'dns':
		Add_DNS_IOC()
	if choice == 'q' or choice == 'Q':
		exit()
def Add_IP_IOC():
	print('\n| Enter IP Indicator |\n')
	ioc = input('\033[1;34m IOC-Collector:~$ \033[0m')
	ip_validation = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
	if(re.search(ip_validation, ioc)):
		print('[+] Adding ' + ioc + '...')
	else:
		print('[-] Error: Invalid IP')
		time.sleep(1.5)
		list_IOC_types()
	Add_IOC_to_IP_file(ioc)
	print('[*] IOC Added: ' + ioc)
	time.sleep(2.5)
	list_IOC_types()
def Add_Hash_IOC():
	print('\n| Enter Hash Indicator |\n')
	ioc = input('\033[1;34m IOC-Collector:~$ \033[0m')
	if verify_hash(ioc) == "Invalid":
		print('[!] Invalid Hash - Try Again')
		Add_Hash_IOC()
	time.sleep(0.5)
	Add_IOC_to_Hash_file(ioc)
	print('[*] IOC Added: ' + ioc)
	time.sleep(2.5)
	list_IOC_types()
def Add_ProcessFile_IOC():
	print('\n| Enter Process File Indicator |\n')
	ioc = input('\033[1;34m IOC-Collector:~$ \033[0m')
	Add_IOC_to_PF_file(ioc)
	print('[*] IOC Added: ' + ioc)
	time.sleep(2.5)
	list_IOC_types()
def Add_DNS_IOC():
	print('\n| Enter DNS Indicator |\n')
	ioc = input('\033[1;34m IOC-Collector:~$ \033[0m')
	if validate_url(ioc) == True:
		Add_IOC_to_DNS_file(ioc)
		print('[*] IOC Added: ' + ioc)
		time.sleep(0.9)
		list_IOC_types()
	else:
		print('[*] ' + ioc + ' not valid')
		time.sleep(1)
		Add_DNS_IOC()
	
# Add that IOC dailyIOC.csv, dailyIOC.xml, dailyIOC.txt
def Add_IOC_to_IP_file(ioc):
	# Write to CSV file
	csv_IP_file = open(full_path_to_csv_IP, 'a')
	csv_IP_file.write(ioc)
	csv_IP_file.write('\n')
	csv_IP_file.close()
def Add_IOC_to_Hash_file(ioc):
	# Write to CSV file
	csv_Hash_file = open(full_path_to_csv_Hash, 'a')
	csv_Hash_file.write(ioc)
	csv_Hash_file.write('\n')
	csv_Hash_file.close()
def Add_IOC_to_PF_file(ioc):
	# Write to CSV file
	csv_PF_file = open(full_path_to_csv_PF, 'a')
	csv_PF_file.write(ioc)
	csv_PF_file.write('\n')
	csv_PF_file.close()
def Add_IOC_to_DNS_file(ioc):
	# Write to CSV file
	csv_DNS_file = open(full_path_to_csv_DNS, 'a')
	csv_DNS_file.write(ioc)
	csv_DNS_file.write('\n')
	csv_DNS_file.close()
# Verify hash 
def verify_hash(hash):
	hashType = ""
	try:
		if len(hash) == 32:
			hashType = "MD5"
			return hashType
		if len(hash) == 40:
			hashTyoe = "SHA1"
			return hashType
		if len(hash)== 64:
			hashType = "SHA256"
			return hashType
		else:
			hashType = "Invalid"
			return hashType
	except Error:
		print('[!] Hash Length Error')
def validate_url(url):
	regex = ("[a-zA-Z0-9@:%._\\+~#?&//=]" +
             "{2,256}\\.[a-z]" +
             "{2,6}\\b([-a-zA-Z0-9@:%" +
             "._\\+~#?&//=]*)")
	p = re.compile(regex)

	if (url == None):
		x =  False
		return x

	if(re.search(p, url)):
		x = True
		return x
	else:
		x = False
		return x

def main():
	check_if_daily_files_created()
	list_IOC_types()

if __name__ == "__main__":
	main()
