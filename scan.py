#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys, requests, socket
from pprint import pprint

# Models for the script.

class Site:
	# Represents a site.

	def __init__(self, Name, Host, Icon):
		self.Name   = Name
		self.Host   = Host
		self.Icon   = Icon

class Result:
	# Represents an endpoint evaluation.

	def __init__(self, Site, Grade, SSLv3, TLSv12, SHA1, RC4, PFS, POODLE, Heartbleed, FREAK, Logjam, SCSV, HSTS, EV):
		self.Site       = Site
		self.Grade      = Grade
		self.SSLv3      = SSLv3
		self.TLSv12     = TLSv12
		self.SHA1       = SHA1
		self.RC4        = RC4
		self.PFS        = PFS
		self.POODLE     = POODLE
		self.Heartbleed = Heartbleed
		self.FREAK      = FREAK
		self.Logjam     = Logjam
		self.SCSV       = SCSV
		self.HSTS       = HSTS
		self.EV         = EV

# Global variables.

API = "https://api.ssllabs.com/api/v2/"

Sites = [
	#     Name                   Hostname                                    Favicon
	Site('BT',                  'ib.btrl.ro',                               'https://www.bancatransilvania.ro/favicon.ico'),
	Site('ING',                 'homebank.ro',                              'https://www.ing.ro/favicon.ico'),
	Site('BRD',                 'mybrdnet.ro',                              'https://www.brd.ro/sites/all/themes/webtheme/images/favicon.ico'),
	Site('BCR',                 '24banking.ro',                             'https://www.bcr.ro/content/8ea9dd8a/-3b9c-429b-9f72-34e75b7512e3/favicon.ico'),
	Site('Raiffeisen',          'raiffeisenonline.ro',                      'https://www.raiffeisen.ro/wps/contenthandler/!ut/p/digest!XHR_M-Rzf5C6GQ6vQGPqEA/dav/fs-type1/themes/ibm.portal.RZBInternet.80Theme/images/favicon.ico'),
	Site('CEC',                 'www.ceconline.ro',                         'https://www.cec.ro/favicon.ico'),
	Site('OTP',                 'otpdirekt.otpbank.ro',                     'https://otpdirekt.otpbank.ro/favicon.ico'),
	Site('UniCredit Tiriac',    'ro.unicreditbanking.net',                  'https://www.unicredit-tiriac.ro/etc/designs/cee2020-pws-ro/favicon.ico'),
	Site('Volksbank',           'www.volksbankromania.ro',                  'http://www.volksbank.ro/favicon.ico'),
	Site('AlphaBank',           'www.alphaclick.ro',                        'https://www.alphabank.ro/favicon.ico'),
	Site('Bancpost',            'fastbanking.bancpost.ro',                  'https://www.bancpost.ro/Images/icon-bancpost.png'),
	Site('Piraeus',             'www.piraeusbank.com',                      'http://www.piraeusbank.ro/Images/icon.png'),
	Site('Credit Europe',       'net.crediteurope.ro',                      'https://www.crediteurope.ro/favicon.gif'),
	Site('Banca Romaneasca',    'ib.brom.ro',                               'https://www.banca-romaneasca.ro/favicon.ico'),
	Site('GarantiBank',         'ebank.garantibank.ro',                     'http://www.garantibank.ro/favicon.ico'),
	Site('Intesa Sanpaolo',     'internetbanking.intesasanpaolobank.ro',    'https://www.intesasanpaolobank.ro/favicon.ico'),
	Site('Carpatica',           'e-smart.carpatica.ro',                     'https://www.carpatica.ro/wp-content/themes/carpatica/images/favicon.ico'),
	Site('Marfin',              'ebanking.marfinbank.ro',                   'http://www.marfinbank.ro/favicon.ico'),
	Site('Libra',               'secure.internetbanking.ro',                'http://www.librabank.ro/favicon.ico'),
	Site('Banca Feroviara',     'bcfonline.bfer.ro',                        'http://www.bancaferoviara.ro/favicon.ico'),
]

# Methods for interacting with the SSL Labs API.

def request(path, payload = {}):
	# Sends a request to the global endpoint.

	url = API + path
	response = requests.get(url, params=payload)
	data = response.json()

	return data

def analyze(host, publish = "off", maxAge = 12, all = "done"):
	# Starts an analysis on the endpoint, if one was not done within the last maxAge hours.

	path = "analyze"
	payload = {'host': host, 'publish': publish, 'maxAge': maxAge}
	data = request(path, payload)

	return data

def getEndpointData(host, s = None):
	# Fetches the results of the analysis for the specified endpoint.

	if s is None:
		s = socket.gethostbyname(host)

	path = "getEndpointData"
	payload = {'host': host, 's': s}
	data = request(path, payload)

	return data

def info():
	# Fetches usage information from the API.

	path = "info"
	data = request(path)

	return data

# Batch scanning helper methods and parser functions.

def parseEndpointObject(site, data):
	# Parses the Endpoint object returned by the API and extracts the relevant information.

	if data.get('progress', 0) != 100:
		return None

	return Result(
		# Metadata
		site, data['grade'],
		# True if server does not support SSLv3
		not any(prot['name'] == 'SSL' for prot in data['details']['protocols']),
		# True if server supports TLSv1.2
		any(prot['id'] == 771 for prot in data['details']['protocols']),
		# True if certificate is not signed with SHA1
		data['details']['cert']['sigAlg'] != 'SHA1withRSA',
		# True if RC4 is not supported
		not data['details']['supportsRc4'],
		# True if Forward Secrecy is supported with most browsers
		data['details']['forwardSecrecy'] == 2 or data['details']['forwardSecrecy'] == 4,
		# True if not vulnerable to POODLE
		not data['details']['poodle'] and data['details']['poodleTls'] != 2,
		# True if not vulnerable to Heartbleed
		not data['details']['heartbleed'],
		# True if not vulnerable to FREAK
		not data['details']['freak'],
		# True if not vulnerable to Logjam
		not data['details'].get('logjam', False),
		# True if server supports TLS_FALLBACK_SCSV
		data['details'].get('fallbackScsv', False),
		# True if server sends HSTS
		not not data['details'].get('stsResponseHeader', None),
		# True if cert is EV
		data['details']['cert'].get('validationType', None) == 'E'
	)

def printTabulated(res):
	# Prints the values from the specified Result argument into a tab-separated format.

	if not hasattr(res, 'Site'):
		print 'test failed'
		return

	print '=image("' + res.Site.Icon + '", 4, 16, 16)\t' +\
		  '=hyperlink("https://www.ssllabs.com/ssltest/analyze.html?d=' + res.Site.Host + '","' + res.Site.Name + '")\t' +\
		  res.Grade + '\t' +\
		  ('Fail', 'Pass')[res.SSLv3]      + '\t' +\
		  ('Fail', 'Pass')[res.TLSv12]     + '\t' +\
		  ('Fail', 'Pass')[res.SHA1]       + '\t' +\
		  ('Fail', 'Pass')[res.RC4]        + '\t' +\
		  ('Fail', 'Pass')[res.PFS]        + '\t' +\
		  ('Fail', 'Pass')[res.POODLE]     + '\t' +\
		  ('Fail', 'Pass')[res.Heartbleed] + '\t' +\
		  ('Fail', 'Pass')[res.FREAK]      + '\t' +\
		  ('Fail', 'Pass')[res.Logjam]     + '\t' +\
		  ('Fail', 'Pass')[res.SCSV]       + '\t' +\
		  ('Fail', 'Pass')[res.HSTS]       + '\t' +\
		  ('Fail', 'Pass')[res.EV]

# CLI handler methods.

def printUsage():
	# Prints usage information.

	print 'usage: ' + sys.argv[0] + ' [start|info|collect]'

def printInfo():
	# Prints usage information from the API.

	inf = info()
	print 'assessments: ' + str(inf['currentAssessments']) + '/' + str(inf['maxAssessments'])

def startScans():
	# Starts the scan of all configured hosts.

	for site in Sites:
		print 'Starting scan of ' + site.Name + '...'
		analyze(site.Host)

def collectScans():
	# Collects the analysis results for all configured hosts.

	for site in Sites:
		res  = parseEndpointObject(site, getEndpointData(site.Host))

		if res is None:
			printTabulated(site)
		else:
			printTabulated(res)

# Entry point of the application.

if __name__ == "__main__":
	if len(sys.argv) < 2:
		printUsage()
	elif sys.argv[1] == 'start':
		startScans()
	elif sys.argv[1] == 'info':
		printInfo()
	elif sys.argv[1] == 'collect':
		collectScans()
	else:
		printUsage()
