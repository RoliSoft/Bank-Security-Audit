#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys, requests, socket
from pprint import pprint

# Models for the script.

class Site:
	"""
	Represents a site.
	"""

	def __init__(self, Name, Host, Icon, Error = ''):
		self.Name   = Name
		self.Host   = Host
		self.Icon   = Icon
		self.Error  = Error

class Result:
	"""
	Represents an endpoint evaluation.
	"""

	def __init__(self, Site, Grade, Score, SSLv3, TLSv12, SHA1, RC4, PFS, POODLE, Heartbleed, FREAK, Logjam, SCSV, HSTS, EV):
		self.Site       = Site
		self.Grade      = Grade
		self.Score      = Score
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

QualysAPI  = 'https://api.ssllabs.com/api/v2/'
MozillaAPI = 'https://http-observatory.security.mozilla.org/api/v1/'

Sites = [
	#     Name                   Hostname                                    Favicon
	Site('BT',                  'ib.btrl.ro',                               'https://www.bancatransilvania.ro/favicon.ico'),
	Site('ING',                 'www.homebank.ro',                          'https://www.ing.ro/favicon.ico'),
	Site('BRD',                 'mybrdnet.ro',                              'https://www.brd.ro/sites/all/themes/webtheme/images/favicon.ico'),
	Site('BCR',                 '24banking.ro',                             'https://www.bcr.ro/content/dam/ro/bcr/common/bcr-favicon.ico'),
	Site('Raiffeisen',          'www.raiffeisenonline.ro',                  'https://www.raiffeisen.ro/favicon.ico'),
	Site('CEC',                 'www.ceconline.ro',                         'https://www.cec.ro/favicon.ico'),
	Site('OTP',                 'www.otpdirekt.ro',                         'https://www.otpbank.ro/assets/img/favicon.ico'),
	Site('UniCredit Tiriac',    'ro.unicreditbanking.net',                  'https://www.unicredit-tiriac.ro/etc/designs/cee2020-pws-ro/favicon.ico'),
	Site('AlphaBank',           'www.alphaclick.ro',                        'https://www.alphabank.ro/favicon.ico'),
	Site('Bancpost',            'fastbanking.bancpost.ro',                  'https://www.bancpost.ro/Images/icon-bancpost.png'),
	Site('Piraeus',             'www.piraeusbank.com',                      'http://www.piraeusbank.ro/Images/icon.png'),
	Site('Credit Europe',       'net.crediteurope.ro',                      'https://www.crediteurope.ro/favicon.gif'),
	Site('Banca Romaneasca',    'ib.brom.ro',                               'https://www.banca-romaneasca.ro/favicon.ico'),
	Site('GarantiBank',         'ebank.garantibank.ro',                     'http://www.garantibank.ro/favicon.ico'),
	Site('Intesa Sanpaolo',     'internetbanking.intesasanpaolobank.ro',    'https://www.intesasanpaolobank.ro/favicon.ico'),
	Site('Carpatica',           'e-smart.carpatica.ro',                     'https://www.carpatica.ro/wp-content/themes/carpatica/images/favicon.ico'),
	Site('Marfin',              'ebanking.marfinbank.ro',                   'http://www.marfinbank.ro/SiteAssets/favicon.ico'),
	Site('Libra',               'secure.internetbanking.ro',                'http://www.librabank.ro/favicon.ico'),
	Site('Banca Feroviara',     'bcfonline.bfer.ro',                        'http://www.bancaferoviara.ro/favicon.ico'),
]

# Methods for interacting with the SSL Labs API.

def request(url, payload = {}, post = False):
	"""
	Sends a request to the global endpoint.
	"""

	func = requests.get if not post else requests.post
	resp = func(url, params=payload)
	data = resp.json()

	return data

def analyze(host, publish = "off", maxAge = 12):
	"""
	Starts an analysis on the endpoint, if one was not done within the last maxAge hours.
	"""

	qualys = request(QualysAPI + 'analyze', {'host': host, 'publish': publish, 'maxAge': maxAge})
	ready  = qualys['status'] == 'READY'

	if 'statusMessage' in qualys:
		status = qualys['statusMessage']
	elif 'endpoints' in qualys:
		if 'statusDetailsMessage' in qualys['endpoints'][0]:
			status = qualys['endpoints'][0]['statusDetailsMessage']
		else:
			status = qualys['endpoints'][0]['statusMessage']
	else:
		status = 'Unknown'

	mozilla = request(MozillaAPI + 'analyze', {'host': host, 'hidden': 'true' if publish == 'off' else 'false'}, True)
	ready   = ready and mozilla['state'] == 'FINISHED'

	if not ready and (not status or status == 'Ready'):
		status = 'Observatory state: ' + mozilla['state']

	return ready, status

def getEndpointData(host, s = None):
	"""
	Fetches the results of the analysis for the specified endpoint.
	"""

	if s is None:
		s = socket.gethostbyname(host)

	qualys  = request(QualysAPI + 'getEndpointData', {'host': host, 's': s})
	mozilla = request(MozillaAPI + 'analyze', {'host': host})

	return qualys, mozilla

def info():
	"""
	Fetches usage information from the API.
	"""

	data = request(QualysAPI + 'info')

	return data

# Batch scanning helper methods and parser functions.

def parseEndpointObject(site, qualys, mozilla):
	"""
	Parses the Endpoint object returned by the API and extracts the relevant information.
	"""

	# pprint([qualys, mozilla])

	if 'progress' not in qualys or qualys['progress'] != 100:

		if 'errors' in qualys:
			site.Error = qualys['errors'][0]['message']

		return site

	if 'state' not in mozilla or mozilla['state'] != 'FINISHED':

		if 'error' in mozilla:
			site.Error = mozilla['error']

		return site

	return Result(

		# Metadata
		site, qualys['grade'], mozilla['score'],

		# True if server does not support SSLv3
		not any(prot['name'] == 'SSL' for prot in qualys['details']['protocols']),

		# True if server supports TLSv1.2
		any(prot['id'] == 771 for prot in qualys['details']['protocols']),

		# True if certificate is not signed with SHA1
		qualys['details']['cert']['sigAlg'] != 'SHA1withRSA',

		# True if RC4 is not supported
		not qualys['details']['supportsRc4'],

		# True if Forward Secrecy is supported with most browsers
		qualys['details']['forwardSecrecy'] == 2 or qualys['details']['forwardSecrecy'] == 4,

		# True if not vulnerable to POODLE
		not qualys['details']['poodle'] and qualys['details']['poodleTls'] != 2,

		# True if not vulnerable to Heartbleed
		not qualys['details']['heartbleed'],

		# True if not vulnerable to FREAK
		not qualys['details']['freak'],

		# True if not vulnerable to Logjam
		not qualys['details'].get('logjam', False),

		# True if server supports TLS_FALLBACK_SCSV
		qualys['details'].get('fallbackScsv', False),

		# True if server sends HSTS
		not not qualys['details'].get('stsResponseHeader', None),

		# True if cert is EV
		qualys['details']['cert'].get('validationType', None) == 'E'

	)

def printTabulated(res):
	"""
	Prints the values from the specified Result argument into a tab-separated format.
	"""

	if not hasattr(res, 'Site'):
		print('=image("' + res.Icon + '", 4, 16, 16)\t' +
		      '=hyperlink("https://www.ssllabs.com/ssltest/analyze.html?d=' + res.Host + '","' + res.Name + '")\t' +
		      '!\t' + res.Error)
		return

	print('=image("' + res.Site.Icon + '", 4, 16, 16)\t' +
	      '=hyperlink("https://www.ssllabs.com/ssltest/analyze.html?d=' + res.Site.Host + '","' + res.Site.Name + '")\t' +
	      res.Grade + '\t' +
	      str(res.Score) + '%\t' +
	      ('Fail', 'Pass')[res.SSLv3] + '\t' +
	      ('Fail', 'Pass')[res.TLSv12] + '\t' +
	      ('Fail', 'Pass')[res.SHA1] + '\t' +
	      ('Fail', 'Pass')[res.RC4] + '\t' +
	      ('Fail', 'Pass')[res.PFS] + '\t' +
	      ('Fail', 'Pass')[res.POODLE] + '\t' +
	      ('Fail', 'Pass')[res.Heartbleed] + '\t' +
	      ('Fail', 'Pass')[res.FREAK] + '\t' +
	      ('Fail', 'Pass')[res.Logjam] + '\t' +
	      ('Fail', 'Pass')[res.SCSV] + '\t' +
	      ('Fail', 'Pass')[res.HSTS] + '\t' +
	      ('Fail', 'Pass')[res.EV])

# CLI handler methods.

def printUsage():
	"""
	Prints usage information.
	"""

	print('usage: ' + sys.argv[0] + ' [start|info|collect]')

def printInfo():
	"""
	Prints usage information from the API.
	"""

	inf = info()
	print('assessments: ' + str(inf['currentAssessments']) + '/' + str(inf['maxAssessments']))

def startScans():
	"""
	Starts the scan of all configured hosts.
	"""

	for site in Sites:
		print('processing ' + site.Name + ': ', end='', flush=True)

		ready, status = analyze(site.Host)

		if ready:
			print('Report ready.')
		else:
			print(status + '...')

def collectScans():
	"""
	Collects the analysis results for all configured hosts.
	"""

	for site in Sites:
		qualys, mozilla = getEndpointData(site.Host)
		res = parseEndpointObject(site, qualys, mozilla)
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
