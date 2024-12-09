#!/usr/bin/python
# @package      hubzero-mailgateway
# @file         mailproc.py
# @author       David Benham <dbenham@purdue.edu>
# @copyright    Copyright (c) 2012-2015 HUBzero Foundation, LLC.
# @license      http://opensource.org/licenses/MIT MIT
#
# Copyright (c) 2012-2015 HUBzero Foundation, LLC.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
# HUBzero is a registered trademark of HUBzero Foundation, LLC.
#

import sys
import os

dist_packages = "/usr/lib/python%d.%d/dist-packages" % (sys.version_info[0], sys.version_info[1])

if os.path.isdir(dist_packages):
    sys.path.insert(1,dist_packages)

import base64
import cgi
import ConfigParser
import datetime
import email
import errno
import fcntl
import grp
import hashlib
import hubzero.config.webconfig
import MySQLdb
import pprint
import pwd
import random
import re
import smtplib
import stat
import string
import sys
import tempfile
import time
import traceback
from Crypto.Cipher import AES
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from struct import *

logfile_name = "/var/log/exim4/hub-processed-mail.log"
logfile = None

# Global config values
mysql_host = ''
mysql_user = ''
mysql_password = ''
mysql_db = ''
email_token_current_version = ''
email_token_encryption_key = ''
email_token_encryption_iv = ''
hubLongURL = ''
version = ''
mailfrom_email = ''
mailfrom_name = ''
site_name = ''
hubShortURL = ''
docroot = ''

"""
Load the configuration from php config file
"""
def loadConfigurationValues():
	global mysql_host
	global mysql_user
	global mysql_password
	global mysql_db
	global email_token_current_version
	global email_token_encryption_key
	global email_token_encryption_iv
	global email_version
	global mailfrom_email
	global mailfrom_name
	global hubLongURL
	global hubShortURL
	global site_name
	global docroot

	data = {}
	data['joomla'] = {}
	data['hubzero'] = {}
	config = ConfigParser.RawConfigParser()
	config.read('/etc/hubzero.conf')

        # some sites have this lowercase, others in uppercase
        try:
                section = config.get('DEFAULT','site')
        except ConfigParser.NoOptionError:
                section = config.get('default','site')

	docroot = config.get(section, 'DocumentRoot')

	## Load the entire file contents
	file_read = open('/etc/hubmail_gw.conf',"r")
	contents = file_read.read()
	file_read.close()

	## Dump all the var configuration values into arrays
	for m in re.finditer("\s*[public|var]\s+\$([a-zA-Z-_0-9]+)\s*=\s*([a-zA-Z-_\ \*\'\"\.0-9,:\/@\^\!\_\#\&]+)\s*;", contents):
		data['joomla'][m.group(1)] = m.group(2).strip(" \'\"\t")

	## Rip out the stuff we care about and set some globals
	mysql_host = data['joomla']['host']
	mysql_user = data['joomla']['user']
	mysql_password = data['joomla']['password']
	mysql_db = data['joomla']['db']
	mailfrom_name = data['joomla']['fromname']
	mailfrom_email = data['joomla']['mailfrom']
	site_name = data['joomla']['sitename']
	hubLongURL = data['joomla']['hubLongURL']
	hubShortURL  = data['joomla']['hubShortURL']

	## Get the current version info and break it out
	email_token_current_version = data['joomla']['email_token_current_version']
	email_token_encryption_info = data['joomla']['email_token_encryption_info_v' + email_token_current_version]

	pass_iv = email_token_encryption_info.split(",")
	email_token_encryption_key  = pass_iv[0]
	email_token_encryption_iv = pass_iv[1]

"""
Get exclusive lock on the logfile, multiple instances of this code could run
concurrently, this logfile lock helps maintain order
"""
def openlog():
	global logfile
	global logfilefd

	start_time = time.time()

	logfd = -1

	## Aquire a lock to the logfd, spinlock till you get it
	while True:
		try:
			if os.path.exists(logfile_name):
				logfilefd = os.open(logfile_name, os.O_APPEND | os.O_RDWR)
				fcntl.flock(logfilefd, fcntl.LOCK_EX | fcntl.LOCK_NB)
			else:
				logfilefd = os.open(logfile_name, os.O_CREAT | os.O_RDWR)
				fcntl.flock(logfilefd, fcntl.LOCK_EX | fcntl.LOCK_NB)
			break;

		except (OSError, IOError), ex:
			if ex.errno != errno.EACCES and ex.errno != errno.EAGAIN:
				raise
			if (time.time() - start_time) >= 30:
				raise Exception('Timeout waiting for logfd lock')
			time.sleep(1)

	## convert to more friendly file for use everywhere
	logfile = os.fdopen(logfilefd, 'a')


"""
Log a message.
"""
def log(msg):
	timestamp = "[" + time.asctime() + "] "
	logfile.write(timestamp + msg + "\n")
	logfile.flush()

def closelog():
	if logfile:
		logfile.close()


"""
 Create database connection.
"""
def db_connect():
	for x in range(0,255):
		try:
#			db = MySQLdb.connect(host=mysql_host, user=mysql_user, passwd=mysql_password, db=mysql_db)
			db = MySQLdb.connect(charset='utf8', init_command='SET NAMES UTF8', host=mysql_host, user=mysql_user, passwd=mysql_password, db=mysql_db)
			#log("db_connect finished on iteration %d" % x)
			return db
		except Exception as ex:
			log("Exception in db_connect: \n" + str(ex) + "\n" + traceback.format_exc())

	time.sleep(1)


"""
 MySQL helpers
"""
def mysql(c,cmd):
	try:
		count = c.execute(cmd)
		if c._warnings > 0:
			log("MySQL warning")
			log("SQL was: %s" % cmd)
			return c.fetchall()
	except MySQLdb.MySQLError, (num, expl):
		log("%s" % expl)
		log("SQL was: %s" % cmd)
		return ()
	except:
		log("Some other MySQL exception.")
		log("SQL was: %s" % cmd)
	return ()

def mysql_act(c,cmd):
	try:
		count = c.execute(cmd)
		return ""
	except MySQLdb.MySQLError, (num, expl):
		return expl



"""

 Generally php creates the token and python just decrypts it, but since we
 gotta fire off our own email in responses in some cases, we got to
 duplicate the functionality here

 Type 1 of this email token has two single bytes, followed by 3 ints and a two byte hex hash.
 Note: most representations of this string are in hex, so you'll often have to double the values

 1     : describe the type of token (unencrypted)
 2     : describe the type of token (unencrypted)
 3-6   : userid of person who received email
 7-10  : id
 11-14 : timestamp of email (standard unix 32 bit timestamp)
 15-16	: first two bytes of a SHA-1 hash of the unencrypted token

 FYI '>' is to ignore 4 byte int alignment when packing

"""
def createEmailToken(version, action, userid, id):
	INPUT_STRING_BLOCKSIZE = 8

	# type 1 of this email token has two single bytes, followed by 3 ints and a two byte hex hash
	# note most representations of this series is in hex, so you'll often have to double the values
	# to get those
	#
	# 1     : describe the type of token (unencrypted)
	# 2     : describe the type of token (unencrypted)
	# 3-6   : userid of person who received email
	# 7-10  : id
	# 11-14 : timestamp of email (standard unix 32 bit timestamp)
	# 15-16	: first two bytes of a SHA-1 hash of the unencrypted token
	#
	# FYI '>' is to ignore 4 byte int alignment

	currentTime = time.time()
	binaryString = pack(">III", int(userid), int(id), int(currentTime) )

	# Hash the unencrypted version hex version of the binary string
	# Include the unencrypted version and action bytes as well
	h = hashlib.sha1()
	hashedString = base64.b16encode(pack(">B",int(version))) + base64.b16encode(pack(">B",int(action))) + base64.b16encode(binaryString)
	h.update(hashedString.lower())
	hash = h.hexdigest().lower()

	binaryString = pack(">IIIH", int(userid), int(id), int(currentTime), int(hash[:4],16) )

	# Add PKCS7 padding before encryption
	pad = INPUT_STRING_BLOCKSIZE + 1 - (len(binaryString) % INPUT_STRING_BLOCKSIZE + 1)
	binaryString += chr(pad) * pad

	# Do the encode
	c = AES.new(email_token_encryption_key, AES.MODE_CBC, email_token_encryption_iv)
	encoded = c.encrypt(binaryString)
	emailToken = base64.b16encode(encoded).lower()

	# Add the unencrypted version number and action (in hex)
	emailToken = base64.b16encode(pack(">B",int(version))) + base64.b16encode(pack(">B",int(action))) + emailToken

	return emailToken


"""
 Decryption routine for decoding the hub email token
 Returns a tuple:

 version(byte) action(byte) tokentype(byte) userid(int) id(int) timestamp(int)

 Type 1 of this email token has two single bytes, followed by 3 ints and a two byte hex hash.
 Note: most representations of this string are in hex, so you'll often have to double the values

 1     : describe the type of token (unencrypted)
 2     : describe the type of token (unencrypted)
 3-6   : userid of person who received email
 7-10  : id
 11-14 : timestamp of email (standard unix 32 bit timestamp)
 15-16	: first two bytes of a SHA-1 hash of the unencrypted token

 FYI '>' is to ignore 4 byte int alignment when packing
"""
def decryptEmailToken(t):

	t = t.lower()

	# the version number and token types are unencrypted bytes on the front of the string
	version = t[0:2]
	tokenType = t[2:4]

	# token without the two unencrypted bytes (4 hex digits) at the beginning
	inputCipherText = t[4:]

	# Do the decode
	c = AES.new(email_token_encryption_key, AES.MODE_CBC, email_token_encryption_iv)
	inputCipherText = base64.b16decode(inputCipherText, True)
	decoded = c.decrypt(inputCipherText)

	# strip off padding. Last hex character represents number of padding bytes (standard pkcs7 padding)
	padding = decoded[-2] + decoded[-1]
	decoded = decoded.rstrip(padding)
	b16decoded = base64.b16encode(decoded)

	# caluclate our hash of bytes 1-14 (include the version and tokenType bytes)
	calculatedHash = b16decoded[-4:]
	textToHash = str((version + tokenType + b16decoded)[:28]).lower()
	h = hashlib.sha1()
	h.update(textToHash)
	hashValue = h.hexdigest()

	# compare our hash values to determine validity
	if calculatedHash.lower() != str(hashValue[:4]).lower():
		raise Exception('Checksum error: ' + calculatedHash.lower() + " != " + str(hashValue[:4]).lower() + " s1:" + textToHash)

	userid, id, timestamp, hash = unpack(">iiiH", decoded)

	# if the timestamp is too old, throw exception.
	currenttime = time.time()
	validseconds = 30*24*60*60
	if (timestamp +validseconds < currenttime):
		raise Exception('Token expired ' + str(currenttime-(timestamp + validseconds)) + " seconds ago" )

	return int(version), int(tokenType), userid, id, timestamp;


"""
 Use python's email package to get info out of the message.
 Generally, an email is either 'multipart/alternative' (in which case it
 will have both a text and html subections representing different versions of
 the same message) or it will be a straight text
"""
def extractMessageFromEmail(emailText):

	msg = email.message_from_string(emailText)
	textEmail = '<unknown>'
	emailFromAddress = '<unknown>'
	emailFromAddressRaw = msg['from']
	emailTpAddress = '<unknown>'
	emailToAddressRaw = msg['to']

	####
	##sys.stderr.write("\n\nemailText= " + emailText + "\n\n")

	emailFromAddressParsed = email.utils.parseaddr(emailFromAddressRaw)
	emailFromAddress = emailFromAddressParsed[1]

	emailToAddressParsed = email.utils.parseaddr(emailToAddressRaw)
	emailToAddress = emailToAddressParsed[1]

	textSubject = msg['subject']
	#textSubject = email.header.decode_header(textSubject)

	## Grab the text version of the email.
	textEmail = u""
	if msg.is_multipart():
		htmlEmail = None
		for part in msg.get_payload():

			if part.get_content_charset() is None:
				# We cannot know the character set, so return decoded "something"
				text = part.get_payload(decode=True)
				continue

			charset = part.get_content_charset()

			if part.get_content_type() == 'text/plain':
				textEmail = unicode(part.get_payload(decode=True), str(charset), "ignore")

			if part.get_content_type() == 'text/html':
				html = unicode(part.get_payload(decode=True), str(charset), "ignore")

	else:
		charset = msg.get_content_charset()
		textEmail = unicode(msg.get_payload(decode=True), str(charset), "ignore")

	return textEmail, textSubject, emailFromAddress, emailToAddress

def getAttachments(emailText):
	msg = email.message_from_string(emailText)
	attachments = _getAttachments(msg)

	return attachments


def _getAttachments(msg_part):
	"""return a list of lists. Each sublist in the list is a 2 element list with a filename followed by the 
	text of the attachment
	"""

	acceptable = ['text/plain', 
		'image/png',
		'image/jpg',
		'image/jpeg',
		'image/gif',
		'image/tiff',
		'application/pdf',
		'application/msword',
		'application/vnd.openxmlformats-officedocument.wordprocessingml.document']

	attachments = []

	# i.e if message is not multipart, msg_part will simply return a string, no attachments
	# in this case
	if not msg_part.is_multipart():
		return attachments

	for m in msg_part.get_payload():

		# for some reason some clients store versions of the message
		# as attachments, they have no filename. We don't want them
		filename = m.get_filename()

		if not filename:
			continue
	
		attachments.append([filename.replace(" ","_"), m.get_content_type(), m.get_payload(decode=True)])

	return attachments


def saveAttachments(attachments, path):

	#recursively create folders
	if not os.path.exists(path):
		os.makedirs(path)

	#save files
	for attach in attachments:
		fob = open(path + '/' + attach[0], "w")
		fob.write(attach[1])
		fob.close()


def saveAttachmentsToTempFiles(attachments):

	for a in attachments:
		log("saveAttachmentsToTempFiles filename=" + a[0])

		fileName, fileExtension = os.path.splitext(a[0])

		## our temp directory
		tempdir = "/tmp/hubemailattach"
		if not os.path.exists(tempdir):
			os.makedirs(tempdir)

		## to detect symbolic links in the file extension name from redirecting us
		filepath = tempdir + "/" + fileName + fileExtension
		if filepath != os.path.realpath(filepath):
			log("saveAttachmentsToTempFiles failure in os.path.realpath check for " + filepath)
			return 0

		# create a unique temp file
		fd, filename = tempfile.mkstemp(fileExtension, fileName + "-", tempdir)
		f = os.fdopen(fd, "w")
		f.write(a[2])
		f.close()

		# change temp file owner to www-data
		os.chmod(filename, 0444)
		#os.chown(filename, pwd.getpwnam('www-data')[2], -1)

		# Dump the complete temp filename into the attachments array for this entry, it will
		# be a new third list element
		a.append(filename)

	return 1


"""
 Write new email header so additional mail processing knows we have
 already processed this support email.
"""
def writeProcessedHeader(emailText):

	msg = email.message_from_string(emailText)

	## First blank line is the boundary between the header and body add our header there
	rv = emailText.replace("\n\n", "\nX-HubTokenProcessed: 1\n\n" , 1)

	return rv


"""
 Send email - just a wrapper
"""
def sendEmail(toaddress, subject, messagetext, fromaddress = '', fromname = '', replytoaddress = '', envelope_from = '', additionalHeaders = None):

	## Build outgoing email
	msg = MIMEMultipart()

	## default from name and from address unless otherwise specified
	if fromaddress:
		if fromname:
			msg['From'] = fromname + ' <' + fromaddress + '>'
		else:
			msg['From'] = mailfrom_name + ' <' + fromaddress + '>'
	else:
		if fromname:
			msg['From'] = fromname + ' <' + mailfrom_email + '>'
		else:
			msg['From'] = mailfrom_name + ' <' + mailfrom_email + '>' # if neither is specified

	msg['Subject'] = subject
	msg['To'] = toaddress

	if replytoaddress:
		msg['Reply-to'] = replytoaddress

	textmsg = MIMEText(messagetext, 'plain', 'utf-8')

	# add additional headers to the outgoing message
	if additionalHeaders is not None:
		for elem in additionalHeaders:
			msg[elem] = additionalHeaders[elem]
		
	
	msg.attach(textmsg)


	# catch SMTPConnectorErrors with code of 421, these get 
	# thrown by conservatively set SMTP servers and the error is:
	# 'Too many concurrent SMTP connections from this IP address; please try again later'
	#
	# This section will retry until sucessful
	while True:
		try:
			server = smtplib.SMTP("localhost")

			# Make the envelope's return-path different form the from address used in the email headers.
			# This helps with bounce processsing, SMTP servers will (usually) send bounces to the
			# return-path address
			if envelope_from:
				server.sendmail(envelope_from, toaddress, msg.as_string())
			else:
				server.sendmail(mailfrom_email, toaddress, msg.as_string())
                except smtplib.SMTPConnectError as e:
                        if e[0] == 421:
                                time.sleep(random.randrange(2,8))
                                continue
		break


	server.quit()


"""
  Trying to strip out some of the reply text between our ~!~!~!~!~!~!~!~!~!~! delimiter
  and the reply from the user. Nearly all email readers insert text between the previous
  message text and your reply, usually something like "On 12/1/2011 dave wrote this:"
  or some other stuff.
"""
def cleanEmail(s):

	replyDelimiterRegEx = r'(.*)(\~\!\~\!\~\!\~\!\~\!\~\!\~\!\~\!\~\!\~\!)(.*)'
	maxHeaderCheck = 15

	# common headers, also, make sure they are close to the lhs of the line to be safe
	RegExFilters = [r"^.{0,5}________________________________________",
	r"^.{0,5}--- On.*wrote:",
	r"^.{0,5}On.*wrote:",
	r"^.{0,5}[Dd]ate:.*20[0-9]{2}.*",
	r"^.{0,5}[Ff]rom:.*@.*",
	r"^.{0,5}On .*wrote:",
	r"^.{0,5}[Ss]ent:.*",
	r"^.{0,5}[Ss]ubject:.*",
	r"^.{0,5}[Tt]o:.*",
	r"^>"]

	matchObj = re.search(replyDelimiterRegEx, s, re.M | re.S)

	if matchObj:
		reply = matchObj.group(1)
		cleanedReplyList = []

		# attempt to remove more junk, read email backwards to remove some reply headers
		lineiterator = iter(reversed(reply.splitlines()))
		firstLegitLineIndexFromEnd = 0
		lc = 0

		for line in lineiterator:
			lc+=1

			# For the first 15 lines, first line that isn't header and isn't a blank line is the end of our legit email
			if lc < maxHeaderCheck:
				matchFound = False

				for regex1 in RegExFilters:
					tempMatch = re.search(regex1, line, re.S)

					if tempMatch:
						#print " match " + str(lc) + "@@" + regex1 + "@@ @@" + line + "@@"
						matchFound = True
						break

				if not matchFound and line and firstLegitLineIndexFromEnd == 0:
					firstLegitLineIndexFromEnd = lc

			# if we found the first legit line, append all remaining lines to a list to construct a clean email
			if firstLegitLineIndexFromEnd != 0 or lc > maxHeaderCheck:
				cleanedReplyList.append(line)

		cleanedReplyList.reverse();
		return '\n'.join(cleanedReplyList)

	else:
		# If we can't find our ~!~!~!~!~!~!~!~!~!~! delimiter, just return the whole message
		return s

"""
  Grab joomla config parameter from the database for specified component
"""
def grabComponentParameter(componentName, parameterName):

	# Lookup database row for this component
	db = db_connect()
	cursor = db.cursor()
	sql  = "SELECT jc.`params` "
	sql += "FROM jos_components jc "
	sql += "WHERE jc.`name` = %s "
	data = (componentName)
	cursor.execute(sql, data)
	rs = cursor.fetchone()

	if not rs:
		return ""
	else:
		params = rs[0]

	cursor.close()

	# params are newline delimited
	items = params.split("\n")
	paramsDict = {}
	for item in items:

		if "=" in item: # This prevents us from splitting a blank or misformatted line

			# each parameter is in format parm=1234
			key,value= item.split("=",1)

			if len(key) > 1:
				paramsDict[key] = value

	if paramsDict.has_key(parameterName):
		try:
			return paramsDict[parameterName]
		except:
			return ""
	else:
		return ""


def getCurrentTime():
	# no better way to detect what date version is being used with
	# a given hub installation: local time or UTC

	# get default site's doc root
	defaultSite = hubzero.config.hubzerositeconfig.getHubDefaultSite()
	wwwDocRoot = hubzero.config.hubzerositeconfig.getHubzeroConfigOption(defaultSite, 'documentroot')

	# cms.php file has version info
	fileName = wwwDocRoot + "/libraries/cms.php"
	if os.path.isfile(wwwDocRoot + "/libraries/cms.php"):

		f = open(fileName, 'r')
		fileText =  f.read()

		match = re.search(r"define\(.*'HVERSION'.*,.*1.2.0.*\);",  fileText)
		if match is not None:
			return datetime.datetime.now()
		else:
			# any value other than 1.2 means use the new format. Earlier than 1.2 didn't have$
			return datetime.datetime.utcnow()
	else:
		# if file doesn't exist we know we're pre 1.2
		return datetime.datetime.now()

