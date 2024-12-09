#!/usr/bin/python
# @package      hubzero-mailgateway
# @file         process_emailbounces.py
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
sys.path.insert(1,"/usr/lib/python2.6/dist-packages")

import base64
import cgi
import ConfigParser
import datetime
import email
import errno
import fcntl
import mailproc
import MySQLdb
import os
import re
import smtplib
import string
import subprocess
import sys
import time
import traceback
from Crypto.Cipher import AES
from struct import *

#=============================================================================
# Main
#=============================================================================

mailproc.openlog()

try:
	# load config
	mailproc.loadConfigurationValues()
	
	## read email into string
	emailtext  = sys.stdin.read()
	
	## log the entire email	
	mailproc.log("\nprocess_emailbounce.py\n")
	mailproc.log("\nRaw Incoming Email Start\n" + emailtext + "\nRaw Incoming Email End\n")
	
	## Grab text only version of email
	emailbody, emailsubject, emailFromAddress, emailToAddress = mailproc.extractMessageFromEmail(emailtext)
	
	## send to spamc process to test for spam, pipe emailtext to child and get the stdout
	mailproc.log("Length of emailtext=" + str(len(emailtext)))
	mailproc.log("Checking for spam...")
	proc = subprocess.Popen("spamc", shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	emailtext, spamcErrors = proc.communicate(emailtext)
	
	## check for spam, spamc will alter email by adding headers to it indicating spam liklihood	
	mailproc.log("\nStart spam checked email\n" + emailtext + "\nEnd Spam check\n")
	
	## Spamassassin will put this extended header in SPAM
	match = re.search("X-Spam-Status: Yes", emailtext, flags=re.M | re.S)
	
	# chcek spam match
	if match:
		mailproc.log("\nRejected as SPAM, not processed\n")
	else:
		if emailbody is None:
			emailbody = '<empty>'
		
		if emailsubject is None:
			emailsubject = '<empty>'
		
		# we ended up in an infitinte loop once, 250k tickets gave birth to this check
		if emailFromAddress != mailproc.mailfrom_email :
			
			## Do a database insert into the jos_email_bounces table
			db = mailproc.db_connect()
			cursor = db.cursor()
			
			# get component
			component = re.search("X-Component: (.*)", emailbody, flags=re.M)
			
			# get component object 
			componentObject = re.search("X-Component-Object: (.*)", emailbody, flags=re.M)
			
			# get component object id 
			componentObjectId = re.search("X-Component-ObjectId: (.*)", emailbody, flags=re.M)
			
			# get who the message was intended for
			realToAddress = re.search("To: (.*)", emailbody, flags=re.M)
			
			# build sql statement
			sql =  "insert into jos_email_bounces "
			sql += "(email, component, object, object_id, reason, date) "
			sql += "values( %s, %s, %s, %s, %s, %s) "
			
			# Use parameters in the cursor for sql injection attack protection
			data = (
					realToAddress.group(1),
					component.group(1),
					componentObject.group(1),
					componentObjectId.group(1),
					emailbody,
					mailproc.getCurrentTime()
					)
			
			# insert record
			cursor.execute (sql, data)
			
			# close database connection
			db.close()
except Exception, ex:
	mailproc.log("\nException Encountered:\n" + str(ex) + "\n" + traceback.format_exc())			
finally:
	mailproc.closelog()
