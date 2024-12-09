#!/usr/bin/python
# @package      hubzero-mailgateway
# @file         processsuppotedemail.py
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
import time
import traceback
from Crypto.Cipher import AES
from struct import *

#=============================================================================
# Main
#=============================================================================

mailproc.openlog()

try:
	mailproc.log("Email processing started")
	mailproc.log("processingsupportemail.py started")
	ticketCreted = False

	mailproc.loadConfigurationValues()

	# read email into string
	emailtext  = sys.stdin.read()

	# log the entire email
	mailproc.log("Raw Incoming Email Start>>>" + emailtext + "<<<Raw Incoming Email End\n")

	# Grab text only version of email
	emailbody, emailsubject, emailFromAddress, emailToAddress = mailproc.extractMessageFromEmail(emailtext)

	# send to spamc process to test for spam, pipe emailtext to child and get the stdout
	# spamc will alter email by adding headers to it indicating spam liklihood
	mailproc.log("Length of emailtext=" + str(len(emailtext)))
	mailproc.log("Checking for spam...")
	proc = subprocess.Popen("spamc", shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	emailtext, spamcErrors = proc.communicate(emailtext)

	# Spamassassin will insert this extended header in SPAM
	match = re.search("X-Spam-Status: Yes", emailtext, flags=re.M | re.S)

	# auto-submitted means this message was generated by a process, not a person, ignore
	match2 = re.search("Auto-Submitted: auto", emailtext, flags=re.M | re.S | re.I)

	if match:
		mailproc.log("Rejected as SPAM or spamc processing error, not processed")
		mailproc.log("Start spamc returned message >>>" + emailtext + "<<< End spamc returned message")
	elif:
		mailproc.log("Rejected as an auto-submitted message, not processed")
		mailproc.log("Email Start>" + emailtext + "<Email End\n")
	else:
		mailproc.log("SPAM check OK, we're clean")

		if emailbody is None:
			emailbody = '<empty>'

		if emailsubject is None:
			emailsubject = '<empty>'

		# Don't create a ticket when the from address is a person on the hub itself.
		# Idea is to allow the web code to mail the support users specified in the
		# support system and *not* create a ticket, only email coming in from
		# the outside do that
		if emailFromAddress.find(mailproc.hubShortURL) == -1:

			# Do a database insert into the jos_support_tickets table
			db = mailproc.db_connect()
			cursor = db.cursor()

			sql =  "insert into jos_support_tickets "
			sql += "(status, created, login, severity, summary, report, email, name) "
			sql += "values( %s, %s, %s, %s, %s, %s, %s, %s) "

			# Use parameters in the cursor for sql injection attack protection
			data = (0,
			        mailproc.getCurrentTime(),
			        'admin',
			        'normal',
					"(E-mail submission) - " + emailbody[0:75],
					"NOTE: E-mail submission from " + emailFromAddress + "\r\n\r\nSubject: " + emailsubject + "\r\n\r\n" + emailbody,
					emailFromAddress,
			        'admin')

			cursor.execute (sql, data)
			newTicketID = cursor.lastrowid
			db.close()
			ticketCreted = True

			# get the attachments from email
			mailproc.log("Scanning for attachments")
			attachments = mailproc.getAttachments(emailtext)

			# process accepted attachments
			if len(attachments) > 0:

				mailproc.log("Processing attachments")

				# save all the attachments to temp files in file system. After this call
				# all the attachments in the array will have three entries,
				# 0 filename
				# 1 binary content
				# 2 location of temp file in filesystem
				if not mailproc.saveAttachmentsToTempFiles(attachments):
					mailproc.log("saveAttachmentsToTempFiles detected a problem with a os.path.realpath")

				# Scan the temp filenames for viruses
				mailproc.log("Checking for viruses in the accepted attachments...")
				virusDetected = False

				for attach in attachments:
					mailproc.log("temp attachment filename:" + attach[2])

					avProc = subprocess.Popen(["clamscan", "-i", "--no-summary" , "--block-encrypted", attach[2]],
						                      shell=False,
						                      stdout=subprocess.PIPE)
					avProc.wait()

					if avProc.returncode:
						mailproc.log("Virus detected in attachment " + attach[2] + " - aborting processing of all attachments")
						virusDetected = True
						break
					else:
						mailproc.log("clamscan reports clean file for " + attach[2])

				if not virusDetected:
					mailproc.log("No viruses detected in any attachments")

					# save attachments in database, they're just links on the ticket comment
					attach_text = ""

					# deal with all the attachments in the database
					for attach in attachments:

						# grab the temp filename from the complete path, use the temp filename (it's unique)
						# to prevent overwriting of multiple files with same name from overwriting each other
						dname, fname = os.path.split(attach[2])

						sql_attach = "INSERT INTO jos_support_attachments(ticket ,filename) VALUES(%s, %s)"
						db = mailproc.db_connect()
						cursor = db.cursor()
						attach_data = (newTicketID, fname)
						cursor.execute(sql_attach, attach_data)
						db.close()

						attach_text += "\n" + '{attachment#%d}' % cursor.lastrowid;

					# add attachments to end of ticket comment
					db = mailproc.db_connect()
					cursor = db.cursor()
					mailproc.log("Updating ticket with attachment information")
					sql_update = "UPDATE `jos_support_tickets` SET `report`= CONCAT(`report`, %s) WHERE id=%s"
					update_data = (attach_text, newTicketID)
					cursor.execute(sql_update, update_data)
					db.close()

					# mailproc.saveAttachments(attachments, path)
					# path to save attachments - based on new ticket id
					path = mailproc.docroot + '/site/tickets/%d' % newTicketID

					# copy files from their temp locations to their permanent home via a sudo enabled python script
					for attach in attachments:

						# grab the temp filename from the complete path, use the temp filename (it's unique)
						# to prevent overwriting of multiple files with same name from overwriting each other
						dname, fname = os.path.split(attach[2])

						destFileName = str(path + "/" + fname)
						mailproc.log("Copying ticket attachment to " + destFileName)

						fileCopyProc = subprocess.Popen(["sudo", "/bin/su", "www-data", "-c", "/usr/lib/hubzero/bin/mailproc/filecopy.py"],
							                    shell=False,
							                    stdin=subprocess.PIPE,
							                    stdout=subprocess.PIPE,
							                    stderr=subprocess.PIPE)

						filecopyFileNames = attach[2] + " " + destFileName
						pout, perr = fileCopyProc.communicate(filecopyFileNames)

						# deal with any subprocess errors
						if fileCopyProc.returncode:
							mailproc.log("Error copying files, filecopy.py returned: " + str(fileCopyProc.returncode))
							mailproc.log(perr)
						else:
							mailproc.log("filecopy.py return=(" + str(fileCopyProc.returncode) + ") Process output: " + pout)

					# delete temp files
					for attach in attachments:
						mailproc.log("Removing temp file " + attach[2])
						os.remove(attach[2])

				else:
					# append info to ticket indicating error with attachments
					sql_update = "UPDATE `jos_support_tickets` SET `report`= CONCAT(`report`, %s) WHERE id=%s"
					update_data = ("\n\nWARNING: Virus detected in attachment, contact site administrator for further information", newTicketID)
					cursor.execute(sql_update, update_data)

			#send user a confirmation email about the ticket created for them
			confirmationMessage = "Your issue has been recieved and assigned ticket number " + str(newTicketID) + " in our system. \r\n"
			confirmationMessage += "If we have further need of information we will contact you.\r\n\r\n"

			confirmationMessage += mailproc.hubLongURL  + "/support/ticket/" + str(newTicketID) + "\r\n\r\n"

			confirmationMessage += "\r\nThanks,\r\n"
			confirmationMessage += mailproc.mailfrom_name

			mailproc.log("Sending new ticket email to " + emailFromAddress)

			mailproc.sendEmail(emailFromAddress,
				               "Email received - ticket " + str(newTicketID) + " created",
				               confirmationMessage,
				               'noreply@' + mailproc.hubShortURL, # just in case the recpient MTA responds to From address instead of returns-path for bouncebacks
				               "noreply",
			                   'noreply@' + mailproc.hubShortURL, # reply-to
			                   'noreply@' + mailproc.hubShortURL, # envelope returns-path,
			                   {"Auto-Submitted": "auto-replied"}
			                   )

		else:
			# don't create ticket, but might need to fire off local email later
			mailproc.log("No ticket created, email from address " + emailFromAddress + " is from hub domain " + mailproc.hubShortURL)


		# Send notifications to someone else? (regardless if a ticket was created or not)
		otherEmail = mailproc.grabComponentParameter("Support", "emails")
		mailproc.log("Processing mail forwards to the support.emails addresses: " + otherEmail)

		# The "{" filter is because generic email processing now just sends email to the {config.mailfrom} address
		# If a hub does that, I'm going to assume they don't want this processing to take place
		if otherEmail and "{" not in otherEmail:
			for e in otherEmail.split("\\n"): # literal '\n', not a newline

				# Just in case the support address is ever included as an outoing email list
				if 'support@' + mailproc.hubShortURL in e:
					mailproc.log("Warning: email support loop detected (support specified as outgoing address) - not emailing " + e)
					continue

				mailproc.log("Sending email to: " + e)
				if ticketCreted :
					newMailMsgBody =  "New ticket created: " + mailproc.hubLongURL  + "/support/ticket/" + str(newTicketID) + "\r\n\r\n"
					#newMailMsgBody += "You are recieving this email because your email is in the admin/support/parameters/email field" + "\r\n\r\n"
					newMailMsgBody += "Ticket information" + "\r\n--------------------------------" + "\r\n\r\n"
					newMailMsgBody += emailbody
					newMailMsgSubject = "New ticket created on " + mailproc.hubShortURL
				else:
					newMailMsgBody  = "Support email delivered to support@" + mailproc.hubShortURL + "\r\n\r\n"
					#newMailMsgBody += "You are recieving this email because your email is in the admin/support/parameters/email field" + "\r\n\r\n"
					newMailMsgBody += emailbody
					newMailMsgSubject = emailsubject

				mailproc.sendEmail(e,
				                   newMailMsgSubject,
				                   newMailMsgBody,
					               mailproc.mailfrom_email,
					               mailproc.mailfrom_name)

		else:
			mailproc.log("No new email notifications sent, support.emails = " + otherEmail)

	mailproc.log("processingsupportemail.py processing completed")

	exit(0)

except Exception, ex:

	exceptionMsg = "\nException Encountered:\n" + str(ex) + "\n" + traceback.format_exc()

	# strip newlines from output, the exim4 will log transport process errors, but only one line,
	# probably to keep logs pretty, who knows? We want everything there.
	# Replace them with literal \n, we can parse error manually when something breaks
	exceptionMsgNewlinesStripped = string.replace(exceptionMsg, "\n", "\\n")
	mailproc.log(exceptionMsgNewlinesStripped)
	sys.stderr.write(exceptionMsgNewlinesStripped)
	exit(1)
finally:
	mailproc.closelog()
