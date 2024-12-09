#!/usr/bin/python
# @package      hubzero-mailgateway
# @file         processticketcomment.py
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


"""
 Need to support multiple versions of the jos_support_tickets table schema
"""
def updateTicketStatusMultSchemas(id):

	# change status to 0 (new), open to 1 (in some cases), and clear resolved values of ticket

	# have to support multiple database schemas for this query
	db = mailproc.db_connect()
	cursor = db.cursor()
	sql = "SELECT count(1) FROM information_schema.COLUMNS WHERE TABLE_NAME = 'jos_support_tickets' AND COLUMN_NAME = 'open'"
	cursor.execute(sql)
	rs = cursor.fetchone()

	# older table version
	if rs[0] == 1:
		cursor = db.cursor()
		sql  = "update jos_support_tickets set status = 0, open = 1, resolved=\"\" where id = %s"
	else: # newer table version
		cursor = db.cursor()
		sql  = "update jos_support_tickets set status = 0, resolved=\"\" where id = %s"

	data = (ticketID)
	cursor.execute (sql, data)
	mailproc.log("Updated ticketID " + str(ticketID) +  " status from unresoved to open")
	cursor.close()



"""
 Note, if changed from a fixed state, the resolved column needs to be set to blank.
 Didn't make this a general change function because I figured we'd never be closing
 tickets via email. Also need to insert comment reflecting status/resolution changes
"""
"""
 if necessary, reopen ticket based on previous state
"""
def setTicketToOpenStatus(ticketID, originalStatus, originalResolved, username):

	changelog = ""
	originalStatusText = {
        '0': "Open",
        '1': "Awaiting user action",
        '2': "Closed",
        }

	# if ticket was set to any resolved status
	if originalResolved:

		updateTicketStatusMultSchemas(ticketID)

		# insert comments to record status change
		changelog = "<ul>"
		changelog += "<li>Comment submitted via email modified status of this ticket</li>"

		if originalResolved:
			changelog += "<li>Reopening ticket, <strong>resolution</strong> changed from " + originalResolved + " to <em>[unresolved]</em></li>"

		changelog += "<li><strong>status</strong> set to <em>Open</em></li>"

		changelog += "</ul>"

		mailproc.log("Ticket set to new/open")
		
	# ticket was awaiting user action
	elif originalStatus == 2: 

		#set waiting user action to open
		# change status to 1 (accepted), open to 1, and clear resolved values of ticket
		db = mailproc.db_connect()
		cursor = db.cursor()
		sql  = "update jos_support_tickets set status = 1, open = 1, resolved=\"\" where id = %s"
		data = (ticketID)
		cursor.execute (sql, data)
		mailproc.log("Updated ticketID " + str(ticketID) +  " status to open")
		cursor.close()

		# insert comments to record change
		cursor = db.cursor()
		changelog = "<ul>"
		changelog += "<li>Comment submitted via email modified status of this ticket</li>"

		if originalResolved:
			changelog += "<li>Setting ticket status from <em>Awaiting user action</em> to </li>"

		changelog += "<li><strong>status</strong> set to <em>accepted</em></li>"

		changelog += "</ul>"

		mailproc.log("Ticket set from waiting to accepted")

		
	else:
		mailproc.log("Ticket not resolved, no need to change")
		return("")

	return changelog


#=============================================================================
# Main
#=============================================================================

mailproc.openlog()

try:
	mailproc.log("Email processing started")
	mailproc.log("processticketcomment.py started")

	mailproc.loadConfigurationValues()

	# read email into string
	emailtext  = sys.stdin.read()

	## log the entire email
	mailproc.log("Raw Incoming Email Start>>>" + emailtext + "<<<Raw Incoming Email End\n")

	# send to spamc process to test for spam, pipe emailtext to child and get the stdout
	# spamc will alter email by adding headers to it indicating spam liklihood
	mailproc.log("Length of emailtext=" + str(len(emailtext)))
	mailproc.log("Checking for spam...")
	proc = subprocess.Popen("spamc", shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	emailtext, spamcErrors = proc.communicate(emailtext)

	# Spamassassin will insert this extended header in SPAM
	match = re.search("X-Spam-Status: Yes", emailtext, flags=re.M | re.S)

	if match:
		mailproc.log("Rejected as SPAM or spamc processing error, not processed")
		mailproc.log("Start spamc returned message >>>" + emailtext + "<<< End spamc returned message")
	else:

		mailproc.log("SPAM check OK, we're clean")

		msg = email.message_from_string(emailtext)
		emailbody = msg.get_payload()

		# Grab text only version of email
		emailbody, emailsubject, emailFromAddress, emailToAddress = mailproc.extractMessageFromEmail(emailtext)

		emailbody = mailproc.cleanEmail(emailbody)

		# See if email is from myself (infinite loops bad)
		if emailFromAddress != mailproc.mailfrom_email:

			userfeedback = emailbody

			# Get the token from the To (it will be in the form htc-XXX@somehub.org.
			# We need the XXX part
			match = re.search('htc-(([a-fA-F0-9])+)@', emailToAddress, flags=re.M | re.S)

			if match:
				hubtoken = match.group(1)
			else:
				hubtoken = ''

			#
			#print '\n\nhubtoken #' + hubtoken + '#\n'
			#print '\n\nemailToAddress#' + emailToAddress + '#\n'

			# Decrypt the hubtoken
			mailproc.log("Decrypting hubtoken(" + hubtoken + ")")
			version, tokenType, userid, ticketID, timestamp = mailproc.decryptEmailToken(hubtoken)

			# Look up info for the ticket
			db = mailproc.db_connect()
			cursor = db.cursor ()
			sql = "select t.id, t.summary, t.created, ju_creator.email, ju_creator.id, ju_owner.email, ju_owner.id, t.status, t.resolved "
			sql += "from jos_support_tickets t "
			sql += "left join jos_users ju_creator on (ju_creator.username = t.login) "
			sql += "left join jos_users ju_owner on (ju_owner.id = t.owner) "
			sql += "where t.id = " + str(ticketID)

			cursor.execute(sql)

			for row in cursor.fetchall():
				ticketid = row[0]
				summary = row[1]
				createdDate = row[2]
				creatorEmail = row[3]
				creatorUserID = row[4]
				ownerEmail = row[5]
				ownerUserID = row[6]
				ticketStatus = row[7]
				ticketResolved = row[8]

			db.close()

			message = "~!~!~!~!~!~!~!~!~!~!" + "\r\n"
			message += "Message from " + mailproc.hubLongURL + " / Ticket #" + str(ticketid) + "\r\n"
			message += "You can reply to this message, but be sure to include your reply text above this area." + "\r\n\r\n"

			message += "----------------------------\r\n"
			message += "TICKET: " + str(ticketid) + "\r\n"
			message += "SUMMARY: " + cgi.escape(summary) + "\r\n"
			message += "CREATED: " + str(createdDate) + "\r\n"
			message += "CREATED BY: " + str(creatorEmail) + "\r\n"
			message += "----------------------------\r\n\r\n"
			message += "A comment has been posted to Ticket # " + str(ticketid) + " by email from <" + emailFromAddress + ">\r\n"
			message += emailbody + "\r\n\r\n"
			message += mailproc.hubLongURL  + "/support/ticket/" + str(ticketid) + "\r\n\r\n"

			subject = mailproc.site_name + " Support, Ticket #" + str(ticketID) + " comment"

			# send email to ticket owner
			if ownerUserID is not None:

				# generate a token for them to respond via email if they wish
				newtoken = mailproc.createEmailToken('01','01', ownerUserID, ticketid)

				mailproc.log("Emailing ticket owner " + ownerEmail)

				mailproc.sendEmail(ownerEmail,
					subject,
					message,
					mailproc.mailfrom_email,
					mailproc.mailfrom_name,
					"htc-" + newtoken + "@" + mailproc.hubShortURL)

			# send email to ticket creator
			if creatorUserID is not None:

				# generate a token for them to respond via email if they wish
				newtoken = mailproc.createEmailToken('01','01', creatorUserID, ticketid)

				mailproc.log("Emailing ticket creator " + creatorEmail)

				mailproc.sendEmail(creatorEmail,
					subject,
					message,
					mailproc.mailfrom_email,
					mailproc.mailfrom_name,
					"htc-" + newtoken  + '@' +  mailproc.hubShortURL)


			### send email to any watchers, but check to see if the watcher's table is there, it isn't in every hub

			db = mailproc.db_connect()
			cursor = db.cursor()
			sql = "SELECT count(1) FROM information_schema.TABLES WHERE TABLE_NAME = 'jos_support_watching'"
			cursor.execute(sql)
			rs = cursor.fetchone()

			# is the jos_support_watching table present
			if rs[0] == 1:
				db = mailproc.db_connect()
				cursor = db.cursor ()
				sql = "select ju.email, ju.id "
				sql += "from jos_support_watching w "
				sql += "join jos_users ju on (ju.id = w.user_id) "
				sql += "where w.ticket_id = " + str(ticketID)

				cursor.execute(sql)

				for row in cursor.fetchall():

					watcherEmail = row[0]
					watcherUserID = row[1]

					newtoken = mailproc.createEmailToken('01','01', watcherUserID, ticketid)
					mailproc.log("Emailing ticket watcher " + watcherEmail)

					mailproc.sendEmail(watcherEmail,
						subject,
						message,
						mailproc.mailfrom_email,
						mailproc.mailfrom_name,
						"htc-" + newtoken  + '@' +  mailproc.hubShortURL)

	                        db.close()


			# Record what we did for the comment on the ticket
			changelog = "<ul class=""email-in-log""><li>Comment submitted via email from " + emailFromAddress + "</li></ul>"

			if creatorEmail != None:
				changelog += "<ul class=""email-out-log""><li>E-mailed ticket creator " + str(creatorEmail) + " </li></ul>"

			if ownerEmail != None:
				changelog += "<ul class=""email-out-log""><li>E-mailed ticket owner " + str(ownerEmail) + " </li></ul>"

			# look up some user info
			if userid> 0:
				db = mailproc.db_connect()
				cursor = db.cursor ()
				sql = "select u.username from jos_users u where u.id = " + str(userid)

				cursor.execute (sql)

				for row in cursor.fetchall():
					username = row[0]

				db.close()
			else:
				username = '<non-hub user>'

			# update ticket status, then return string to insert comment documenting changes
			changelog += setTicketToOpenStatus(ticketID, ticketStatus, ticketResolved, username)

			# insert the ticket comment
			db = mailproc.db_connect()
			cursor = db.cursor ()
			sql  = "INSERT INTO jos_support_comments (ticket, comment, created, created_by, changelog, access) "
			sql += "VALUES( %s, %s, %s, %s, %s, %s )"
			data = ( ticketID, emailbody, mailproc.getCurrentTime(), userid, changelog, 0)
			cursor.execute (sql, data)
			commentid = cursor.lastrowid
			mailproc.log("Inserted email ticket comment (" + str(commentid) +  ") into database")

			# get the attachments from email
			mailproc.log("Scanning for attachments")
			attachments = mailproc.getAttachments(emailtext)

			# process accepted attachments
			if attachments and len(attachments) > 0:

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
					mailproc.log("temp attachment filename:" + attach[3])

					avProc = subprocess.Popen(["clamscan", "-i", "--no-summary" , "--block-encrypted", attach[3]],
					                          shell=False,
					                          stdout=subprocess.PIPE)
					avProc.wait()

					if avProc.returncode:
						mailproc.log("Virus detected in attachment " + attach[3] + " - aborting processing of all attachments")
						virusDetected = True
						break
					else:
						mailproc.log("clamscan reports clean file for " + attach[3])
				if not virusDetected:
					mailproc.log("No viruses detected in any attachments")

					# save attachments in database, they're just links on the ticket comment
					attach_text = ""

					# deal with all the attachments in the database
					for attach in attachments:

						# grab the temp filename from the complete path, use the temp filename (it's unique)
						# to prevent overwriting of multiple files with same name from overwriting each other
						dname, fname = os.path.split(attach[3])

						sql_attach = "INSERT INTO jos_support_attachments(ticket ,filename) VALUES( %s, %s)"
						attach_data = (ticketid, fname)
						cursor.execute(sql_attach, attach_data)

						attach_text += "\n" + '{attachment#%d}' % cursor.lastrowid;

					# add attachments to end of ticket comment
					mailproc.log("Updating ticket with attachment information")
					sql_update = "UPDATE `jos_support_comments` SET `comment`= CONCAT(`comment`, %s) WHERE id=%s"
					update_data = (attach_text, commentid)
					cursor.execute(sql_update, update_data)

					# mailproc.saveAttachments(attachments, path)
					# path to save attachments - based on new ticket id
					path = mailproc.docroot + '/app/site/tickets/%d' % ticketID

					# copy files from their temp locations to their permanent home via a sudo enabled python script
					for attach in attachments:

						# grab the temp filename from the complete path, use the temp filename (it's unique)
						# to prevent overwriting of multiple files with same name from overwriting each other
						dname, fname = os.path.split(attach[3])

						destFileName = str(path + "/" + fname)
						mailproc.log("Copying ticket attachment to " + destFileName)

						fileCopyProc = subprocess.Popen(["sudo", "-u", "www-data", "/usr/lib/hubzero/bin/mailproc/filecopy.py"],
							                    shell=False,
							                    stdin=subprocess.PIPE,
							                    stdout=subprocess.PIPE,
							                    stderr=subprocess.PIPE)

						filecopyFileNames = attach[3] + " " + destFileName
						pout, perr = fileCopyProc.communicate(filecopyFileNames)

						# deal with any subprocess errors
						if fileCopyProc.returncode:
							mailproc.log("Error copying files, filecopy.py returned: " + str(fileCopyProc.returncode))
							mailproc.log(perr)
						else:
							mailproc.log("filecopy.py return=" + str(fileCopyProc.returncode) + " Process output: " + pout)


					# delete temp files
					for attach in attachments:
						mailproc.log("Removing temp file " + attach[3])
						os.remove(attach[3])

				else:
					# append info to ticket comment indicating error with attachments
					sql_update = "UPDATE `jos_support_comments` SET `comment`= CONCAT(`comment`, %s) WHERE id=%s"
					update_data = ("\n\nWARNING: Virus detected in attachment, contact site administrator for further information", commentid)
					cursor.execute(sql_update, update_data)


			else:
				mailproc.log("No accepted attachments found")


			mailproc.log("Email processing completed")
			db.close()

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


