#!/usr/bin/python
# @package      hubzero-mailgateway
# @file         processgroupforumpost.py
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
import hashlib
import encodings.utf_8
import hubzero.config.webconfig
import mailproc
import MySQLdb
import re
import smtplib
import string
import subprocess
import sys
import time
import traceback
from Crypto.Cipher import AES
from struct import *
from distutils.version import StrictVersion as V

mailproc.openlog()

## after getting log file taken care of, put everything inside a global try except and log all exceptions
try:

	mailproc.log("Email processing started")
	mailproc.log("processgroupforumpost.py started")

	mailproc.loadConfigurationValues()

	## read email into string
	emailtext  = sys.stdin.read()

	## log the entire email
	mailproc.log("Raw Incoming Email Start>>>" + emailtext + "<<<Raw Incoming Email End\n")

	## send to spamc process to test for spam, pipe emailtext to child and get the stdout
	proc = subprocess.Popen("spamc", shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
	proc.stdin.write(emailtext)
	proc.stdin.close()
	proc.wait()
	emailtext = proc.stdout.read()

	## Spamassassin will put this extended header in SPAM
	match = re.search("X-Spam-Status: Yes", emailtext, flags=re.M | re.S)

	if match:
		mailproc.log("Rejected as SPAM, not processed")
		mailproc.log("Modified SPAM processing Email Start>" + emailtext + "<Modified SPAM processing Email End\n")
	else:

		msg = email.message_from_string(emailtext)
		emailbody = msg.get_payload()

		## Grab text only version of email
		emailbody, emailsubject, emailFromAddress, emailToAddress = mailproc.extractMessageFromEmail(emailtext)
		emailbody = mailproc.cleanEmail(emailbody)


		### see if email is from Yahoo with this specific subject line.
		if "auto response" in emailsubject.lower() and 'yahoo.com' in emailFromAddress.lower():
			mailproc.log("Yahoo originated 'auto response' subject found, cancelling processing ")
			exit(3)


		### hash the subject and message to attempt to detect duplicate submissions and prevent email loops
		hubhashdir = '/var/log/exim4/hubmailedhash/'
		m = hashlib.md5()
		m.update((emailbody + emailsubject + emailFromAddress).encode('utf-8'))
		mailhash =  m.hexdigest()

		if not os.path.exists(hubhashdir):
			os.makedirs(hubhashdir, 0775)

		## delete old files, use this touched file's date/time last accessed to tell us
		## when to do our find/delete. We don't want to run the find/delete every time, bad performance
		lastCheckedFileName = hubhashdir + 'check.last'

		if not os.path.isfile(lastCheckedFileName):
			subprocess.call(["touch", lastCheckedFileName])

		fileAgeInSeconds = time.time() - os.path.getmtime(lastCheckedFileName)

		if fileAgeInSeconds > 432000: # 5 days
			# delete files older than
			subprocess.call(["touch", lastCheckedFileName])
			subprocess.Popen('find ' + hubhashdir + ' -type f -mmin +7200 -exec rm {} \;', shell=True).wait()

		hashfilename = hubhashdir + m.hexdigest()

		if os.path.isfile(hashfilename):
			mailproc.log("Email loop detected on subject/body/from hash (" + mailhash + ")")
			mailproc.log("Cancelling processing")
			exit(1)
		else:
			with open(hashfilename, "w") as f:
				f.write("")

		### Header checks for vacation autoreplies
		msgHeaders = email.parser.HeaderParser().parsestr(emailtext)

		# convert list of tuples to dictionary
		headerDict = dict(msgHeaders.items())

		# list of headers to look for. If found, we're considering this email to be a response from
		# an automailer of some sort. Store found headers and their value in a dictionary
		selected_headers = [ "Autorespond", "X-Autoresponse", "X-Autoreply-From" ]
		badHeaders = dict((hkey, headerDict[hkey]) for hkey in selected_headers if hkey in headerDict)

		if not badHeaders and len(badHeaders) > 0:
			mailproc.log("Autoreply header(s) found")
			mailproc.log(badHeaders)
			mailproc.log("Cancelling processing")
			exit(2)

		# Another out of office reply to check - absence and 'no' are considered human generated responses
		# https://www.iana.org/assignments/auto-submitted-keywords/auto-submitted-keywords.xhtml
		if not headerDict.get('Auto-Submitted') == None and not headerDict.get('Auto-Submitted') == 'no':
			mailproc.log("Autoreply header found")
			mailproc.log("Auto-Submitted: " + headerDict.get('Auto-Submitted'))
			mailproc.log("Cancelling processing")
			exit(2)

		## See if email is from myself (infinite loops bad)
		if emailFromAddress != mailproc.mailfrom_email:

			userfeedback = emailbody

			## Get the token from the To (it will be in the form hgm-XXX@somehub.org.
			## We need the XXX part
			match = re.search('hgm-(([a-fA-F0-9])+)@', emailToAddress, flags=re.M | re.S)

			if match:
				hubtoken = match.group(1)
			else:
				hubtoken = ''

			mailproc.log("Token " + hubtoken)

			# Decrypt the hubtoken
			version, tokenType, userid, forum_post_id, timestamp = mailproc.decryptEmailToken(hubtoken)

			# Lookup this jos_forum_posts record contained in the token
			mailproc.log("Looking up forum info for forum_post_id = " + str(forum_post_id))

			# have to support multiple database schemas for this query
			db = mailproc.db_connect()
			cursor = db.cursor()
			sql = "SELECT count(1) FROM information_schema.COLUMNS WHERE TABLE_NAME = 'jos_forum_posts' AND COLUMN_NAME = 'scope'"
			cursor.execute(sql)
			rs = cursor.fetchone()

			# newer table version requires different lookups
			if rs[0] == 1:
				cursor = db.cursor()
				sql  = "SELECT jfp.`id`, jfp.`parent`, jfp.`scope_id`, jfp.`category_id`, jfp.`title`, fc.alias, fs.alias, fc.closed "
				sql += "FROM jos_forum_posts jfp "
				sql += "JOIN jos_forum_categories fc on (fc.id = jfp.category_id) "
				sql += "JOIN jos_forum_sections fs on (fs.id = fc.section_id) "
				sql += "WHERE jfp.id = %s "
			else:
				cursor = db.cursor()
				sql  = "SELECT jfp.`id`, jfp.`parent`, jfp.`group_id`, jfp.`category_id`, jfp.`title`, 0 ,0"
				sql += "FROM jos_forum_posts jfp "
				sql += "WHERE jfp.id = %s "

			data = (forum_post_id)
			cursor.execute(sql, data)

			rs = cursor.fetchone()

			if not rs:
				raise Exception("Cannot obtain info for jos_forum_post with ID " + str(commentid))
			else:
				parent = rs[0]
				groupid = rs[2]
				categoryid = rs[3]
				posttitle = rs[4]
				postcategory = rs[5]
				postsection = rs[6]
				closed = rs[7]

			cursor.close()
			db.close()

			if closed != 0 :
				mailproc.log("Forum category is closed, not posting")
				exit(0)

			access = 4
			state = 1

			# If a parent is set...
			if parent != 0 :
				# Lookup the parent record
				mailproc.log("Looking up forum info for parent forum_post_id = " + str(parent))

				db = mailproc.db_connect()
				cursor = db.cursor()
				sql  = "SELECT jfp.`access`, jfp.`state` "
				sql += "FROM jos_forum_posts jfp "
				sql += "WHERE jfp.id = %s "

				data = (parent)
				cursor.execute(sql, data)

				rs = cursor.fetchone()

				if not rs:
					raise Exception("Cannot obtain info for parent jos_forum_post with ID " + str(parent))
				else:
					access = rs[0]
					state = rs[1]

				cursor.close()
				db.close()

			# Look up group name
			mailproc.log("Looking up group information on forum post for groupid " + str(groupid))
			db = mailproc.db_connect()
			cursor = db.cursor()
			sql  = "SELECT xg.`description`, xg.`cn`, case when plugins like '%%forum=nobody%%' then 1 else 0 end as ForumClosed FROM jos_xgroups xg WHERE xg.gidNumber = %s"
			data = (groupid)
			cursor.execute(sql, data)
			rs = cursor.fetchone()

			if not rs:
				raise Exception("Cannot obtain info for jos_xgroups with ID of " + str(groupid))
			else:
				groupDescription = rs[0]
				groupName = rs[1]
				groupForumClosed = rs[2]

			cursor.close()
			db.close()

			if groupForumClosed != 0 :
				mailproc.log("The group forum is closed, not posting")
				exit(0)


			# Do a database insert into the jos_xforum table. Need to support multiple versions of this table, specifically
			# the scope and thread fields are not always present
			db = mailproc.db_connect()
			cursor = db.cursor()
			sql = "SELECT count(1) FROM information_schema.COLUMNS WHERE TABLE_NAME = 'jos_forum_posts' AND COLUMN_NAME = 'scope'"
			cursor.execute(sql)
			rs = cursor.fetchone()
			if rs[0] == 1:
				scope_field = True
			else:
				scope_field = False

			sql = "SELECT count(1) FROM information_schema.COLUMNS WHERE TABLE_NAME = 'jos_forum_posts' AND COLUMN_NAME = 'thread'"
			cursor.execute(sql)
			rs = cursor.fetchone()
			if rs[0] == 1:
				thread_field = True
			else:
				thread_field = False

			db = mailproc.db_connect()
			cursor = db.cursor()
			sql_fields = "INSERT INTO jos_forum_posts (`title`, `comment`, `created`, `created_by`, `state`, `sticky`, `parent`, `hits`, `access`, `anonymous`, `modified`, `modified_by`, `category_id`, `last_activity` "
			sql_values = "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s"
			data = ("Emailed forum response from " + emailFromAddress,
				userfeedback + "\n---- Emailed forum response from " + emailFromAddress,
				mailproc.getCurrentTime(), userid, 1, 0,
				parent, 0, access,
				0, mailproc.getCurrentTime(), userid, categoryid,
				mailproc.getCurrentTime())

			# add any necessary colums for all the different versions of this table bouncing around out there
			if scope_field:
				sql_fields += ", `scope`, `scope_id`"
				sql_values += ", %s, %s"
				data += ('group', groupid,)
			else:
				sql_fields += ", `group_id`"
				sql_values += ", %s"
				data += (groupid,)

			if thread_field:
				sql_fields += ", `thread`"
				sql_values += ", %s"
				data += (parent,)

			# add final delimiters
			sql_fields += ")"
			sql_values += ")"

			cursor.execute (sql_fields + " " + sql_values, data)
			newCommentID = cursor.lastrowid
			db.close()

			## Grab all users of this group who are interested in receiving email about this reply
			mailproc.log("Grabbing all users subscribed to this post")
			db = mailproc.db_connect()
			cursor = db.cursor ()

			sql  = "SELECT u.id, u.email "
			sql += "FROM jos_xgroups_members m "
			sql += "JOIN jos_users u ON (u.id = m.uidNumber) "
			sql += "JOIN jos_xgroups_memberoption mo ON (mo.gidNumber = m.gidNumber and mo.userID = u.id and mo.optionname = 'receive-forum-email') "
			sql += "where m.gidNumber = %s and mo.optionvalue = 1 "
			data = (groupid)
			cursor.execute(sql, data)
			rows = cursor.fetchall()

			message = "~!~!~!~!~!~!~!~!~!~!" + "\r\n"
			message += "Message from " + mailproc.hubLongURL + "\r\n"
			message += "You can reply to this message, but be sure to include your reply text above this area." + "\r\n\r\n"
			message += emailFromAddress + " wrote:\r\n\r\n"
			message += emailbody

			cmsVersion = hubzero.config.webconfig.getCMSversion()

			# only include the unsubscribe link if the web app can process it
			if V(cmsVersion) >= V("1.2.2"):
				addUnsubscribeSection = True
			else:
				addUnsubscribeSection = False

			forumlink = mailproc.hubLongURL + "/groups/" + groupName + "/forum/" + postsection + "/" + postcategory + "/" + str(parent) + "#c" + str(newCommentID)

			## Loop through all people who want email notifications of forum posts
			for row in rows:
				mailproc.log('Sending response email to ' + row[1])

				# generate a token for them to respond via email if they wish
				newtoken = mailproc.createEmailToken('01','02', row[0], parent)

				# generate a token and link for unsubscribe, it is user specific, so it's
				# generated inside this loop, individally for each user
				unsubline = ''
				if addUnsubscribeSection:
					unsubtoken = mailproc.createEmailToken('01','03', row[0], groupid)
					unsubline = "\r\n\r\nUnsubscribe:\r\n"
					unsubline += mailproc.hubLongURL + "/groups/" + groupName + "/unsubscribe?t=" + unsubtoken 

				mailproc.sendEmail(row[1],
					mailproc.site_name + ' - ' + groupName + " - " + posttitle,
					message + "\r\n\r\nFull forum post:\r\n" + forumlink + unsubline,
					"",
					"",
					"hgm-" + newtoken + "@" + mailproc.hubShortURL)

			db.close()
			mailproc.log("processgroupforumpost.py end")

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
