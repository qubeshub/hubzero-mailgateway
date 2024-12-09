#!/usr/bin/python
# @package      hubzero-mailgateway
# @file         filecopy.py
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

import os
import pwd
import grp
import traceback

try:

	# arguments are passed via stdin for security reasons- it makes
	# the sudo entry this command runs under more secure if no command
	# line args are used, although it makes the whole process more
	# convoluted
	stdinString = sys.stdin.read()
	inputArgs = stdinString.split()

	if len(inputArgs) != 2:
		sys.stderr.write("Error: Two Input file names need to be space deliminted on stdin")
		exit(1)
	else:
		filename1 = inputArgs[0]
		filename2 = inputArgs[1]

	if filename1 != os.path.realpath(filename1):
		sys.stderr.write("os.path.realpath check failed for " + filename1)
		exit(1)

	if filename2 != os.path.realpath(filename2):
		sys.stderr.write("os.path.realpath check failed for " + filename2)
		exit(1)

	f1 = os.open(filename1, (os.O_NOFOLLOW))

	d2 = os.path.dirname(filename2)

	if d2:
		if not os.path.exists(d2):
			os.makedirs(d2)
			os.chown(d2, pwd.getpwnam('www-data')[2], grp.getgrnam('www-data')[2] )

	f2 = os.open(filename2, (os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW))

	# 64 MB limit per file (had to draw a line somewhere)
	f1contents = os.read(f1, (2**26))
	os.write(f2, f1contents)

	os.close(f1)
	os.close(f2)

	sys.stdout.write("copy successful, filelength = " + str(len(f1contents)))

	exit(0)

except Exception, ex:
	sys.stderr.write("\n Exception Encountered:\n" + str(ex) + "\n" + traceback.format_exc())
	exit(1)
