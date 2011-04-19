# Copyright (c) 2010-2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import optparse
import os
import sqlite3

def main():
	usage = "usage: %prog username"
	parser = optparse.OptionParser(usage)
	options, args = parser.parse_args()
	if len(args) != 1:
		parser.error("Incorrect number of arguments")
	else:
		username = args[0]
		dbpath = os.path.abspath(
			os.path.join(os.path.dirname(__file__),'../db/keystone.db'))
		con = sqlite3.connect(dbpath)
		cur = con.cursor()
		cur.execute(
			"DELETE FROM users WHERE username='%s'" % username)
		con.commit()
		con.close()

if __name__ == '__main__':
	main()
