import subprocess
import time

if __name__ == '__main__':
	#remove pre-existing test databases
	subprocess.call(['rm', 'keystone.db'])
	subprocess.call(['rm', 'keystone.token.db'])

	# populate the test database
	subprocess.call(['../../bin/sampledata.sh'])
	
	# run the keystone server
	server = subprocess.Popen(['../../bin/keystone'])
	
	# blatent hack.
	time.sleep(3)
	
	# run tests
	subprocess.call(['python', 'unit/test_keystone.py'])
	
	#kill the keystone server
	server.kill()
	
	# remove test databases
	subprocess.call(['rm', 'keystone.db'])
	subprocess.call(['rm', 'keystone.token.db'])
