from scanner.core.controller.plugin import DetectorPlugin
from scanner.knowledge_base.data_container.http.url import URL
from scanner.knowledge_base.data_container.http.headers import HTTPHeaders
from scanner.misc.utils.logger import singleton_logger as core_logger


class jetleak(DetectorPlugin):
	"""
	Detect CVE-2015-2080 (JetLeak)
	"""
	NAME = "JetLeak"
	CS_VULN_TEMPLATE_ID = "1000021"
	RESOURCE_TYPES = [ URL ]

	def detect(self, url):
		headers = HTTPHeaders([
			('Referer', '\x00')
		])
		http_request = self.create_http_request(url=url, headers=headers)
		http_response = self.requester.http.send(request=http_request)
		attributes = {}

		if 'Illegal character 0x0 in state' in http_response.get_body():
			attributes = {
				"base_url": str(url.get_full_domain_with_path()),
				"url": str(url)
			}
			traffics = [
				http_response.id
			]
			core_logger.info("Vulnerability is found: %s, URL=%r"%(self.get_name(), str(url)))
			self.save_vuln(traffics=traffics, attributes=attributes)
			self.save_attribute(webserver="jetty", base_url=url)
