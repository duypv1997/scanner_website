from scanner.core.controller.plugin import DetectorPlugin
from scanner.knowledge_base.data_container.http.url import URL
from scanner.knowledge_base.data_container.http.headers import HTTPHeaders
from scanner.misc.utils.logger import singleton_logger as core_logger


class ms15_034(DetectorPlugin):
	"""
	Detect MS15-034 - Remote code execution in HTTP.sys
	"""
	NAME = "MS15_034"

	CS_VULN_TEMPLATE_ID = "1000022"
	RESOURCE_TYPES = [ URL ]

	def detect(self, url):
		headers = HTTPHeaders([
			('Range', 'bytes=18-18446744073709551615')
		])
		http_request = self.create_http_request(url=url, headers=headers)
		http_response = self.requester.http.send(request=http_request)
		attributes = {}

		if http_response.status_code == 416:
			core_logger.info("Vulnerability is found: %s, URL=%r"%(self.get_name(), str(url)))
			# self.save_vuln(traffics=[(http_request, http_response)], attributes=attributes)
			# self.save_attribute(os="windows", base_url=url)
			# self.save_attribute(webserver="iis", base_url=url)
