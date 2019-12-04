from scanner.core.controller.plugin import DetectorPlugin
from scanner.knowledge_base.data_container.http.url import URL
from scanner.misc.utils.logger import singleton_logger as core_logger


class werkzeug_debugger(DetectorPlugin):
	"""
	Detect if Werkzeug's debugger is enabled.
	"""
	NAME = "Werkzeug debugger"
	CS_VULN_TEMPLATE_ID = "1000020"
	RESOURCE_TYPES = [ URL ]

	CHECK_URL = '/?__debugger__=yes&cmd=resource&f=debugger.js'
	CHECK_PATTERNS = ('CONSOLE_MODE', 'openShell', 'console.png')

	def detect(self, url):
		check_url = url.join(self.CHECK_URL)
		http_request = self.create_http_request(url=check_url,)
		http_response = self.requester.http.send(request=http_request)

		# All patterns must appears on respone
		for pattern in self.CHECK_PATTERNS:
			if pattern not in http_response.get_body():
				return

		attributes = {
			"base_url": str(request.url.get_full_domain_with_path()),
			"url": str(url)
		}
		traffics = [
			http_response.id
		]
		core_logger.info("Vulnerability is found: %s, URL=%r"%(self.get_name(), str(url)))
		self.save_vuln(traffics=traffics, attributes=attributes)
		self.save_attribute(web_technology="werkzeug", base_url=base_url)
