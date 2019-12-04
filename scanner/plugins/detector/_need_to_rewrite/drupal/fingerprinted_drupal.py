from w3af.core.controllers.plugins.infrastructure_plugin import InfrastructurePlugin
from w3af.core.data.request.fuzzable_http_request import FuzzableHTTPRequest
from w3af.core.data.bloomfilter.scalable_bloom import ScalableBloomFilter

import re


class fingerprinted_drupal(InfrastructurePlugin):
    NAME = "Fingerprinted Drupal"

    def __init__(self):
        InfrastructurePlugin.__init__(self)
        self._already_tested_dirs = ScalableBloomFilter()
        self._drupal_index_detected = True

    def get_long_desc(self):
        return ""

    def discover(self, fuzzable_http_request):
        for d in fuzzable_http_request.get_url().get_directories():
            if d.url_string not in self._already_tested_dirs:
                self._already_tested_dirs.add(d.url_string)
                self.check_and_save_version(d)

    def check_and_save_version(self, url):
        data = self._get_version(url)
        if data:
            response, version = data
            fr = FuzzableHTTPRequest.from_parts(url)
            vuln_data = {
                "version": version
            }
            vuln = self.create_vuln("Fingerprinted Drupal", traffic_ids=response.id, mutant=fr, data=vuln_data)
            self.save_vuln(vuln, vuln_type="fingerprinted_drupal")
            self.kb_update_lang("PHP", mutant=fr, traffic_ids=response.id)
            return

    def _get_version(self, url):
        for change_log in [ "CHANGELOG.txt", "core/CHANGELOG.txt" ]:
            u = url.url_join(change_log)
            response = self.requestor.http.GET(u, cache=False, grep=False)
            match = re.search("^Drupal (\d+(\.\d+(\.\d+)?)?)", response.get_body(), re.M)
            if match:
                return response, match.group(1)

        if not self._drupal_index_detected:
            response = self.requestor.http.GET(url, cache=False, grep=False)
            match = re.search("<meta name=\"Generator\" content=\"Drupal (\d+(\.\d+(\.\d+)?)?)", response.get_body())
            if match:
                self._drupal_index_detected = True
                return response, match.group(1)

