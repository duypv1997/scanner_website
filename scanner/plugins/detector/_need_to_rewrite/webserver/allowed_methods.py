"""
allowed_methods.py

Copyright 2006 Andres Riancho

This file is part of w3af, http://w3af.org/ .

w3af is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 2 of the License.

w3af is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with w3af; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

"""
import w3af.core.controllers.output_manager as om
import w3af.core.data.constants.response_codes as response_codes

from w3af.core.controllers.plugins.infrastructure_plugin import InfrastructurePlugin
from w3af.core.controllers.exceptions import RunOnce
from w3af.core.controllers.misc.group_by_min_key import group_by_min_key
from w3af.core.data.options.opt_factory import opt_factory
from w3af.core.data.options.option_list import OptionList
from w3af.core.data.bloomfilter.scalable_bloom import ScalableBloomFilter
from w3af.core.data.request.fuzzable_http_request import FuzzableHTTPRequest


class allowed_methods(InfrastructurePlugin):
    """
    Enumerate the allowed methods of an URL.
    :author: Andres Riancho (andres.riancho@gmail.com)
    """
    NAME = "Allowed methods"

    BAD_CODES = {response_codes.UNAUTHORIZED, response_codes.NOT_IMPLEMENTED,
                 response_codes.METHOD_NOT_ALLOWED, response_codes.FORBIDDEN}

    DAV_METHODS = {'DELETE', 'PROPFIND', 'PROPPATCH', 'COPY', 'MOVE', 'LOCK',
                   'UNLOCK', 'MKCOL'}
    COMMON_METHODS = {'OPTIONS', 'GET', 'HEAD', 'POST', 'TRACE', 'PUT'}
    UNCOMMON_METHODS = {'*', 'SUBSCRIPTIONS', 'NOTIFY', 'DEBUG', 'TRACK',
                        'POLL', 'PIN', 'INVOKE', 'SUBSCRIBE', 'UNSUBSCRIBE'}
    # Methods taken from http://www.w3.org/Protocols/HTTP/Methods.html
    PROPOSED_METHODS = {'CHECKOUT', 'SHOWMETHOD', 'LINK', 'UNLINK', 'CHECKIN',
                        'TEXTSEARCH', 'SPACEJUMP', 'SEARCH', 'REPLY'}
    EXTRA_METHODS = {'CONNECT', 'RMDIR', 'MKDIR', 'REPORT', 'ACL', 'DELETE',
                     'INDEX', 'LABEL', 'INVALID'}
    VERSION_CONTROL = {'VERSION_CONTROL', 'CHECKIN', 'UNCHECKOUT', 'PATCH',
                       'MERGE', 'MKWORKSPACE', 'MKACTIVITY', 'BASELINE_CONTROL'}

    def __init__(self):
        InfrastructurePlugin.__init__(self)

        # Internal variables
        self._exec = True
        self._already_tested = ScalableBloomFilter()

        # Methods
        self._supported_methods = self.DAV_METHODS | self.COMMON_METHODS | \
                                  self.UNCOMMON_METHODS | self.PROPOSED_METHODS | \
                                  self.EXTRA_METHODS | self.VERSION_CONTROL

        # User configured variables
        self._exec_one_time = True
        self._report_dav_only = True

    def discover(self, fuzzable_http_request):
        """
        Uses several techniques to try to find out what methods are allowed for
        an URL.

        :param fuzzable_http_request: A fuzzable_http_request instance that contains
                                    (among other things) the URL to test.
        """
        if not self._exec:
            # This will remove the plugin from the infrastructure
            # plugins to be run.
            raise RunOnce()

        # Run the plugin.
        if self._exec_one_time:
            self._exec = False

        domain_path = fuzzable_http_request.get_url().get_domain_path()
        if domain_path not in self._already_tested:
            self._already_tested.add(domain_path)
            _allowed_methods, id_list = self._identify_allowed_methods(domain_path)
            self._analyze_methods(domain_path, _allowed_methods, id_list)

    def _identify_allowed_methods(self, url):
        # First, try to check available methods using OPTIONS,
        # if OPTIONS isn't enabled, do it manually
        allowed_options, id_options = self._identify_with_OPTIONS(url)
        allowed_bf, id_bf = self._identify_with_bruteforce(url)
        
        _allowed_methods = allowed_options + allowed_bf
        # If a method was found by both, bf and options, it is duplicated in 
        # the list. Remove dups
        _allowed_methods = list(set(_allowed_methods))
        # There are no duplicate requests.
        # Even if a method was discovered with both, bf and options, we 
        # furthermore want to see both requests
        id_list = id_options + id_bf
        
        # Added this to make the output a little bit more readable.
        _allowed_methods.sort()
        
        return _allowed_methods, id_list

    def _identify_with_OPTIONS(self, url):
        """
        Find out what methods are allowed using OPTIONS
        :param url: Where to check.
        """
        _allowed_methods = []
        id_list = []

        try:
            res = self.requestor.http.OPTIONS(url)
        except:
            pass
        else:
            headers = res.get_lower_case_headers()
            id_list.append(res.id)
            
            for header_name in ['allow', 'public']:
                if header_name in headers:
                    _allowed_methods.extend(headers[header_name].split(','))
                    _allowed_methods = [x.strip() for x in _allowed_methods]
                    _allowed_methods = list(set(_allowed_methods))
        
        return _allowed_methods, id_list

    def _identify_with_bruteforce(self, url):
        id_list = []
        _allowed_methods = []
        #
        #   Before doing anything else, I'll send a request with a
        #   non-existent method if that request succeeds, then all will...
        #
        non_exist_response = self.requestor.http.BUUZZZZZZZ(url)
        get_response = self.requestor.http.GET(url)
        fr = FuzzableHTTPRequest.from_http_response(get_response)

        if non_exist_response.get_code() not in self.BAD_CODES\
        and get_response.get_body() == non_exist_response.get_body():

            traffic_ids = [non_exist_response.get_id(), get_response.get_id()]
            vuln = self.create_vuln('Non existent methods default to GET', mutant=fr, traffic_ids=traffic_ids)
            self.save_vuln(vuln, vuln_type='custom-configuration', uniq_type='URL')
            #
            #   It makes no sense to continue working, all methods will
            #   appear as enabled because of this custom configuration.
            #
            return [], traffic_ids

        # 'DELETE' is not tested! I don't want to remove anything...
        # 'PUT' is not tested! I don't want to overwrite anything...
        methods_to_test = self._supported_methods.copy()

        # remove dangerous methods.
        methods_to_test.remove('DELETE')
        methods_to_test.remove('PUT')

        for method in methods_to_test:
            method_functor = getattr(self.requestor.http, method)
            try:
                response = apply(method_functor, (url,), {})
            except:
                pass
            else:
                code = response.get_code()                
                if code not in self.BAD_CODES:
                    _allowed_methods.append(method)
                    id_list.append(response.id)
        
        return _allowed_methods, id_list

    def _analyze_methods(self, url, _allowed_methods, id_list):
        # Sometimes there are no allowed methods, which means that our plugin
        # failed to identify any methods.
        if not _allowed_methods:
            return

        # Check for DAV
        elif set(_allowed_methods).intersection(self.DAV_METHODS):
            # dav is enabled!
            # Save the results in the KB so that other plugins can use this
            # information
            vuln_data = {
                "methods": _allowed_methods,
                "url": str(url),
            }
            vuln = self.create_vuln('DAV methods enabled', traffic_ids=id_list, data=vuln_data)
            self.save_vuln(vuln, vuln_type="dav-methods")
        else:
            vuln_data = {
                "methods": _allowed_methods,
                "url": str(url),
            }
            info = self.create_vuln('Allowed HTTP methods', traffic_ids=id_list, data=vuln_data)
            self.save_vuln(info, vuln_type="methods")

    def end(self):
        """
        Print the results.
        """
        # First I get the data from the kb
        all_info_obj = self.get_vulns(vuln_type='methods')
        dav_info_obj = self.get_vulns(vuln_type='dav-methods')

        # Now I transform it to something I can use with group_by_min_key
        all_methods = []
        for i in all_info_obj:
            all_methods.append((i.get_url(), i.get_data('methods')))

        dav_methods = []

        for i in dav_info_obj:
            dav_methods.append((i.get_url(), i.get_data('methods')))

        # Now I work the data...
        to_show, method_type = dav_methods, ' DAV'
        if not self._report_dav_only:
            to_show, method_type = all_methods, ''

        # Make it hashable
        tmp = []
        for url, methodList in to_show:
            tmp.append((url, ', '.join(methodList)))

        result_dict, item_index = group_by_min_key(tmp)

        for k in result_dict:
            if item_index == 0:
                # Grouped by URLs
                msg = 'The URL: "%s" has the following %s methods enabled:'
                om.out.information(msg % (k, method_type))
            else:
                # Grouped by Methods
                msg = 'The methods: %s are enabled on the following URLs:'
                om.out.information(msg % k)

            for i in result_dict[k]:
                om.out.information('- ' + i)

    def get_options(self):
        """
        :return: A list of option objects for this plugin.
        """
        ol = OptionList()

        d1 = 'Execute plugin only one time'
        h1 = ('Generally the methods allowed for a URL are configured system'
              ' wide, so executing this plugin only once is the faster choice.'
              ' The most accurate choice is to run it against every URL.')
        o = opt_factory('execOneTime', self._exec_one_time, d1,
                        'boolean', help=h1)
        ol.add(o)

        d2 = 'Only report findings if uncommon methods are found'
        o = opt_factory('reportDavOnly', self._report_dav_only, d2, 'boolean')
        ol.add(o)

        return ol

    def set_options(self, options_list):
        """
        This method sets all the options that are configured using the user
        interface generated by the framework using the result of get_options().

        :param options_list: A dictionary with the options for the plugin.
        :return: No value is returned.
        """
        self._exec_one_time = options_list['execOneTime'].get_value()
        self._report_dav_only = options_list['reportDavOnly'].get_value()

    def get_long_desc(self):
        """
        :return: A DETAILED description of the plugin functions and features.
        """
        return """
        This plugin finds which HTTP methods are enabled for a URI.

        Two configurable parameters exist:
            - execOneTime
            - reportDavOnly

        If "execOneTime" is set to True, then only the methods in the webroot
        are enumerated. If "reportDavOnly" is set to True, this plugin will only
        report the enabled method list if DAV methods have been found.

        The plugin will try to use the OPTIONS method to enumerate all available
        methods, if that fails, a manual enumeration is done.
        """
