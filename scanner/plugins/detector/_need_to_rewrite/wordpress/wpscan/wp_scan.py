from w3af.core.controllers.plugins.infrastructure_plugin import InfrastructurePlugin
from w3af.core.data.request.fuzzable_http_request import FuzzableHTTPRequest
from w3af.core.data.bloomfilter.scalable_bloom import ScalableBloomFilter
from w3af.core.data.parsers.doc.url import URL

from .wp_plugins import WpPlugins
from .wp_themes import WpThemes
from .wp_version import WpVersion
from .wp_vulns import WpVulns
from .wordpress import Wordpress


class wpscan(InfrastructurePlugin):
	NAME = "Wordpress Scanner"

	def __init__(self):
		InfrastructurePlugin.__init__(self)
		self._already_tested_dirs = ScalableBloomFilter()
		self._wp_dirs = set()

	def get_vuln(self, data, component="core", component_name=None, version=None):
		vuln_data = {}
		try:
			vuln_data["title"] = data["title"]
			vuln_type = data.get("vuln_type", None)
			if vuln_type == "UNKNOWN":
				vuln_type = None
			vuln_data["vuln_type"] = vuln_type 
			vuln_data["fixed_in"] = data["fixed_in"]
			vuln_data["references"] = []
			for ref_url in data["references"]["url"]:
				url = URL(ref_url)
				vuln_data["references"].append({
					"title": url.get_domain(),
					"url": ref_url
				})
			if component == "core":
				vuln_data["core_version"] = version
				vuln_name = "Potential Wordpress vulnerability"
			elif component == "plugin":
				vuln_data["plugin_name"] = component_name
				vuln_data["plugin_version"] = version
				vuln_name = "Potential Wordpress plugin vulnerability"
			elif component == "theme":
				vuln_data["theme_name"] = component_name
				vuln_data["theme_version"] = version
				vuln_name = "Potential Wordpress theme vulnerability"
			else:
				return None
		except KeyError:
			return None	
		else:
			return self.create_vuln(vuln_name, traffic_ids=[], mutant=None, data=vuln_data)


	def discover(self, fuzzable_http_request):
		for u in fuzzable_http_request.get_url().get_directories()[::-1]:
			if u.url_string not in self._already_tested_dirs:
				for d in self._wp_dirs:
					if d in u:
						break
				else:
					self._already_tested_dirs.add(u.url_string)
					wp = Wordpress(self, fuzzable_http_request)
					if wp.is_wordpress:
						self._wp_dirs.add(u)
						WpVersion(wp).find()
						WpPlugins(wp).find()
						WpThemes(wp).find()
						WpVulns(wp).find()
						print wp.plugins
						print wp.themes
						import sys
						sys.exit()


						for v in wp.version_vulns:
							vuln = self.get_vuln(v, component="core", version=wp.version)
							if vuln:
								self.save_vuln(vuln, vuln_type="wordpress_vuln")

						for plugin_name, data in wp.plugins.iteritems():
							plugin_version = data.get("version", None)
							vuln = self.get_vuln(data, component="plugin", component_name=plugin_name, version=plugin_version)
							if vuln:
								self.save_vuln(vuln, vuln_type="wordpress_vuln")

						for theme_name, data in wp.themes.iteritems():
							theme_version = data.get("version", None)
							vuln = self.get_vuln(data, component="theme", component_name=theme_name, version=theme_version)
							if vuln:
								self.save_vuln(vuln, vuln_type="wordpress_vuln")
