from w3af.core.data.request.fuzzable_http_request import FuzzableHTTPRequest

from Wappalyzer import Wappalyzer, WebPage


class Wordpress:
	def __init__(self, plugin, fuzzable_http_request):
		self.plugin = plugin
		self.version = None
		self.version_vulns = []
		self.plugins = {}
		self.themes = {}
		self.fr = fuzzable_http_request
		self.is_wordpress = self.check_wordpress()

	def check_wordpress(self):
		url = self.fr.get_url()
		for p in ( "wp-login.php", ""):
			u = url
			if p:
				u = u.url_join(p)
			response = self.plugin.requestor.http.GET(u, cache=False, grep=False)
			if p:
				if response.get_code() != 200 or "WordPress" not in response.body:
					continue
			else:
				webpage = WebPage(url=u.url_string, html=response.body, headers={})
				if 'WordPress' not in Wappalyzer.latest().analyze(webpage):
					continue
			self.plugin.kb_update_web_technology("Wordpress", version=None, mutant=self.fr, traffic_ids=response.id)
			self.plugin.kb_update_lang("PHP", mutant=self.fr, traffic_ids=response.id)
			return True
		return False
