from .vuln import VulnDB, VulnTemplateDB
from .sitemap import SitemapDB 


class KnowledgeBase(object):
	def __init__(self):
		self.sitemap = SitemapDB()
		self.vuln = VulnDB()
		self.vuln_template = VulnTemplateDB()


kb = KnowledgeBase()
