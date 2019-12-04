from scanner.knowledge_base.data_container.dc import DataContainer
from scanner.knowledge_base.data_container.domain import Domain
from scanner.knowledge_base.data_container.http.path import Path
from scanner.knowledge_base.data_container.http.query_string import QueryString
from scanner.exceptions import InvalidURL

import re
from urllib.parse import urlparse


class URL(DataContainer):
	"""
	TODO: parse URL
	"""

	def __init__(self, data, normalize=True):
		if not isinstance(data, str):
			raise ValueError("URL can only be built from string, not %s"%(type(data)))
		self.auto_normalize = normalize
		self.scheme, self.domain, self.path, self.query_string, self.fragment = self._parse(data)

	@staticmethod
	def _parse(url_string):
		"""
		TODO: Parse more specific
		"""
		scheme, netloc, path, param, qs, fragment = urlparse(url_string)
		scheme = scheme.lower().strip()
		try:
			domain = Domain(netloc)
		except ValueError:
			raise InvalidURL(url_string=url_string)

		if scheme == "https":
			domain.port = domain.port or 443
		elif scheme == "http":
			domain.port = domain.port or 80
		else:
			raise InvalidURL(url_string=url_string)
		return scheme, domain, Path(path), QueryString(qs), fragment

	@staticmethod
	def _parse_full_path(part):
		pattern = "([^?]*)(?:\?([^#]*))?(?:#(.*))?"
		match = re.match(pattern, part)
		return match.group(1), QueryString(match.group(2)), match.group(3)

	def _build_str(self):
		s = self.get_full_domain_with_path()
		if self.query_string:
			s += "?{}".format(self.query_string)
		if self.fragment:
			s += "?{}".format(self.fragment)
		return s

	def get_full_domain(self):
		return "{scheme}://{domain}".format(scheme=self.scheme, domain=str(self.domain))

	def get_full_domain_with_path(self):
		s = self.get_full_domain()
		if self.path:
			s += self.path.absolute_path
		return s

	def join(self, part):
		path, query_string, fragment = self._parse_full_path(part)
		url = URL(self.get_full_domain_with_path())
		url.path.join(part)
		url.query_string = query_string
		url.fragment = fragment
		return url
