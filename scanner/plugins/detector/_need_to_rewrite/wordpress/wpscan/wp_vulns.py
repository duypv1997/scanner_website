import json

from .wp_data import WpData
from .wp_version import latest_version


class WpVulns:
    def __init__(self, wordpress):
        self.wp = wordpress

    def find(self):
        for method in dir(self):
            if method.startswith('find_based_'):
                getattr(self, method)()

    def find_based_wp_version(self):
        versions = json.loads(WpData.versions())
        if self.wp.version in versions:
            self.wp.version_vulns = versions[self.wp.version]['vulnerabilities']

    def find_based_plugins(self):
        plugins = json.loads(WpData.plugins())
        for plugin_name in self.wp.plugins:
            if plugin_name in plugins:
                for vuln in plugins[plugin_name]['vulnerabilities']:
                    if self.wp.plugins[plugin_name]['version'] != latest_version(self.wp.plugins[plugin_name]['version'], vuln['fixed_in']):
                        self.wp.plugins[plugin_name]['vulnerabilities'].append(vuln)

    def find_based_themes(self):
        themes = json.loads(WpData.themes())
        for theme_name in self.wp.themes:
            if theme_name in themes:
                for vuln in themes[theme_name]['vulnerabilities']:
                    if self.wp.themes[theme_name]['version'] != latest_version(self.wp.themes[theme_name]['version'], vuln['fixed_in']):
                        self.wp.themes[theme_name]['vulnerabilities'].append(vuln)
