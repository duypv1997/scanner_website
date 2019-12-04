from .wp_items import WpItems


class WpPlugins(WpItems):
    def find(self):
        for method in dir(self):
            if method.startswith('find_from_'):
                getattr(self, method)()

    def find_from_content(self):
        # regex = re.compile('wp-content/plugins/(.*?)/.*?[css|js].*?ver=([0-9.]*)')
        # match = regex.findall(wordpress.index.text)
        # plugins = {}
        # for m in match:
        #     plugin_name = m[0].replace('-master', '').replace('.min', '')
        #     if m[1] != '1':
        #         if plugin_name not in plugins.keys():
        #             plugins[plugin_name] = {'version': m[1], 'vulnerabilities': []}
        #         else:
        #             plugins[plugin_name]['version'] = lastest_version(plugins[plugin_name]['version'], m[1])
        self.wp.plugins = WpItems.find_from_content(self, type='plugins')
