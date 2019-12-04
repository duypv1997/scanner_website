from .wp_items import WpItems


class WpThemes(WpItems):
    def find(self):
        for method in dir(self):
            if method.startswith('find_from_'):
                getattr(self, method)()

    def find_from_content(self):
        # regex = re.compile('wp-content/themes/(.*?)/.*?[css|js].*?ver=([0-9.]*)')
        # match = regex.findall(wordpress.index.text)
        # themes = {}
        # for m in match:
        #     theme_name = m[0].replace('-master', '').replace('.min', '')
        #     if m[1] != '1':
        #         if theme_name not in themes.keys():
        #             themes[theme_name] = {'version': m[1], 'vulnerabilities': []}
        #         else:
        #             themes[theme_name]['version'] = lastest_version(themes[theme_name]['version'], m[1])
        self.wp.themes = WpItems.find_from_content(self, type='themes')
