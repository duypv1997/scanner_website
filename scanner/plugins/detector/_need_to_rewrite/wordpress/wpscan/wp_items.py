import re


class WpItems:
    FINGERS = [
        {'file': 'readme.txt', 'patterns': ['Stable tag: ([0-9\.]{3,})', 'Version: ([0-9\.]{3,})', '= ([0-9\.]{3,}) =']},
        {'file': 'changelog.txt', 'patterns': ['= ([0-9\.]{3,}) =']}
    ]

    def __init__(self, wordpress):
        self.wp = wordpress

    def find_version(self, url, patterns):
        response = self.wp.plugin.requestor.http.GET(url, cache=False, grep=False)
        for item in patterns:
            regex = re.compile(item)
            match = regex.findall(response.body)
            if match:
                return match[0]
        return None

    def find_from_content(self, type):
        regex = re.compile('wp-content/' + type + '/(.*?)/.*?[css|js]')
        response = self.wp.plugin.requestor.http.GET(self.wp.fr.get_url(), cache=False, grep=False)
        match = regex.findall(response.body)
        items = {}
        for m in match:
            item_name = m.replace('-master', '').replace('.min', '')
            if item_name not in items:
                for finger in self.FINGERS:
                    url = self.wp.fr.get_url().url_join('wp-content/%s/%s/%s'%(type, item_name, finger['file']))
                    ver = self.find_version(url, finger['patterns'])
                    if ver:
                        items[item_name] = {
                            'version': ver,
                            'vulnerabilities': []
                        }
        return items
