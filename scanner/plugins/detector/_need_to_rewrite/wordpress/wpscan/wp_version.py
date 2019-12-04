from w3af.core.data.request.fuzzable_http_request import FuzzableHTTPRequest

import re


class WpVersion:
    def __init__(self, wordpress):
        self.wp = wordpress

    def find(self):
        for method in dir(WpVersion):
            if method.startswith('find_from_'):
                if getattr(self, method)():
                    return True
        return False

    def scan_url(self, pattern, path=None):
        url = self.wp.fr.get_url()
        if path:
            url = url.url_join(path)
        r = self.wp.plugin.requestor.http.GET(url, cache=False, grep=False)
        regex = re.compile(pattern, flags=re.IGNORECASE)
        match = regex.findall(r.body)
        if match:
            self.wp.version = match[0]
            fr = FuzzableHTTPRequest.from_http_response(r)
            self.wp.plugin.kb_update_web_technology("Wordpress", version=self.wp.version, mutant=fr, traffic_ids=[r.id])
            return True
        return False

    def find_from_meta_generator(self):
        pattern = 'meta name="generator" content="WordPress (.*?)"'
        return self.scan_url(pattern)

    def find_from_rss_generator(self):
        pattern = 'generator>https://wordpress.org/\?v=(.*?)</generator'
        path = 'feed/'
        return self.scan_url(pattern, path)

    def find_from_rdf_generator(self):
        pattern = '<admin:generatorAgent rdf:resource="https://wordpress.org/\?v=(.*?)" />'
        path = 'feed/rdf/'
        return self.scan_url(pattern, path)

    def find_from_atom_generator(self):
        pattern = '<generator uri="https://wordpress.org/" version="(.*?)">WordPress</generator>'
        path = 'feed/atom/'
        return self.scan_url(pattern, path)

    def find_from_readme(self):
        pattern = '<br />\sversion (.*?)'
        path = 'readme.html'
        return self.scan_url(pattern, path)

    def find_from_sitemap_generator(self):
        pattern = 'generator="wordpress/(.*?)"'
        path = 'sitemap.xml'
        return self.scan_url(pattern, path)

    def find_from_links_opml(self):
        pattern = 'generator="wordpress/(.*?)"'
        path = 'wp-links-opml.php'
        return self.scan_url(pattern, path)

    # @staticmethod
    # def find_from_hash(wordpress):
    #     versions = ElementTree.fromstring(WpData.md5_versions())
    #     for file in versions:
    #         try:
    #             r = requests.get(wordpress.url + file.attrib['src'], headers={"User-Agent": wordpress.agent}, verify=False).text
    #             md5sum = hashlib.md5(r).hexdigest()
    #             print file.attrib['src'],  md5sum
    #             for hash in file:
    #                 if md5sum == hash.attrib['md5']:
    #                     wordpress.version = hash[0].text
    #                     return True
    #         except Exception:
    #             pass
    #     return False


def latest_version(ver1, ver2):
    if ver1 is None or ver1 == '':
        return ver2
    if ver2 is None or ver2 == '':
        return ver1
    if ver1 == ver2:
        return ver1
    num1 = ver1.split('.')
    num1.append(-1)
    num2 = ver2.split('.')
    num2.append(-1)
    for i in range(len(num1)):
        if int(num1[i]) > int(num2[i]):
            return ver1
        elif int(num1[i]) < int(num2[i]):
            return ver2


if __name__ == '__main__':
    pass
