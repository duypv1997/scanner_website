import os, zipfile


class WpData:
    data = zipfile.ZipFile(os.path.join(os.path.dirname(__file__), 'data.zip'), 'r')

    def __init__(self):
        pass

    @classmethod
    def md5_versions(cls):
        return cls.data.read('data/wp_versions.xml', 'r')

    @classmethod
    def versions(cls):
        return cls.data.read('data/wordpresses.json', 'r')

    @classmethod
    def plugins(cls):
        return cls.data.read('data/plugins.json', 'r')

    @classmethod
    def themes(cls):
        return cls.data.read('data/themes.json', 'r')


if __name__ == '__main__':
    pass
