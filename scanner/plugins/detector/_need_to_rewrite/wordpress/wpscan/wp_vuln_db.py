import requests


class WpVulnDb:
    BASE_URL = 'https://wpvulndb.com/api/v3/'
    TOKEN = 'cqCtq68HwHjc1RMg67MgBop2DsqzI8CjLbqsaOpyULw'
    HEADERS = {
        'Authorization': 'Token token=' + TOKEN
    }

    def __init__(self):
        pass

    @classmethod
    def get(cls, api, data):
        try:
            return requests.get(cls.BASE_URL + api + data, headers=cls.HEADERS).content
        except Exception as e:
            print e
            return None

    @classmethod
    def by_version(cls, version_name):
        return cls.get('wordpresses/', version_name.replace('.', ''))

    @classmethod
    def by_plugin(cls, plugin_name):
        return cls.get('plugins/', plugin_name)

    @classmethod
    def by_theme(cls, theme_name):
        return cls.get('themes/', theme_name)


if __name__ == '__main__':
    pass
