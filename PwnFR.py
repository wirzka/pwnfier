import requests

class PwnFR(object):
    """Wrapper for the haveIbeenpwnd API version 3
    See  for documentation.
    """

    VERSION = 'APIv3'
    
    
    def __init__(self, api_key=None):
        self._api_key = api_key

    # def __getattr__(self, name):
    #     raise NotImplementedError('{} not available in APIv3'.format(name))

    def _get_response(self, service, parameter=''):
        BASE_URL = 'https://haveibeenpwned.com/api/v3/{service}{parameter}' 
        VALID_SERVICES = (
            'breachedaccount/',
            'breaches',
            'breach/',
            'dataclasses',
            'pasteaccount/'
        )

        if service not in VALID_SERVICES:
            msg = 'Unknown service "{}"'
            raise NotImplementedError(msg.format(service))
        headers = {'hibp-api-key': self._api_key, 'Accept': 'application/json', 'user-agent': 'pwnfier.py'}
        response = requests.get(BASE_URL.format(service=service, parameter=parameter), verify=True,
            headers=headers)
        if response.status_code == 401:
            raise ValueError('Unauthorised — the API key provided was not valid. API key:\n')
        elif response.status_code == 404:
            return 0
        response.raise_for_status()
        return response.json()

    def _get_pwned(self, sha1):
        BASE_URL = 'https://api.pwnedpasswords.com/range/{}'
        headers = {'user-agent': 'pwnfier.py'}
        response = requests.get(BASE_URL.format(sha1), headers=headers)
        if response.status_code == 404:
            return 0
        elif response.status_code == 200:
            return response.content
        else:
            raise ConnectionError('[!] Something strange is happening.. [!]')

    def breachedaccount(self, account):
        return self._get_response('breachedaccount/', account)

    def breaches(self, filter=None):
        if filter:
            return self._get_response('breaches', '?domain={}'.format(filter))
        else:
            return self._get_response('breaches')

    def breach(self, website=None):
        return self._get_response('breach/', website)
   
    # def dataclasses():
    #     return self._get_response('dataclasses')
    def checkPwd(self, sha1):
        return self._get_pwned(sha1)

    def pasteaccount(self, account):
        return self._get_response('pasteaccount/', account)
