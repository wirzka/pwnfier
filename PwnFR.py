import requests

class PwnFR(object):
    """Wrapper for the haveIbeenpwnd API version 3
    See  for documentation.
    """

    VERSION = 'APIv3'

    def __init__(self, api_key=None):
        self._api_key = api_key

    def __getattr__(self, name):
        raise NotImplementedError('{} not available in APIv3'.format(name))

    def _get_response(self, service, parameter=''):
        BASE_URL = 'https://haveibeenpwned.com/api/v3/{service}{parameter}'
        VALID_SERVICES = (
            'breachedaccount',
            'breaches',
            'breach',
            'dataclasses',
            'pasteaccount',
        )

        if service not in VALID_SERVICES:
            msg = 'Unknown service "{}"'
            raise NotImplementedError(msg.format(service))
        headers = {'hibp-api-key': self._api_key, 'Accept': 'application/json', 'user-agent': 'pwnfier.py'}
        response = requests.request(
            method='GET',
            url=BASE_URL.format(service=service, parameter=parameter),
            headers=headers)
        if response.status_code == 401:
            raise ValueError('Unauthorised — the API key provided was not valid. API key:\n')
        elif response.status_code in (422, 429):
            return response.json()['errors']
        response.raise_for_status()
        return response.json()['data']

    def breachedaccount(self, account):
        return self._get_response('breachedaccount', account)

    def breaches(self, filter=None):
        return self._get_response('breaches', '?domain='+filter)

    def breach(self, website=None):
        return self._get_response('breach', website)
   
    # def dataclasses():
    #     return self._get_response('dataclasses')
    def checkPwd(self, pwd):
        return self._get_response()

    def  pasteaccount(self, account):
        return self._get_response('pasteaccount/', account)