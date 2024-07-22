import collections
import requests
from requests.adapters import HTTPAdapter
import urllib3
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
CredentialPlugin = collections.namedtuple('CredentialPlugin', ['name', 'inputs', 'backend'])

class HostHeaderSSLAdapter(HTTPAdapter):
    def resolve(self, hostname):
        # a dummy DNS resolver
        resolutions = {
            'passwordvault.incomm.com': '10.114.9.73',
        }
        return resolutions.get(hostname)

    def send(self, request, **kwargs):
        from urllib.parse import urlparse

        connection_pool_kwargs = self.poolmanager.connection_pool_kw

        result = urlparse(request.url)
        resolved_ip = self.resolve(result.hostname)

        if result.scheme == 'https' and resolved_ip:
            request.url = request.url.replace(
                'https://' + result.hostname,
                'https://' + resolved_ip,
            )
            connection_pool_kwargs['server_hostname'] = result.hostname  # SNI
            connection_pool_kwargs['assert_hostname'] = result.hostname

            # overwrite the host header
            request.headers['Host'] = result.hostname
        else:
            # those headers from a previous request may have been left
            connection_pool_kwargs.pop('server_hostname', None)
            connection_pool_kwargs.pop('assert_hostname', None)

        return super(HostHeaderSSLAdapter, self).send(request, **kwargs)

def bt_lookup(https_proxy=None, **kwargs):
    #
    # IMPORTANT:
    # This section of code *actually*
    # interfaces with third party credential system
    #
    baseurl = kwargs.get('url')
    token = kwargs.get('token')
    identifier = kwargs.get('identifier')

    headers = { 'Authorization': f'PS-Auth key={token}; runas={identifier}',
                'Content-Type': 'application/json; odata=verbose',
                'accept': 'application/json; odata=verbose' }

    def retry_loop(s, method, url, data=None, max_tries=5):
        if data is None:
            data = {}
        counter = 1
        while True:
            r = s.request(method, url=f'{baseurl}{url}', json=data, verify=False)
            if 200 <= r.status_code <= 226 or r.status_code == 409:
                return r
            else:
                print(f'{method} URL: {url}\nError code: {r.status_code}\nError text: {r.text}.\nTrying again...')
                s.close()
                if counter == max_tries:
                    assert counter != max_tries
                else:
                    counter += 1
                    time.sleep(5)

    with requests.Session() as session:
        session.mount('https://', HostHeaderSSLAdapter())
        session.headers.update(headers)
        if https_proxy:
            session.proxies.update({ 'https': https_proxy })

        retry_loop(session, "post", "Auth/SignAppIn")

        response = retry_loop(session, "get", "ManagedAccounts?SystemName=PasswordVault")

        account_name = identifier.split('\\')[1]
        for account_dict in response.json():
            if account_dict['AccountName'] == account_name:
                svc_acc_sys_id = account_dict.get('SystemId')
                svc_acc_id = account_dict.get('AccountId')
                break
        else:
            svc_acc_sys_id = None
            svc_acc_id = None
            raise Exception(f'No information can be found about {identifier}')

        data = {
            "AccessTypes": "View",
            "SystemID": f"{svc_acc_sys_id}",
            "AccountID": f"{svc_acc_id}",
            "DurationMinutes": "20",
            "Reason": "API_CheckOut",
            "RotateInCheckin": "False"
        }
        retry_loop(session, "post", "Requests", data=data)

        response = retry_loop(session, "get", "Requests")
        request_id = response.json()[0]['RequestID']

        response = retry_loop(session, "get", f'Credentials/{request_id}?type=password')
        password = response.text.strip('\"')
        # print(f'password: {password}')

        data = { "Reason": "CheckOutReason" }
        retry_loop(session, "put", f'Requests/{request_id}/Checkin', data=data)

        retry_loop(session, "post", 'Auth/Signout')
    return password

bt_plugin = CredentialPlugin(
    'BT AWX Credential Plugin',
    inputs={
        'fields': [{
            'id': 'url',
            'label': 'BeyondTrust Server URL',
            'type': 'string',
        }, {
            'id': 'token',
            'label': 'Authentication Token',
            'type': 'string',
            'secret': True,
        }],
        'metadata': [{
            'id': 'identifier',
            'label': 'Service Name Identifier',
            'type': 'string',
            'help_text': 'Service Name Identifier in BeyondTrust System.'
        }],
        'required': ['url', 'token', 'identifier'],
    },
    backend = bt_lookup
)