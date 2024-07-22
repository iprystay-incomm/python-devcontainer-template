import collections
import os
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

def bt_lookup(**kwargs):
    #
    # IMPORTANT:
    # This section of code *actually*
    # interfaces with third party credential system
    #
    # baseurl = kwargs.get('url')
    baseurl = 'https://passwordvault.incomm.com/BeyondTrust/api/public/v3/'
    # token = kwargs.get('token')
    token = "a86aead68ba900b7b94efee2fa0ef33f8cba2fc4f0587bd4c1a55ed6ca184ad12db08f86cc296d387afefacb9ab19f538b0f77fc716eafa77c386280f5a2876f"
    # identifier = kwargs.get('identifier')
    # identifier = 'incommrde\SVC-plateng-aap-rde'
    identifier = 'incommide\SVC-plateng-aap-ide'

    # if token != 'VALID':
    #     raise ValueError('Invalid token!')

    headers = { 'Authorization': f'PS-Auth key={token}; runas={identifier}',
                'Content-Type': 'application/json; odata=verbose',
                'accept': 'application/json; odata=verbose' }
    https_proxy = 'http://172.16.70.2:8888'
    # https_proxy = os.environ.get('https_proxy')

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
                svc_acc_principal_name = account_dict.get('UserPrincipalName')
                break
        else:
            svc_acc_sys_id = None
            svc_acc_id = None
            svc_acc_principal_name = None
            raise Exception(f'No information can be found about {identifier}')

        print(svc_acc_principal_name, f'SystemId={svc_acc_sys_id} AccountId={svc_acc_id}')

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
        print(f'password: {password}')

        data = { "Reason": "CheckOutReason" }
        retry_loop(session, "put", f'Requests/{request_id}/Checkin', data=data)

        retry_loop(session, "post", 'Auth/Signout')
    return password



example_plugin = CredentialPlugin(
    'Example AWX Credential Plugin',
    # see: https://docs.ansible.com/ansible-tower/latest/html/userguide/credential_types.html
    # inputs will be used to create a new CredentialType() instance
    #
    # inputs.fields represents fields the user will specify *when they create*
    # a credential of this type; they generally represent fields
    # used for authentication (URL to the credential management system, any
    # fields necessary for authentication, such as an OAuth2.0 token, or
    # a username and password). They're the types of values you set up _once_
    # in AWX
    #
    # inputs.metadata represents values the user will specify *every time
    # they link two credentials together*
    # this is generally _pathing_ information about _where_ in the external
    # management system you can find the value you care about i.e.,
    #
    # "I would like Machine Credential A to retrieve its username using
    # Credential-O-Matic B at identifier=some_key"
    inputs={
        'fields': [{
            'id': 'url',
            'label': 'Server URL',
            'type': 'string',
        }, {
            'id': 'token',
            'label': 'Authentication Token',
            'type': 'string',
            'secret': True,
        }],
        'metadata': [{
            'id': 'identifier',
            'label': 'Identifier',
            'type': 'string',
            'help_text': 'The name of the key in My Credential System to fetch.'
        }],
        'required': ['url', 'token', 'secret_key'],
    },
    # backend is a callable function which will be passed all the values
    # defined in `inputs`; this function is responsible for taking the arguments,
    # interacting with the third party credential management system in question
    # using Python code, and returning the value from the third party
    # credential management system
    backend = bt_lookup()
)