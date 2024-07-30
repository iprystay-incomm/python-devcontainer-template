import base64
import collections
import requests
from requests.adapters import HTTPAdapter
import urllib3
import time
import json
from cryptography.fernet import Fernet, InvalidToken
from lockfile import LockFile, LockTimeout


cache_file_path = ".bt_credential_plugin_cache"
CredentialPlugin = collections.namedtuple('CredentialPlugin', ['name', 'inputs', 'backend'])
lock = LockFile(cache_file_path)

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

bt_plugin_inputs = {
    'fields': [{
            'id': 'url',
            'label': 'BeyondTrust Server URL',
            'type': 'string',
            'default': 'https://passwordvault.incomm.com/BeyondTrust/api/public/v3/',
        }, {
            'id': 'token',
            'label': 'Authentication Token',
            'type': 'string',
            'secret': True,
        }, {
            'id': 'verify_ssl',
            'label': 'Verify SSL',
            'type': 'boolean',
            'default': True,
        }, {
            'id': 'connect_direct',
            'label': 'Direct Connection',
            'type': 'boolean',
            'default': True,
        }],
        'metadata': [{
            'id': 'identifier',
            'label': 'Service Name Identifier',
            'type': 'string',
            'help_text': 'Service Name Identifier in BeyondTrust System.'
        }],
        'required': ['url', 'token', 'identifier'],
}

def bt_lookup( **kwargs ):
    baseurl = kwargs.get('url')
    token = kwargs.get('token')
    identifier = kwargs.get('identifier')
    verify_ssl = kwargs.get('verify_ssl')
    connect_direct = kwargs.get('connect_direct')
    # use_cache = True if kwargs.get('use_cache')=='Utilize cached data' else False
    use_cache = True

    def retry_loop(s, method, url, data=None, max_tries=5):
        if data is None:
            data = {}
        counter = 1
        while True:
            r = s.request(method, url=f'{baseurl}{url}', json=data, verify=verify_ssl)
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

    fernet = Fernet(base64.urlsafe_b64encode(token[:32].encode()))
    password = None

    if use_cache:
        try:
            try:
                lock.acquire(timeout=60)  # wait up to 60 seconds
            except LockTimeout:
                lock.break_lock()
                lock.acquire()

            with open(cache_file_path, 'r+') as fp:
                lines = []

                for line in fp:
                    line = line.strip()
                    record = json.loads(line)
                    # print(f'{record}\n')
                    exp_date = record.get('next_change_date')
                    exp_datetime = time.mktime(time.strptime(exp_date, "%Y-%m-%dT%H:%M:%S"))
                    now =time.time()
                    if exp_datetime > now:
                        lines.append(f'{line}\n')
                        if record.get('account_name').lower() == identifier.split('\\')[-1].lower():
                            try:
                                password = fernet.decrypt(record.get('password')).decode()
                                #     password decrypted
                            except InvalidToken:
                                pass
                                # print('invalid token for a record')
                    else:
                        pass
                        # print('record expired - deleting from cache')
                fp.seek(0)
                for line in lines:
                    fp.write(line)
                fp.truncate()
            lock.release()
        except FileNotFoundError:
            pass

    if not password:
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        headers = { 'Authorization': f'PS-Auth key={token}; runas={identifier}',
                    'Content-Type': 'application/json; odata=verbose',
                    'accept': 'application/json; odata=verbose' }

        with requests.Session() as session:
            session.mount('https://', HostHeaderSSLAdapter())
            session.headers.update(headers)
            if not connect_direct:
                https_proxy = 'http://172.16.70.2:8888'
                session.proxies.update({ 'https': https_proxy })

            retry_loop(session, "post", "Auth/SignAppIn")

            response = retry_loop(session, "get", "ManagedAccounts?SystemName=PasswordVault")

            account_name = identifier.split('\\')[1]
            for account_dict in response.json():
                if account_dict['AccountName'] == account_name:
                    account = {
                        'svc_acc_sys_id': account_dict.get('SystemId'),
                        'svc_acc_id': account_dict.get('AccountId'),
                        'next_change_date': account_dict.get('NextChangeDate'),
                        'account_name': account_name
                    }
                    break
            else:
                raise Exception(f'No information can be found about {identifier}')

            data = {
                "AccessTypes": "View",
                "SystemID": f"{account.get('svc_acc_sys_id')}",
                "AccountID": f"{account.get('svc_acc_id')}",
                "DurationMinutes": "20",
                "Reason": "API_CheckOut",
                "RotateInCheckin": "False"
            }
            retry_loop(session, "post", "Requests", data=data)

            response = retry_loop(session, "get", "Requests")
            request_id = response.json()[0]['RequestID']

            response = retry_loop(session, "get", f'Credentials/{request_id}?type=password')
            password = response.text.strip('\"')

            if use_cache:
                try:
                    lock.acquire(timeout=5)  # wait up to 60 seconds
                    account['password'] = (fernet.encrypt(password.encode())).decode()
                    new_record = json.dumps(account)
                    with open(cache_file_path, 'a') as fp:
                        fp.write(f'{new_record}\n')
                    lock.release()
                except LockTimeout:
                    pass

            data = { "Reason": "CheckOutReason" }
            retry_loop(session, "put", f'Requests/{request_id}/Checkin', data=data)

            retry_loop(session, "post", 'Auth/Signout')
    return password

bt_plugin = CredentialPlugin(
    'BT AWX Credential Plugin',
    inputs = bt_plugin_inputs,
    backend = bt_lookup
)