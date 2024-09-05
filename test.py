import argparse
import os
from ansible.constants import DEFAULT_VAULT_ID_MATCH
from ansible.parsing.vault import VaultSecret, VaultLib
from ansible.parsing.vault import AnsibleVaultError

from bt_credential_plugin import bt_plugin

token = '''          $ANSIBLE_VAULT;1.1;AES256
          35393438643736633063633063346163666562373938326665353564323934666637376236373039
          3139613134373861663233313532646466316434653435370a336266663234653361313230613339
          35323764333462623337346438616238643261646434613534323964366537653232316164326135
          6566303061656537320a663332623363623335396132376562333231386166393161306530656462
          34323736613366373961613035633165383363653963386534313765656532356335343137663065
          36316232323463313238663666663265643430643736653463353833356163626130393934623838
          31646235386137623634653865653638663364353463646466646439623038663034333439633934
          35613332663563386635633264613836613163303136306131663030636262313031656631666661
          37326131613531666563633962366131386532663730353963643730383439636563633065316261
          39656566303236396238316464353731383333653635343465323831393838353564393038633938
          326365633963343062343061386238393036
'''
password = os.environ.get('TOKEN_PASSWORD') or input("Define TOKEN_PASSWORD environment var or type it here (will be echoed)\npassword: ")

vault_secrets = [(DEFAULT_VAULT_ID_MATCH, VaultSecret(password.encode()))]
vault = VaultLib(vault_secrets)

try:
    token = vault.decrypt(token.replace(" ", "")).decode()
except AnsibleVaultError as e:
    print(f'Wrong password!\n', e)
    exit()

url = 'https://passwordvault.incomm.com/BeyondTrust/api/public/v3/'
# identifier = 'incommide\SVC-plateng-aap-ide'
identifier = 'incommrde\SVC-plateng-aap-rde'

print(bt_plugin.backend(url=url, token=token, identifier=identifier, use_cache=True))
# print(bt_plugin.backend(url=url, token=token, identifier=identifier))
