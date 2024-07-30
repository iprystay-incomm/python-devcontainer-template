from bt_credential_plugin import bt_plugin


token = "a86aead68ba900b7b94efee2fa0ef33f8cba2fc4f0587bd4c1a55ed6ca184ad12db08f86cc296d387afefacb9ab19f538b0f77fc716eafa77c386280f5a2876f"
url = 'https://passwordvault.incomm.com/BeyondTrust/api/public/v3/'
identifier = 'incommide\SVC-plateng-aap-ide'
# identifier = 'incommrde\SVC-plateng-aap-rde'

print(bt_plugin.backend(url=url, token=token, identifier=identifier, verify_ssl=False, use_cache='Utilize cached data'))
# print(bt_plugin.backend(url=url, token=token, identifier=identifier))
