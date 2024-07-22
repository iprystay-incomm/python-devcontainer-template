import awx_custom_credential_plugin_example

plugin = awx_custom_credential_plugin_example.example_plugin
print(plugin)
print(plugin.backend)
print(plugin.backend(url="test", identifier="email", token="VALID"))
