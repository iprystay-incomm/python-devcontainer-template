#!/usr/bin/env python

from setuptools import setup

requirements = []  # add Python dependencies here
# e.g., requirements = ["PyYAML"]

setup(
    name='bt-credential-plugin',
    version='0.1',
    author='Ansible, Inc.',
    author_email='info@ansible.com',
    description='BeyondTrust Credential lookup plugin for AAP',
    long_description='',
    license='None',
    keywords='ansible',
    url='https://github.com/iprystay-incomm/python-devcontainer-template',
    packages=['bt_credential_plugin'],
    include_package_data=True,
    zip_safe=False,
    setup_requires=[],
    install_requires=requirements,
    entry_points = {
        'awx.credential_plugins': [
            'bt_plugin = bt_credential_plugin:bt_plugin',
        ]
    }
)