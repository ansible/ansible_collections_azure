#!/usr/bin/python
#
# Copyright (c) 2020 Haiyuan Zhang <haiyzhan@micosoft.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_openshiftmanagedclusterversion_info
version_added: '2.7.0'
short_description: Fetch available versions of Azure Red Hat OpenShift Managed Cluster
description:
    - fetch available version of Azure Red Hat OpenShift Managed Cluster instance.
options:
    location:
        description:
            - List install versions available for the defined region.
        required: true
        type: str
extends_documentation_fragment:
    - azure.azcollection.azure
author:
    - Maxim Babushkin (@maxbab)
'''

EXAMPLES = '''
- name: Obtain openshift versions for ARO cluster
  azure_rm_openshiftmanagedclusterversion_info:
    location: centralus
'''

RETURN = '''
versions:
    description:
        - openshift versions values
    returned: always
    type: list
'''

import json
from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common_ext import AzureRMModuleBaseExt
from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common_rest import GenericRestClient


class Actions:
    NoAction, Create, Update, Delete = range(4)


class AzureRMOpenShiftManagedClustersVersionInfo(AzureRMModuleBaseExt):
    def __init__(self):
        self.module_arg_spec = dict(
            location=dict(
                type='str', required=True
            )
        )

        self.location = None

        self.results = dict(changed=False)
        self.mgmt_client = None
        self.state = None
        self.url = None
        self.status_code = [200]

        self.query_parameters = {}
        self.query_parameters['api-version'] = '2023-11-22'
        self.header_parameters = {}
        self.header_parameters['Content-Type'] = 'application/json; charset=utf-8'

        self.mgmt_client = None
        super(AzureRMOpenShiftManagedClustersVersionInfo, self).__init__(self.module_arg_spec, supports_check_mode=True, supports_tags=False)

    def exec_module(self, **kwargs):

        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        self.mgmt_client = self.get_mgmt_svc_client(GenericRestClient,
                                                    base_url=self._cloud_environment.endpoints.resource_manager)
        self.results = self.get_versions()
        return self.results

    def get_versions(self):
        response = None
        resp_results = {}
        results = {}
        # prepare url
        self.url = ('/subscriptions' +
                    '/{{ subscription_id }}' +
                    '/providers' +
                    '/Microsoft.RedHatOpenShift' +
                    '/locations' +
                    '/{{ location }}' +
                    '/openshiftversions')
        self.url = self.url.replace('{{ subscription_id }}', self.subscription_id)
        self.url = self.url.replace('{{ location }}', self.location)
        self.log("Fetch versions of openshift cluster.")
        try:
            response = self.mgmt_client.query(self.url,
                                              'GET',
                                              self.query_parameters,
                                              self.header_parameters,
                                              None,
                                              self.status_code,
                                              600,
                                              30)
            if isinstance(response.text, str):
                resp_results = json.loads(response.text)
            else:
                resp_results = json.loads(response.text())
        except Exception as e:
            self.log('Could not get info for @(Model.ModuleOperationNameUpper).')
        results['versions'] = self.format_versions(resp_results)
        return results

    def format_versions(self, version):
        result = list()
        if version.get('value'):
            for ver in version['value']:
                result.append(ver.get('properties').get('version'))
        return result


def main():
    AzureRMOpenShiftManagedClustersVersionInfo()


if __name__ == '__main__':
    main()
