#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_snapshot_info
version_added: "2.7.0"
short_description: Get the Azure Snapshot instance facts
description:
    - Get or list instance facts of Azure Snapshot.
options:
    resource_group:
        description:
            - The name of the resource group.
        required: true
        type: str
    name:
        description:
            - Resource name.
        type: str
    tags:
        description:
            - Limit results by providing a list of tags. Format tags as 'key' or 'key:value'.
        type: list
        elements: str
extends_documentation_fragment:
    - azure.azcollection.azure
author:
    - xuzhang3 (@xuzhang3)
    - Fred-sun (@Fred-sun)

'''

EXAMPLES = '''
- name: Get the snapshot instance by name
  azure_rm_snapshot_info:
    resource_group: myResourceGroup
    name: mySnapshot

- name: List all snapshots by resource group and filter by tags
  azure_rm_snapshot_info:
    resource_group: myResourceGroup
    name: mySnapshot
'''

RETURN = '''
state:
    description:
        - The description of the snapshot instance facts.
    type: complex
    returned: always
    contains:
        id:
            description:
                - The Snapshot instance ID.
            type: str
            returned: always
            sample: /subscription/xxx-xxx/resourceGroups/testRG/providers/Microsoft.Compute/snapshots/mySnapshot01
        location:
            description:
                - The Snapshot instance location.
            type: str
            returned: always
            sample: eastus
        name:
            description:
                - The Snapshot instance name.
            type: str
            returned: always
            sample: mySnapshot01
        properties:
            description:
                - The properties of the snapshot instance.
            type: dict
            returned: always
            sample: {
                    "creationData": {
                        "createOption": "Import",
                        "sourceUri": "https://vmforimagerpfx01.blob.core.windows.net/vhds/vmforimagerpfx01.vhd"
                    },
                    "diskSizeBytes": 32213303296,
                    "diskSizeGB": 30,
                    "diskState": "Unattached",
                    "encryption": {
                        "type": "EncryptionAtRestWithPlatformKey"
                    },
                    "incremental": false,
                    "networkAccessPolicy": "AllowAll",
                    "provisioningState": "Succeeded",
                    "publicNetworkAccess": "Enabled",
                    "timeCreated": "2024-08-01T07:08:32.1635314+00:00",
                    "uniqueId": "85607f7a-ce44-40bd-a523-a7e2a10d72c3"
                   }
        sku:
            description:
                - The snapshots sku option.
            type: complex
            returned: always
            contains:
                name:
                    description:
                        - The Sku name.
                    type: str
                    returned: always
                    sample: Standard_LRS
                tier:
                    description:
                        - The Sku tier.
                    type: str
                    returned: always
                    sample: Standard
        tags:
            description:
                - Resource tags.
            type: dict
            returned: always
            sample: {'key1': 'value1'}
        type:
            description:
                - Resource type.
            type: str
            returned: always
            sample: Microsoft.Compute/snapshots
'''

import json
from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common_ext import AzureRMModuleBaseExt
from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common_rest import GenericRestClient


class AzureRMSnapshotsInfo(AzureRMModuleBaseExt):
    def __init__(self):
        self.module_arg_spec = dict(
            resource_group=dict(
                type='str',
                required=True
            ),
            name=dict(
                type='str',
            ),
            tags=dict(
                type='list',
                elements='str'
            )
        )

        self.resource_group = None
        self.name = None
        self.tags = None

        self.results = dict(changed=False)
        self.mgmt_client = None
        self.url = None

        self.query_parameters = {}
        self.status_code = [200, 201, 202]
        self.query_parameters['api-version'] = '2022-03-02'
        self.header_parameters = {}
        self.header_parameters['Content-Type'] = 'application/json; charset=utf-8'

        super(AzureRMSnapshotsInfo, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                   supports_check_mode=True,
                                                   facts_module=True,
                                                   supports_tags=False)

    def exec_module(self, **kwargs):
        for key in list(self.module_arg_spec.keys()):
            setattr(self, key, kwargs[key])

        response = None

        self.mgmt_client = self.get_mgmt_svc_client(GenericRestClient,
                                                    base_url=self._cloud_environment.endpoints.resource_manager)

        if self.name is not None:
            self.results['state'] = self.get()
        else:
            self.results['state'] = self.list_by_resourcegroup()

        return self.results

    def get(self):
        self.url = ('/subscriptions' +
                    '/{{ subscription_id }}' +
                    '/resourceGroups' +
                    '/{{ resource_group }}' +
                    '/providers' +
                    '/Microsoft.Compute' +
                    '/snapshots' +
                    '/{{ snapshot_name }}')
        self.url = self.url.replace('{{ subscription_id }}', self.subscription_id)
        self.url = self.url.replace('{{ resource_group }}', self.resource_group)
        self.url = self.url.replace('{{ snapshot_name }}', self.name)
        response = None
        try:
            response = self.mgmt_client.query(url=self.url,
                                              method='GET',
                                              query_parameters=self.query_parameters,
                                              header_parameters=self.header_parameters,
                                              body=None,
                                              expected_status_codes=self.status_code,
                                              polling_timeout=600,
                                              polling_interval=30)
            response = json.loads(response.body())
            self.log("Response : {0}".format(response))
        except Exception as e:
            self.log('Did not find the Snapshot instance.')
        if response and self.has_tags(response.get('tags'), self.tags):
            return [response]
        else:
            return []

    def list_by_resourcegroup(self):
        self.url = ('/subscriptions' +
                    '/{{ subscription_id }}' +
                    '/resourceGroups' +
                    '/{{ resource_group }}' +
                    '/providers' +
                    '/Microsoft.Compute' +
                    '/snapshots')
        self.url = self.url.replace('{{ subscription_id }}', self.subscription_id)
        self.url = self.url.replace('{{ resource_group }}', self.resource_group)
        response = None
        results = []

        try:
            response = self.mgmt_client.query(url=self.url,
                                              method='GET',
                                              query_parameters=self.query_parameters,
                                              header_parameters=self.header_parameters,
                                              body=None,
                                              expected_status_codes=self.status_code,
                                              polling_timeout=600,
                                              polling_interval=30)
            response = json.loads(response.body())
            self.log("Response : {0}".format(response))
            # self.log("Snapshot instance : {0} found".format(response.name))
        except Exception as e:
            self.log('Did not find the Snapshot instance.')
        for item in response['value']:
            if self.has_tags(item.get('tags'), self.tags):
                results.append(item)

        return results


def main():
    AzureRMSnapshotsInfo()


if __name__ == '__main__':
    main()
