#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: azure_rm_batchaccountapplicationpackage_info
version_added: "3.0.0"
short_description: Get the Batch Account Application Package facts
description:
    - Get the Batch Account Application Package facts.

options:
    resource_group:
        description:
            - The name of the resource group in which to create the Batch Account.
        type: str
        required: true
    batch_account_name:
        description:
            - The name of the Batch Account.
        type: str
        required: true
    application_name:
        description:
            - The name of the batch account application.
        type: str
        required: true
    name:
        description:
            - The name of the batch account application package.
        type: str

extends_documentation_fragment:
    - azure.azcollection.azure

author:
    - xuzhang3 (@xuzhang3)
    - Fred Sun (@Fred-sun)
'''

EXAMPLES = '''
- name: Get the Batch Account Application Package by name
  azure_rm_batchaccountapplicationpackage_info:
    resource_group: MyResGroup
    batch_account_name: batchname01
    application_name: mybatchaccountapplication
    name: mybatchaccountapplicationpackage

- name: List the Batch Account Application Package
  azure_rm_batchaccountapplicationpackage_info:
    resource_group: MyResGroup
    batch_account_name: batchname01
    application_name: mybatchaccountapplication
'''

RETURN = '''
batch_account_application_package:
    description:
        - The specified application package/
    type: complex
    returned: always
    contains:
        id:
            description:
                - The ID of the application package.
            type: str
            returned: always
            sample: "/subscriptions/xxx-xxx/resourceGroups/testRG/providers/Microsoft.Batch/batchAccounts/batch01/applications/app01/versions/version01"
        resource_group:
            description:
                - The resource group of the application package.
            type: str
            returned: always
            sample: testRG
        name:
            description:
                - The name of the resource.
            type: str
            returned: always
            sample: version01
        batch_account_name:
            description:
                - The name of the batch account.
            type: str
            returned: always
            sample: batch01
        application_name:
            description:
                - The name of the application.
            type: str
            returned: always
            sample: app01
        etag:
            description:
                - The ETag of the resource, used for concurrency statements.
            type: str
            returned: always
            sample: 0x8DCFCE1E9B31502
        format:
            description:
                - The format of the application package, if the package is active.
            type: str
            returned: always
            sample: zip
        last_activation_time:
            description:
                - The time at which the package was last activated, if the package is active.
            type: str
            returned: always
            sample: '2024-11-04T15:03:59.834538Z'
        state:
            description:
                - The current state of the application package.
            type: str
            returned: always
            sample: Active
        storage_url:
            description:
                - The URL for the application package in Azure Storage.
            type: str
            returned: always
            sample: null
        storage_url_expiry:
            description:
                - The UTC time at which the Azure Storage URL will expire.
            type: str
            returned: always
            sample: null
        type:
            description:
                - The type of the batch account application package.
            type: str
            returned: always
            sample: Microsoft.Batch/batchAccounts/applications/versions
'''

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common_ext import AzureRMModuleBase

try:
    from azure.core.exceptions import HttpResponseError
except ImportError:
    # This is handled in azure_rm_common
    pass


class AzureRMBatchAccountApplicationPackageInfo(AzureRMModuleBase):
    """Configuration class for an Azure RM Batch Account Application Package resource"""

    def __init__(self):
        self.module_arg_spec = dict(
            resource_group=dict(
                type='str',
                required=True,
            ),
            batch_account_name=dict(
                type='str',
                required=True
            ),
            application_name=dict(
                type='str',
                required=True
            ),
            name=dict(
                type='str',
            ),
        )

        self.resource_group = None
        self.batch_account_name = None
        self.application_name = None
        self.name = None

        self.results = dict(changed=False)

        super(AzureRMBatchAccountApplicationPackageInfo, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                                        supports_check_mode=True,
                                                                        supports_tags=False)

    def exec_module(self, **kwargs):
        """Main module execution method"""

        for key in list(self.module_arg_spec.keys()):
            setattr(self, key, kwargs[key])

        response = []

        if self.name is not None:
            response = [self.get_application_package()]
        else:
            response = self.list_by_application_package()

        self.results['batch_account_application_package'] = [self.format_item(item) for item in response]

        return self.results

    def list_by_application_package(self):
        self.log("List all Batch Account Application Package in the batch account application {0}".format(self.batch_account_name))
        result = []
        response = []
        try:
            response = self.batch_account_client.application_package.list(resource_group_name=self.resource_group,
                                                                          account_name=self.batch_account_name,
                                                                          application_name=self.application_name)
            self.log("Response : {0}".format(response))
        except Exception as e:
            self.log('Did not find the Batch Account instance. Exception as {0}'.format(e))
        for item in response:
            result.append(item.as_dict())
        return result

    def get_application_package(self):
        '''
        Gets the properties of the specified Batch Account Application Package
        '''
        self.log("Fetch the Batch Account instance {0} is present".format(self.name))
        try:
            response = self.batch_account_client.application_package.get(resource_group_name=self.resource_group,
                                                                         account_name=self.batch_account_name,
                                                                         application_name=self.application_name,
                                                                         version_name=self.name)
            self.log("Response : {0}".format(response))
        except HttpResponseError:
            self.log('Did not find the Batch Account Application Package instance.')
            return
        return response.as_dict() if response else None

    def format_item(self, item):
        result = {
            'resource_group': self.resource_group,
            'batch_account_name': self.batch_account_name,
            'application_name': self.application_name,
            'id': item['id'],
            'name': item['name'],
            'type': item['type'],
            'etag': item['etag'],
            'state': item['state'],
            'format': item.get('format'),
            'storage_url': item.get('storage_url'),
            'storage_url_expiry': item.get('storage_url_expiry'),
            'last_activation_time': item.get('last_activation_time'),
        } if item is not None else None
        return result


def main():
    """Main execution"""
    AzureRMBatchAccountApplicationPackageInfo()


if __name__ == '__main__':
    main()
