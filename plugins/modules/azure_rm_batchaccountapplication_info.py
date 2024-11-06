#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: azure_rm_batchaccountapplication_info
version_added: "3.0.0"
short_description: Get the Batch Account Application facts
description:
    - Get the Batch Account Application facts.

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
    name:
        description:
            - The name of the batch account application.
        type: str

extends_documentation_fragment:
    - azure.azcollection.azure

author:
    - xuzhang3 (@xuzhang3)
    - Fred Sun (@Fred-sun)
'''

EXAMPLES = '''
- name: Get the Batch Account Application by name
  azure_rm_batchaccountapplication_info:
    resource_group: MyResGroup
    batch_account_name: batchname01
    name: mybatchaccount

- name: List the Batch Account Application
  azure_rm_batchaccountapplication_info:
    resource_group: MyResGroup
    batch_account_name: batchname01
'''

RETURN = '''
batch_account_application:
    description:
        - Contains information about an application in a Batch account.
    type: complex
    returned: always
    contains:
        id:
            description:
                - The ID of the batch account application.
            type: str
            returned: always
            sample: "/subscriptions/xxx-xxx/resourceGroups/testRG/providers/Microsoft.Batch/batchAccounts/batch01/applications/app01"
        resource_group:
            description:
                - The resource group name.
            type: str
            returned: always
            sample: testRG
        batch_account_name:
            description:
                - The name of the batch account.
            type: str
            returned: always
            sample: batch01
        name:
            description:
                - The name of the application.
            type: str
            returned: always
            sample: app01
        allow_updates:
            description:
                - A value indicating whether packages within the application may be overwritten using the same version string.
            type: str
            returned: always
            sample: true
        default_version:
            description:
                - The package to use if a client requests the application but does not specify a version.
                - This property can only be set to the name of an existing package.
            type: str
            returned: always
            sample: null
        display_name:
            description:
                - The display name for the application.
            type: str
            returned: always
            sample: testbatch
        type:
            description:
                - The type of the resource.
            type: str
            returned: always
            sample: Microsoft.Batch/batchAccounts/applications
'''

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common_ext import AzureRMModuleBase

try:
    from azure.core.exceptions import ResourceNotFoundError
except ImportError:
    # This is handled in azure_rm_common
    pass


class AzureRMBatchAccountApplicationInfo(AzureRMModuleBase):
    """Configuration class for an Azure RM Batch Account Application package resource"""

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
            name=dict(
                type='str',
            ),
        )

        self.resource_group = None
        self.batch_account_name = None
        self.name = None

        self.results = dict(changed=False)

        super(AzureRMBatchAccountApplicationInfo, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                                 supports_check_mode=True,
                                                                 supports_tags=False)

    def exec_module(self, **kwargs):
        """Main module execution method"""

        for key in list(self.module_arg_spec.keys()):
            setattr(self, key, kwargs[key])

        response = []

        if self.name is not None:
            response = [self.get_batchaccount_application()]
        else:
            response = self.list_by_batchaccount_application()

        self.results['batch_account_application'] = [self.format_item(item) for item in response]

        return self.results

    def list_by_batchaccount_application(self):
        self.log("List all Batch Account in the batch account {0}".format(self.batch_account_name))
        result = []
        response = []
        try:
            response = self.batch_account_client.application.list(resource_group_name=self.resource_group,
                                                                  account_name=self.batch_account_name)
            self.log("Response : {0}".format(response))
        except Exception as e:
            self.log('Did not find the Batch Account instance. Exception as {0}'.format(e))
        for item in response:
            result.append(item.as_dict())
        return result

    def get_batchaccount_application(self):
        '''
        Gets the properties of the specified Batch Account Application
        '''
        self.log("Fetch the Batch Account instance {0} is present".format(self.name))
        try:
            response = self.batch_account_client.application.get(resource_group_name=self.resource_group,
                                                                 account_name=self.batch_account_name,
                                                                 application_name=self.name)
            self.log("Response : {0}".format(response))
        except ResourceNotFoundError:
            self.log('Did not find the Batch Account Application instance.')
            return
        return response.as_dict()

    def format_item(self, item):
        result = {
            'resource_group': self.resource_group,
            'batch_account_name': self.batch_account_name,
            'id': item['id'],
            'name': item['name'],
            'type': item['type'],
            'display_name': item['display_name'],
            'allow_updates': item['allow_updates'],
            'default_version': item['default_version'] if item.get('default_version') is not None else None
        }
        return result


def main():
    """Main execution"""
    AzureRMBatchAccountApplicationInfo()


if __name__ == '__main__':
    main()
