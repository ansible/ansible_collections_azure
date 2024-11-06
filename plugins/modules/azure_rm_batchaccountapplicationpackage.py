#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: azure_rm_batchaccountapplicationpackage
version_added: "3.0.0"
short_description: Manages a Batch Account Application Package on Azure
description:
    - Create, update and delete instance of Azure Batch Account Application Package.

options:
    resource_group:
        description:
            - The name of the resource group in which to create the Batch Account Application Package.
        required: true
        type: str
    batch_account_name:
        description:
            - The name of the Batch Account.
        required: true
        type: str
    application_name:
        description:
            - The name of the Batch Account Application.
        type: str
        required: true
    name:
        description:
            - The name of the Batch Account Application Package.
        required: true
        type: str
    format:
        description:
            - The format of the application package, if the package is active.
            - Sample as C(zip).
        type: str
    is_activate:
        description:
            - Whether to activates the specified application package.
        type: bool
        default: false
    state:
        description:
            - Assert the state of the Batch Account Application Package.
            - Use C(present) to create or update a Batch Account Application Package and C(absent) to delete it.
        default: present
        type: str
        choices:
            - present
            - absent

extends_documentation_fragment:
    - azure.azcollection.azure

author:
    - xuzhang3 (@xuzhang3)
    - Fred Sun (@Fred-sun)
'''

EXAMPLES = '''
- name: Create Batch Account Application Package
  azure_rm_batchaccountapplicationpackage:
    resource_group: MyResGroup
    application_name: mybatchaccountapplication
    batch_account_name: mybatchaccount
    name: version01

- name: Activate the Batch Account Application Package
  azure_rm_batchaccountapplicationpackage:
    resource_group: MyResGroup
    application_name: mybatchaccountapplication
    batch_account_name: mybatchaccount
    name: version01
    is_activate: true
    format: zip

- name: Delete Batch Account Application Package
  azure_rm_batchaccountapplicationpackage:
    resource_group: MyResGroup
    application_name: mybatchaccountapplication
    batch_account_name: mybatchaccount
    name: version01
    state: absent
'''

RETURN = '''
state:
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
    from azure.core.polling import LROPoller
    from azure.core.exceptions import HttpResponseError
except ImportError:
    # This is handled in azure_rm_common
    pass


class AzureRMBatchAccountApplicationPackage(AzureRMModuleBase):
    """Configuration class for an Azure RM Batch Account Application Package resource"""

    def __init__(self):
        self.module_arg_spec = dict(
            resource_group=dict(
                required=True,
                type='str'
            ),
            batch_account_name=dict(
                type='str',
                required=True,
            ),
            application_name=dict(
                type='str',
                required=True,
            ),
            name=dict(
                required=True,
                type='str'
            ),
            format=dict(
                type='str'
            ),
            is_activate=dict(
                type='bool',
                default=False
            ),
            state=dict(
                type='str',
                default='present',
                choices=['present', 'absent']
            )
        )

        required_if = [('is_activate', True, ['format'])]
        self.resource_group = None
        self.batch_account_name = None
        self.application_name = None
        self.name = None
        self.is_activate = None
        self.results = dict(changed=False)
        self.state = None
        self.body = dict()

        super(AzureRMBatchAccountApplicationPackage, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                                    supports_check_mode=True,
                                                                    required_if=required_if,
                                                                    supports_tags=False)

    def exec_module(self, **kwargs):
        """Main module execution method"""

        for key in list(self.module_arg_spec.keys()):
            if hasattr(self, key):
                setattr(self, key, kwargs[key])
            elif kwargs[key] is not None:
                self.body[key] = kwargs[key]

        response = None
        changed = False

        old_response = self.get_application_package()

        if not old_response:
            self.log("Batch Account Application Package instance doesn't exist")
            if self.state == 'absent':
                self.log("Old instance didn't exist")
            else:
                if not self.check_mode:
                    changed = True
                    response = self.create_application_package()
                    if self.is_activate:
                        self.activate_application_package()
        else:
            self.log("Batch Account Application Package instance already exists")
            if self.state == 'absent':
                if not self.check_mode:
                    changed = True
                    response = self.delete_application_package()
            else:
                if not self.check_mode:
                    if self.is_activate:
                        changed = True
                        self.activate_application_package()

        self.results = dict(
            changed=changed,
            state=response if response else old_response,
        )
        return self.results

    def create_application_package(self):
        '''
        Creates Batch Account Application Package with the specified configuration.
        '''
        self.log("Creating the Batch Account Application Package instance {0}".format(self.name))

        try:
            response = self.batch_account_client.application_package.create(resource_group_name=self.resource_group,
                                                                            account_name=self.batch_account_name,
                                                                            application_name=self.application_name,
                                                                            version_name=self.name,
                                                                            parameters=self.body)
            if isinstance(response, LROPoller):
                response = self.get_poller_result(response)
        except Exception as exc:
            self.log('Error attempting to create the Batch Account Application Package instance.')
            self.fail("Error creating the Batch Account Application Package instance: {0}".format(str(exc)))
        return response.as_dict()

    def activate_application_package(self):
        '''
        Update Batch Account Application Package with the specified configuration.
        '''
        self.log("Updating the Batch Account Application Package instance {0}".format(self.name))

        try:
            response = self.batch_account_client.application_package.activate(resource_group_name=self.resource_group,
                                                                              account_name=self.batch_account_name,
                                                                              application_name=self.application_name,
                                                                              version_name=self.name,
                                                                              parameters=self.body)
            if isinstance(response, LROPoller):
                response = self.get_poller_result(response)
        except Exception as exc:
            self.log('Error attempting to update the Batch Account Application Package instance.')
            self.fail("Error updating the Batch Account Application Package instance: {0}".format(str(exc)))
        return response.as_dict()

    def delete_application_package(self):
        '''
        Deletes specified Batch Account Application Package instance in the specified subscription and resource group.
        :return: True
        '''
        self.log("Deleting the Batch Account Application Package instance {0}".format(self.name))
        try:
            self.batch_account_client.application_package.delete(resource_group_name=self.resource_group,
                                                                 account_name=self.batch_account_name,
                                                                 application_name=self.application_name,
                                                                 version_name=self.name)
        except Exception as e:
            self.log('Error attempting to delete the Batch Account Application Package instance.')
            self.fail("Error deleting the Batch Account Application Package instance: {0}".format(str(e)))

        return True

    def get_application_package(self):
        '''
        Gets the properties of the specified Batch Account Application Package
        :return: deserialized Batch Account Application Package instance state dictionary
        '''
        self.log("Checking if the Batch Account Application Package instance {0} is present".format(self.name))
        found = False
        try:
            response = self.batch_account_client.application_package.get(resource_group_name=self.resource_group,
                                                                         account_name=self.batch_account_name,
                                                                         application_name=self.application_name,
                                                                         version_name=self.name)
            found = True
            self.log("Response : {0}".format(response))
            self.log("Batch Account Application Package instance : {0} found".format(response.name))
        except HttpResponseError as e:
            self.log('Did not find the Batch Account Application Package instance. Exception as {0}'.format(e))
        if found is True:
            return self.format_item(response.as_dict())
        return False

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
    AzureRMBatchAccountApplicationPackage()


if __name__ == '__main__':
    main()
