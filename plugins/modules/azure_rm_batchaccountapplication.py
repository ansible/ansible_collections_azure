#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: azure_rm_batchaccountapplication
version_added: "3.0.0"
short_description: Manages a Batch Account Application on Azure
description:
    - Create, update and delete instance of Azure Batch Account Application.

options:
    resource_group:
        description:
            - The name of the resource group in which to create the Batch Account Application.
        required: true
        type: str
    batch_account_name:
        description:
            - The name of the Batch Account.
        required: true
        type: str
    name:
        description:
            - The name of the Batch Account Application.
        required: true
        type: str
    display_name:
        description:
            - The display name for the application.
        type: str
    allow_updates:
        description:
            - A value indicating whether packages within the application may be overwritten using the same version string.
        type: bool
    default_version:
        description:
            -  The package to use if a client requests the application but does not specify a version.
            - This property can only be set to the name of an existing package.
        type: str
    state:
        description:
            - Assert the state of the Batch Account Application.
            - Use C(present) to create or update a Batch Account Application and C(absent) to delete it.
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
- name: Create Batch Account Application
  azure_rm_batchaccountapplication:
    resource_group: MyResGroup
    name: mybatchaccountapplication
    batch_account_name: mybatchaccount
    allow_updates: true
    display_name: fredtest

- name: Delete Batch Account Application
  azure_rm_batchaccountapplication:
    resource_group: MyResGroup
    name: mybatchaccountapplication
    batch_account_name: mybatchaccount
    state: absent
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
    from azure.core.polling import LROPoller
    from azure.core.exceptions import ResourceNotFoundError
except ImportError:
    # This is handled in azure_rm_common
    pass


class AzureRMBatchAccountApplication(AzureRMModuleBase):
    """Configuration class for an Azure RM Batch Account Application resource"""

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
            name=dict(
                required=True,
                type='str'
            ),
            display_name=dict(
                type='str'
            ),
            allow_updates=dict(
                type='bool'
            ),
            default_version=dict(
                type='str'
            ),
            state=dict(
                type='str',
                default='present',
                choices=['present', 'absent']
            )
        )

        self.resource_group = None
        self.batch_account_name = None
        self.name = None
        self.results = dict(changed=False)
        self.state = None
        self.body = dict()

        super(AzureRMBatchAccountApplication, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                             supports_check_mode=True,
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

        old_response = self.get_batchaccount_application()

        if not old_response:
            self.log("Batch Account Application instance doesn't exist")
            if self.state == 'absent':
                self.log("Old instance didn't exist")
            else:
                changed = True
                if not self.check_mode:
                    response = self.create_batchaccount_application()
        else:
            self.log("Batch Account Application instance already exists")
            if self.state == 'absent':
                if not self.check_mode:
                    changed = True
                    response = self.delete_batchaccount_application()
            else:
                if self.body.get('default_version') is not None and self.body['default_version'] != old_response['default_version']:
                    changed = True
                else:
                    self.body['default_version'] = old_response['default_version']
                if self.body.get('display_name') and self.body['display_name'] != old_response['display_name']:
                    changed = True
                else:
                    self.body['display_name'] = old_response['display_name']
                if self.body.get('allow_updates') is not None and bool(self.body['allow_updates']) != bool(old_response['allow_updates']):
                    changed = True
                else:
                    self.body['allow_updates'] = old_response['allow_updates']
                if not self.check_mode and changed:
                    response = self.update_batchaccount_application()

        self.results = dict(
            changed=changed,
            state=response,
        )
        return self.results

    def create_batchaccount_application(self):
        '''
        Creates Batch Account Application with the specified configuration.
        '''
        self.log("Creating the Batch Account Application instance {0}".format(self.name))

        try:
            response = self.batch_account_client.application.create(resource_group_name=self.resource_group,
                                                                    account_name=self.batch_account_name,
                                                                    application_name=self.name,
                                                                    parameters=self.body)
            if isinstance(response, LROPoller):
                response = self.get_poller_result(response)
        except Exception as exc:
            self.log('Error attempting to create the Batch Account Application instance.')
            self.fail("Error creating the Batch Account Application instance: {0}".format(str(exc)))
        return response.as_dict()

    def update_batchaccount_application(self):
        '''
        Update Batch Account Application with the specified configuration.
        '''
        self.log("Updating the Batch Account Application instance {0}".format(self.name))

        try:
            response = self.batch_account_client.application.update(resource_group_name=self.resource_group,
                                                                    account_name=self.batch_account_name,
                                                                    application_name=self.name,
                                                                    parameters=self.body)
            if isinstance(response, LROPoller):
                response = self.get_poller_result(response)
        except Exception as exc:
            self.log('Error attempting to update the Batch Account Application instance.')
            self.fail("Error updating the Batch Account Application instance: {0}".format(str(exc)))
        return response.as_dict()

    def delete_batchaccount_application(self):
        '''
        Deletes specified Batch Account Application instance in the specified subscription and resource group.
        :return: True
        '''
        self.log("Deleting the Batch Account Application instance {0}".format(self.name))
        try:
            self.batch_account_client.application.delete(resource_group_name=self.resource_group,
                                                         account_name=self.batch_account_name,
                                                         application_name=self.name)
        except Exception as e:
            self.log('Error attempting to delete the Batch Account Application instance.')
            self.fail("Error deleting the Batch Account Application instance: {0}".format(str(e)))

        return True

    def get_batchaccount_application(self):
        '''
        Gets the properties of the specified Batch Account Application
        :return: deserialized Batch Account Application instance state dictionary
        '''
        self.log("Checking if the Batch Account Application instance {0} is present".format(self.name))
        found = False
        try:
            response = self.batch_account_client.application.get(resource_group_name=self.resource_group,
                                                                 account_name=self.batch_account_name,
                                                                 application_name=self.name)
            found = True
            self.log("Response : {0}".format(response))
            self.log("Batch Account Application instance : {0} found".format(response.name))
        except ResourceNotFoundError as e:
            self.log('Did not find the Batch Account Application instance. Exception as {0}'.format(e))
        if found is True:
            return self.format_item(response.as_dict())
        return False

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
    AzureRMBatchAccountApplication()


if __name__ == '__main__':
    main()
