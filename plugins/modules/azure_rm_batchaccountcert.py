#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: azure_rm_batchaccountcertificate
version_added: "3.0.0"
short_description: Manages a Batch Account Certificate on Azure
description:
    - Create, update, delete and cancel delete instance of Azure Batch Account Certificate.

options:
    resource_group:
        description:
            - The name of the resource group in which to create the Batch Account Certificate.
        required: true
        type: str
    batch_account_name:
        description:
            - The name of the Batch Account.
        required: true
        type: str
    name:
        description:
            - The name of the Batch Account Certificate.
        required: true
        type: str
    thumbprint_algorithm:
        description:
            - This must match the first portion of the certificate name.
            - Currently required to be 'SHA1'.
        type: str
        required: true
        choices:
            - SHA1
    thumbprint:
        description:
            - This must match the thumbprint from the name.
        type: str
    format:
        description:
            - The format of the certificate - either Pfx or Cer.
            - If omitted, the default is C(Pfx).
        type: str
        choices:
            - Pfx
            - Cer
    is_cancel_delete:
        description:
            - Whether to cancel delete the certificate.
        type: bool
        default: false
    state:
        description:
            - Assert the state of the Batch Account Certificate.
            - Use C(present) to create or update a Batch Account Certificate and C(absent) to delete it.
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
- name: Create Batch Account Certificate
  azure_rm_batchaccountcertificate:
    resource_group: MyResGroup
    name: mybatchaccountcertificate
    batch_account_name: mybatchaccount

- name: Delete Batch Account Certificate
  azure_rm_batchaccountcertificate:
    resource_group: MyResGroup
    name: mybatchaccountcertificate
    batch_account_name: mybatchaccount
    state: absent
'''

RETURN = '''
certificate:
    description:
        - Contains information about an certificate in a Batch account.
    type: complex
    returned: always
    contains:
        id:
            description:
                - The ID of the batch account certificate.
            type: str
            returned: always
            sample: "/subscriptions/xxx-xxx/resourceGroups/testRG/providers/Microsoft.Batch/batchAccounts/batch01/certificates/cert01",
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
                - The name of the certificate.
            type: str
            returned: always
            sample: app01
        type:
            description:
                - The type of the resource.
            type: str
            returned: always
            sample: Microsoft.Batch/batchAccounts/certificates
'''

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common_ext import AzureRMModuleBase

try:
    from azure.core.polling import LROPoller
    from azure.core.exceptions import ResourceNotFoundError
except ImportError:
    # This is handled in azure_rm_common
    pass


class AzureRMBatchAccountCertificate(AzureRMModuleBase):
    """Configuration class for an Azure RM Batch Account Certificate resource"""

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
            thumbprint_algorithm=dict(
                type='str',
                choices=['SHA1'],
            ),
            is_cancel_delete=dict(
                type='bool'
            ),
            thumbprint=dict(
                type='str'
            ),
            format=dict(
                type='str',
                choices=['Pfx', 'Cer']
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
        self.is_cancel_delete = None
        self.results = dict(changed=False)
        self.state = None
        self.body = dict()

        super(AzureRMBatchAccountCertificate, self).__init__(derived_arg_spec=self.module_arg_spec,
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

        old_response = self.get_batchaccount_certificate()

        if not old_response:
            self.log("Batch Account Certificate instance doesn't exist")
            if self.state == 'absent':
                self.log("Old instance didn't exist")
            else:
                changed = True
                if not self.check_mode:
                    response = self.create_batchaccount_certificate()
        else:
            self.log("Batch Account Certificate instance already exists")
            if self.state == 'absent':
                if not self.check_mode:
                    changed = True
                    response = self.delete_batchaccount_certificate()
            else:
                if self.body.get('thumbprint') is not None and self.body['thumbprint'] != old_response['thumbprint']:
                    changed = True
                else:
                    self.body['thumbprint'] = old_response['thumbprint']
                if self.body.get('format') and self.body['format'] != old_response['format']:
                    changed = True
                else:
                    self.body['format'] = old_response['format']
                    self.body['allow_updates'] = old_response['allow_updates']
                if not self.check_mode and changed:
                    response = self.update_batchaccount_certificate()

        self.results = dict(
            changed=changed,
            state=response,
        )
        return self.results

    def create_batchaccount_certificate(self):
        '''
        Creates Batch Account Certificate with the specified configuration.
        '''
        self.log("Creating the Batch Account Certificate instance {0}".format(self.name))

        try:
            response = self.batch_account_client.certificate.create(resource_group_name=self.resource_group,
                                                                    account_name=self.batch_account_name,
                                                                    certificate_name=self.name,
                                                                    parameters=self.body)
            if isinstance(response, LROPoller):
                response = self.get_poller_result(response)
        except Exception as exc:
            self.log('Error attempting to create the Batch Account Certificate instance.')
            self.fail("Error creating the Batch Account Certificate instance: {0}".format(str(exc)))
        return response.as_dict()

    def update_batchaccount_certificate(self):
        '''
        Update Batch Account Certificate with the specified configuration.
        '''
        self.log("Updating the Batch Account Certificate instance {0}".format(self.name))

        try:
            response = self.batch_account_client.certificate.update(resource_group_name=self.resource_group,
                                                                    account_name=self.batch_account_name,
                                                                    certificate_name=self.name,
                                                                    parameters=self.body)
            if isinstance(response, LROPoller):
                response = self.get_poller_result(response)
        except Exception as exc:
            self.log('Error attempting to update the Batch Account Certificate instance.')
            self.fail("Error updating the Batch Account Certificate instance: {0}".format(str(exc)))
        return response.as_dict()

    def delete_batchaccount_certificate(self):
        '''
        Deletes specified Batch Account Certificate instance in the specified subscription and resource group.
        :return: True
        '''
        self.log("Deleting the Batch Account Certificate instance {0}".format(self.name))
        try:
            self.batch_account_client.certificate.delete(resource_group_name=self.resource_group,
                                                         account_name=self.batch_account_name,
                                                         certificate_name=self.name)
        except Exception as e:
            self.log('Error attempting to delete the Batch Account Certificate instance.')
            self.fail("Error deleting the Batch Account Certificate instance: {0}".format(str(e)))

        return True

    def get_batchaccount_certificate(self):
        '''
        Gets the properties of the specified Batch Account Certificate
        :return: deserialized Batch Account Certificate instance state dictionary
        '''
        self.log("Checking if the Batch Account Certificate instance {0} is present".format(self.name))
        found = False
        try:
            response = self.batch_account_client.certificate.get(resource_group_name=self.resource_group,
                                                                 account_name=self.batch_account_name,
                                                                 certificate_name=self.name)
            found = True
            self.log("Response : {0}".format(response))
            self.log("Batch Account Certificate instance : {0} found".format(response.name))
        except ResourceNotFoundError as e:
            self.log('Did not find the Batch Account Certificate instance. Exception as {0}'.format(e))
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
            'thumbprint_algorithm': item['thumbprint_algorithm'],
            'thumbprint': item['thumbprint'],
            'format': item['format'],
            'provisioning_state': item['provisioning_state'],
            'provisioning_state_transition_time': item['provisioning_state_transition_time'],
            'previous_provisioning_state': item['previous_provisioning_state'],
            'previous_provisioning_state_transition_time': item['previous_provisioning_state_transition_time'],
            'publish_data': item['publish_data'],
        } if item is not None else None
        return result


def main():
    """Main execution"""
    AzureRMBatchAccountCertificate()


if __name__ == '__main__':
    main()
