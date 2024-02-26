#!/usr/bin/python
#
# Copyright (c) 2016 Matt Davis, <mdavis@ansible.com>
#                    Chris Houseknecht, <house@redhat.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
extends_documentation_fragment:
    - azure.azcollection.azure
    - azure.azcollection.azure_tags

author:
'''

EXAMPLES = '''
'''


RETURN = '''
state:
'''


from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase
from azure.core.exceptions import ResourceNotFoundError
import logging
logging.basicConfig(filename='tt.log', level=logging.INFO)


class AzureRMStorageAccountManagementPolicy(AzureRMModuleBase):

    def __init__(self):

        self.module_arg_spec = dict(
            resource_group=dict(required=True, type='str', aliases=['resource_group_name']),
            storage_account_name=dict(type='str', required=True),
            name=dict(type='str', required=True),
            state=dict(default='present', choices=['present', 'absent']),
            rules=dict(
                type='list',
                elements='dict',
                options=dict(
                    enabled=dict(type='bool'),
                    name=dict(type='str', required=True),
                    type=dict(type='str', required=True, choices=['Lifecycle']),
                    definition=dict(
                        type='dict',
                        options=dict(
                            actions=dict(
                                type='dict',
                                required=True,
                                options=dict(
                                    base_blob=dict(
                                        tier_to_cool=dict(
                                            type='dict',
                                            options=dict(
                                                days_after_modification_greater_than=dict(type='float'),
                                                days_after_last_access_time_greater_than=dict(type='float')
                                            )
                                        ),
                                        tier_to_archive=dict(
                                            type='dict',
                                            options=dict(
                                                days_after_modification_greater_than=dict(type='float'),
                                                days_after_last_access_time_greater_than=dict(type='float')
                                            )
                                        ),
                                        delete=dict(
                                            type='dict',
                                            options=dict(
                                                days_after_modification_greater_than=dict(type='float'),
                                                days_after_last_access_time_greater_than=dict(type='float')
                                            )
                                        ),
                                        enable_auto_tier_to_hot_from_cool=dict(type='bool')
                                    ),
                                    snapshot=dict(
                                        type='dict',
                                        options=dict(
                                            tier_to_cool=dict(
                                                type='dict',
                                                options=dict(
                                                    days_after_creation_greater_than=dict(type='float', required=True)
                                                )
                                            ),
                                            tier_to_archive=dict(
                                                type='dict',
                                                options=dict(
                                                    days_after_creation_greater_than=dict(type='float', required=True)
                                                )
                                            ),
                                            delete=dict(
                                                type='dict',
                                                options=dict(
                                                    days_after_creation_greater_than=dict(type='float', required=True)
                                                )
                                            )
                                        )
                                    ),
                                    version=dict(
                                        type='dict',
                                        options=dict(
                                            tier_to_cool=dict(
                                                type='dict',
                                                options=dict(
                                                    days_after_creation_greater_than=dict(
                                                        type='float',
                                                    )
                                                )
                                            ),
                                            tier_to_archive=dict(
                                                type='dict',
                                                options=dict(
                                                    days_after_creation_greater_than=dict(
                                                        type='float',
                                                    )
                                                )
                                            ),
                                            delete=dict(
                                                type='dict',
                                                options=dict(
                                                    days_after_creation_greater_than=dict(
                                                        type='float',
                                                        required=True
                                                    )
                                                )
                                            )
                                        )
                                    )
                                )
                            ),
                            filters=dict(
                                type='dict',
                                options=dict(
                                    prefix_match=dict(type='list', elements='str'),
                                    blob_types=dict(type='list', elements='str', required=True),
                                    blob_index_match=dict(
                                        type='list',
                                        elements='dict',
                                        options=dict(
                                            name=dict(type='str', required=True),
                                            op=dict(type='str', required=True),
                                            value=dict(type='str', required=True)
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
        )

        self.results = dict(
            changed=False,
            state=dict()
        )

        self.resource_group = None
        self.name = None
        self.storage_account_name = None
        self.state = None
        self.rules = None

        super(AzureRMStorageAccountManagementPolicy, self).__init__(self.module_arg_spec,
                                                                    supports_check_mode=True)

    def exec_module(self, **kwargs):

        for key in list(self.module_arg_spec.keys()):
            setattr(self, key, kwargs[key])

        managed_policy = self.get_management_policy()
        changed = False

        if self.state == 'present':
            if managed_policy is not None:
                pass
            else:
                changed = True
                if not self.check_mode:
                    self.create_or_update_management_policy(self.rules)
        else:
            if managed_policy is not None:
                changed = True
                if not self.check_mode:
                    self.delete_management_policy()

        self.results['state'] = self.get_management_policy()
        self.results['changed'] = changed

        return self.results

    def get_management_policy(self):
        self.log('Get info for storage account management policy {0}'.format(self.name))

        response = None
        try:
            response = self.storage_client.management_policies.get(self.resource_group, self.storage_account_name, self.name)
        except ResourceNotFoundError:
            pass

        return self.format_to_dict(response)

    def format_to_dict(self, obj):
        pass

    def create_or_update_management_policy(self, rules):
        self.log("Creating or updating storage account mangement policy {0}".format(self.name))

        try:
            logging.info('tt'*10)
            logging.info(rules)
            logging.info(self.storage_client.management_policies)
            tt = self.storage_client.management_policies.create_or_update(resource_group_name=self.resource_group,
                                                                              account_name=self.storage_account_name,
                                                                              name=self.name,
                                                                              properties=dict(policy=rules))
            logging.info(tt)
            logging.info('tt'*10)
        except Exception as e:
            logging.info(e)
            logging.info('ffff'*10)
            self.log('Error creating or updating storage account management policy.')
            self.fail("Failed to create or updating storage account management policy: {0}".format(str(e)))
        return self.get_management_polic()

    def delete_management_policy(self):
        try:
            self.storage_client.management_policies.delete(self.resource_group, self.storage_account_name, self.name)
        except Exception as e:
            self.fail("Failed to delete the storage account management policy: {0}".format(str(e)))


def main():
    AzureRMStorageAccountManagementPolicy()


if __name__ == '__main__':
    main()
