#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_sqlmidbshorttermretentionpolicy_info
version_added: "2.4.0"
short_description: Get Azure SQL managed instance short term retention policy
description:
    - Get Azure SQL managed instance short term retention policy.

options:
    resource_group:
        description:
            - The name of the resource group that contains the resource.
        type: str
        required: true
    managed_instance_name:
        description:
            - The name of the SQL managed instance.
        type: str
        required: true
    database_name:
        description:
            - The name of the SQL managed instance database.
        type: str
        required: true
    policy_name:
        description:
            - The name of the SQL managed instance short term retention policy.
        type: str
        choices:
            - default

extends_documentation_fragment:
    - azure.azcollection.azure

author:
    - xuzhang3 (@xuzhang3)
    - Fred-sun (@Fred-sun)
'''

EXAMPLES = '''
- name: Get SQL managed instance short term retention policy by name
  azure_rm_sqlmidbshorttermretentionpolicy_info:
    resource_group: testrg
    managed_instance_name: testinstancename
    database_name: newdatabase
    policy_name: default
'''

RETURN = '''
short_term_retention_policy:
    description:
        - A dictionary containing facts for SQL Managed Instance Short Term Retention Policies.
    returned: always
    type: complex
    contains:
        id:
            description:
                - Resource ID.
            returned: always
            type: str
            sample: "/subscriptions/xxx-xxx/resourceGroups/testRG/providers/Microsoft.Sql/
                     managedInstances/fredsqlmi/databases/newdatabase/backupShortTermRetentionPolicies/default"
        database_name:
            description:
                - SQL managed instance database name.
            returned: always
            type: str
            sample: newdatabase
        policy_name:
            description:
                - SQL managed instance short term retentioni policy name.
            returned: always
            type: str
            sample: default
        managed_instance_name:
            description:
                - SQL managed instance name.
            returned: always
            type: str
            sample: testmanagedinstance
        type:
            description:
                - The SQL managed instance short term retention policy type.
            type: str
            returned: always
            sample: "Microsoft.Sql/managedInstances/databases/backupShortTermRetentionPolicies"
        resource_group:
            description:
                - The resource relate resource group.
            type: str
            returned: always
            sample: testRG
        retention_days:
            description:
                - The backup retention period in days. This is how many days Point-in-Time
            type: int
            sample: 7
            returned: always
'''

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase

try:
    from azure.core.exceptions import HttpResponseError
except ImportError:
    # This is handled in azure_rm_common
    pass


class AzureRMSqMIShortTermRetentionPolicyInfo(AzureRMModuleBase):
    def __init__(self):
        # define user inputs into argument
        self.module_arg_spec = dict(
            resource_group=dict(
                type='str',
                required=True,
            ),
            managed_instance_name=dict(
                type='str',
                required=True,
            ),
            database_name=dict(
                type='str',
                required=True,
            ),
            policy_name=dict(
                type='str',
                choices=['default']
            ),
        )
        # store the results of the module operation
        self.results = dict(
            changed=False
        )
        self.resource_group = None
        self.managed_instance_name = None
        self.database_name = None
        self.policy_name = None

        super(AzureRMSqMIShortTermRetentionPolicyInfo, self).__init__(self.module_arg_spec, supports_check_mode=True, supports_tags=False, facts_module=True)

    def exec_module(self, **kwargs):
        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        if self.policy_name is not None:
            self.results['short_term_retention_policy'] = self.get()
        else:
            self.results['short_term_retention_policy'] = self.list_by_database()
        return self.results

    def list_by_database(self):
        response = None
        try:
            response = self.sql_client.managed_backup_short_term_retention_policies.list_by_database(resource_group_name=self.resource_group,
                                                                                                     managed_instance_name=self.managed_instance_name,
                                                                                                     database_name=self.database_name)
            self.log("Response : {0}".format(response))
        except HttpResponseError:
            self.log('Could not get facts for SQL managed instance short term retention policyes.')

        return [self.format_item(item) for item in response] if response is not None else []

    def get(self):
        response = None
        try:
            response = self.sql_client.managed_backup_short_term_retention_policies.get(resource_group_name=self.resource_group,
                                                                                        managed_instance_name=self.managed_instance_name,
                                                                                        database_name=self.database_name,
                                                                                        policy_name=self.policy_name)
            self.log("Response : {0}".format(response))
        except HttpResponseError as ec:
            self.log('Could not get facts for SQL managed instance short term retention policyes.')

        return [self.format_item(response)] if response is not None else None

    def format_item(self, item):
        d = item.as_dict()
        d = {
            'resource_group': self.resource_group,
            'managed_instance_name': self.managed_instance_name,
            'database_name': self.database_name,
            'id': d.get('id', None),
            'name': d.get('name', None),
            'type': d.get('type', None),
            'retention_days': d.get('retention_days', None),
        }
        return d


def main():
    AzureRMSqMIShortTermRetentionPolicyInfo()


if __name__ == '__main__':
    main()
