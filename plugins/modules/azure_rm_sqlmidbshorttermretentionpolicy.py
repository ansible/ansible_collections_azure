#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_sqlmidbshorttermretentionpolicy
version_added: "2.4.0"
short_description: Manage SQL Managed Instance database backup short term retention policy
description:
    - Manage SQL Managed Instance database backup short term retention policy.

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
        required: true
        choices:
            - default
    retention_days:
        description:
            - The backup retention period in days. This is how many days Point-in-Time.
        type: int
        default: 7

extends_documentation_fragment:
    - azure.azcollection.azure

author:
    - xuzhang3 (@xuzhang3)
    - Fred-sun (@Fred-sun)
'''

EXAMPLES = '''
- name: Update SQL managed instance short term retention policy's retention_days
  azure_rm_sqlmidbshorttermretentionpolicy:
    resource_group: testrg
    managed_instance_name: testinstancename
    database_name: newdatabase
    policy_name: default
    retention_days: 3
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
                - The SQL managed instance type.
            type: str
            returned: always
            sample: "Microsoft.Sql/managedInstances"
        resource_group:
            description:
                - The resource relate resource group.
            type: str
            returned: always
            sample: testRG
        retention_days:
            description:
                - The backup retention period in days. This is how many days Point-in-Time.
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


class AzureRMSqMIShortTermRetentionPolicy(AzureRMModuleBase):
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
                required=True,
                choices=['default']
            ),
            retention_days=dict(
                type='int',
                default=7
            ),
        )
        # store the results of the module operation
        self.results = dict(
            changed=False,
            diff=[]
        )
        self.resource_group = None
        self.managed_instance_name = None
        self.database_name = None
        self.policy_name = None
        self.retention_days = None

        super(AzureRMSqMIShortTermRetentionPolicy, self).__init__(self.module_arg_spec, supports_check_mode=True, supports_tags=False, facts_module=True)

    def exec_module(self, **kwargs):
        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        old_response = self.get()

        if old_response is not None:
            if self.retention_days is not None and old_response['retention_days'] != self.retention_days:
                self.results['changed'] = True
                self.results['diff'].append('retention_days')
                if not self.check_mode:
                    self.results['short_term_retention_policy'] = self.update_policy()
        else:
            self.results['changed'] = True
            if not self.check_mode:
                self.results['short_term_retention_policy'] = self.create_policy()
        return self.results

    def get(self):
        response = None
        try:
            response = self.sql_client.managed_backup_short_term_retention_policies.get(resource_group_name=self.resource_group,
                                                                                        managed_instance_name=self.managed_instance_name,
                                                                                        database_name=self.database_name,
                                                                                        policy_name=self.policy_name)
            self.log("Response : {0}".format(response))
        except HttpResponseError:
            self.log('Could not get facts for SQL managed instance short term retention policyes.')

        return self.format_item(response) if response is not None else None

    def update_policy(self):
        response = None
        try:
            response = self.sql_client.managed_backup_short_term_retention_policies.begin_update(resource_group_name=self.resource_group,
                                                                                                 managed_instance_name=self.managed_instance_name,
                                                                                                 database_name=self.database_name,
                                                                                                 policy_name=self.policy_name,
                                                                                                 parameters=dict(retention_days=self.retention_days))
            self.log("Response : {0}".format(response))
        except HttpResponseError as ec:
            self.fail('Could not update the SQL managed instance short term retention policyes. Exception as {0}'.format(ec))

        return self.format_item(self.get_poller_result(response))

    def create_policy(self):
        response = None
        try:
            response = self.sql_client.managed_backup_short_term_retention_policies.begin_create_or_update(resource_group_name=self.resource_group,
                                                                                                           managed_instance_name=self.managed_instance_name,
                                                                                                           database_name=self.database_name,
                                                                                                           policy_name=self.policy_name,
                                                                                                           parameters=dict(retention_days=self.retention_days))
            self.log("Response : {0}".format(response))
        except HttpResponseError as ec:
            self.fail('Could not Create the SQL managed instance short term retention policyes. Exception as {0}'.format(ec))

        return self.format_item(self.get_poller_result(response))

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
    AzureRMSqMIShortTermRetentionPolicy()


if __name__ == '__main__':
    main()
