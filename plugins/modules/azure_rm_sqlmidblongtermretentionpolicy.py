#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_sqlmidblongtermretentionpolicy
version_added: "2.4.0"
short_description: Manage Azure SQL Managed Instance long-term backup retention
description:
    - Manage Azure SQL Managed Instance long-term backup retention.

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
            - The name of the SQL managed instance long term retention policy.
        type: str
        required: true
        choices:
            - default
    monthly_retention:
        description:
            - The monthly retention policy for an LTR backup in an ISO 8601 format.
        type: str
    yearly_retention:
        description:
            - The yearly retention policy for an LTR backup in an ISO 8601 format.
        type: str
    weekly_retention:
        description:
            - The weekly retention policy for an LTR backup in an ISO 8601 format.
        type: str
    week_of_year:
        description:
            - The week of year to take the yearly backup in an ISO 8601 format.
        type: int

extends_documentation_fragment:
    - azure.azcollection.azure

author:
    - xuzhang3 (@xuzhang3)
    - Fred-sun (@Fred-sun)
'''

EXAMPLES = '''
- name: Update SQL managed instance long term retention policy's retention_days
  azure_rm_sqlmidblongtermretentionpolicy:
    resource_group: testrg
    managed_instance_name: testinstancename
    database_name: newdatabase
    policy_name: default
    monthly_retention: P3M
    week_of_year: 17
    weekly_retention: P13W
    yearly_retention: P6Y
'''

RETURN = '''
long_term_retention_policy:
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
                - SQL managed instance long term retentioni policy name.
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
        week_of_year:
            description:
                - The week of year to take the yearly backup in an ISO 8601 format.
            type: int
            sample: 7
            returned: always
        weekly_retention:
            description:
                - The weekly retention policy for an LTR backup in an ISO 8601 format.
            type: str
            sample: P13W
            returned: always
        monthly_retention:
            description:
                - The monthly retention policy for an LTR backup in an ISO 8601 format.
            type: str
            sample: P3M
            returned: always
        yearly_retention:
            description:
                - The yearly retention policy for an LTR backup in an ISO 8601 format.
            type: str
            sample: P6Y
            returned: always
'''

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase

try:
    from azure.core.exceptions import HttpResponseError
except ImportError:
    # This is handled in azure_rm_common
    pass


class AzureRMSqMILongTermRetentionPolicy(AzureRMModuleBase):
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
            weekly_retention=dict(
                type='str',
            ),
            monthly_retention=dict(
                type='str'
            ),
            yearly_retention=dict(
                type='str'
            ),
            week_of_year=dict(
                type='int'
            )
        )
        # store the results of the module operation
        self.parameters = dict()
        self.results = dict(
            changed=False,
            diff=[]
        )
        self.resource_group = None
        self.managed_instance_name = None
        self.database_name = None
        self.policy_name = None

        super(AzureRMSqMILongTermRetentionPolicy, self).__init__(self.module_arg_spec, supports_check_mode=True, supports_tags=False, facts_module=True)

    def exec_module(self, **kwargs):
        for key in self.module_arg_spec:
            if hasattr(self, key):
                setattr(self, key, kwargs[key])
            else:
                self.parameters[key] = kwargs.get(key)

        old_response = self.get()

        if old_response is not None:
            for key in self.parameters.keys():
                if self.parameters[key] is not None and old_response[key] != self.parameters[key]:
                    self.results['changed'] = True
                    self.results['diff'].append(key)
            if self.results['changed'] and not self.check_mode:
                self.results['long_term_retention_policy'] = self.create_or_update_policy()
        else:
            self.results['changed'] = True
            if not self.check_mode:
                self.results['long_term_retention_policy'] = self.create_or_update_policy()
        return self.results

    def get(self):
        response = None
        try:
            response = self.sql_client.managed_instance_long_term_retention_policies.get(resource_group_name=self.resource_group,
                                                                                         managed_instance_name=self.managed_instance_name,
                                                                                         database_name=self.database_name,
                                                                                         policy_name=self.policy_name)
            self.log("Response : {0}".format(response))
        except HttpResponseError:
            self.log('Could not get facts for SQL managed instance long term retention policyes.')

        return self.format_item(response) if response is not None else None

    def create_or_update_policy(self):
        response = None
        try:
            response = self.sql_client.managed_instance_long_term_retention_policies.begin_create_or_update(resource_group_name=self.resource_group,
                                                                                                            managed_instance_name=self.managed_instance_name,
                                                                                                            database_name=self.database_name,
                                                                                                            policy_name=self.policy_name,
                                                                                                            parameters=self.parameters)
            self.log("Response : {0}".format(response))
        except HttpResponseError as ec:
            self.fail('Could not create SQL managed instance long term retention policyes. Exception info as {0}'.format(ec))

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
            "monthly_retention": d.get("monthly_retention"),
            "week_of_year": d.get("week_of_year"),
            "weekly_retention": d.get("weekly_retention"),
            "yearly_retention": d.get("yearly_retention")
        }
        return d


def main():
    AzureRMSqMILongTermRetentionPolicy()


if __name__ == '__main__':
    main()
