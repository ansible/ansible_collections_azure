#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_sqlmidatabase_info
version_added: "2.4.0"
short_description: Get Azure SQL managed instance database facts
description:
    - Get facts of Azure SQL managed instance database facts.

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
- name: Get SQL managed instance database by name
  azure_rm_sqlmidatabase_info:
    resource_group: testrg
    managed_instance_name: testinstancename
    database_name: newdatabase
'''

RETURN = '''
database:
    description:
        - A dictionary containing facts for SQL Managed Instance database info.
    returned: always
    type: complex
'''

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase

try:
    from azure.core.exceptions import HttpResponseError
except ImportError:
    # This is handled in azure_rm_common
    pass


class AzureRMSqlMIDatabaseInfo(AzureRMModuleBase):
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
            ),
            tags=dict(
                type='list',
                elements='str'
            ),
        )
        # store the results of the module operation
        self.results = dict(
            changed=False
        )
        self.resource_group = None
        self.managed_instance_name = None
        self.database_name = None
        self.tags = None

        super(AzureRMSqlMIDatabaseInfo, self).__init__(self.module_arg_spec, supports_check_mode=True, supports_tags=False, facts_module=True)

    def exec_module(self, **kwargs):
        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        if self.database_name is not None:
            self.results['database'] = self.get()
        else:
            self.results['database'] = self.list_by_instance()
        return self.results

    def list_by_instance(self):
        response = None
        results = []
        try:
            response = self.sql_client.managed_databases.list_by_instance(resource_group_name=self.resource_group,
                                                                          managed_instance_name=self.managed_instance_name)
            self.log("Response : {0}".format(response))
        except HttpResponseError:
            self.log('Could not get facts for SQL managed instance database.')

        if response is not None:
            for item in response:
                if self.has_tags(item.tags, self.tags):
                    results.append(self.format_item(item))
        return results


    def get(self):
        response = None
        try:
            response = self.sql_client.managed_databases.get(resource_group_name=self.resource_group,
                                                             managed_instance_name=self.managed_instance_name,
                                                             database_name=self.database_name)
            self.log("Response : {0}".format(response))
        except HttpResponseError as ec:
            self.log('Could not get facts for SQL managed instance database.')

        if response is not None and self.has_tags(response.tags, self.tags):
            return [self.format_item(response)]


    def format_item(self, item):
        d = item.as_dict()
        d = {
            'resource_group': self.resource_group,
            'managed_instance_name': self.managed_instance_name,
            'database_name': d.get('name'),
            'id': d.get('id', None),
            'type': d.get('type', None),
            'location': d.get('location'),
            'tags': d.get('tags'),
            'collation': d.get('collation'),
            'status': d.get('status'),
            'creation_date': d.get('creation_date'),
            'earliest_restore_point': d.get('earliest_restore_point'),
            'restore_point_in_time': d.get('restore_point_in_time'),
            'default_secondary_location': d.get('default_secondary_location'),
            'catalog_collation': d.get('catalog_collation'),
            'create_mode': d.get('create_mode'),
            'storage_container_uri': d.get('storage_container_uri'),
            'source_database_id': d.get('source_database_id'),
            'restorable_dropped_database_id': d.get('restorable_dropped_database_id'),
            'storage_container_sas_token': d.get('storage_container_sas_token'),
            'failover_group_id': d.get('failover_group_id'),
            'recoverable_database_id': d.get('recoverable_database_id'),
            'long_term_retention_backup_resource_id': d.get('long_term_retention_backup_resource_id'),
            'auto_complete_restore': d.get('auto_complete_restore'),
            'last_backup_name': d.get('last_backup_name')
        }
        return d


def main():
    AzureRMSqlMIDatabaseInfo()


if __name__ == '__main__':
    main()
