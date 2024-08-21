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
    contains:
        auto_complete_restore:
            description:
                - Whether to auto complete restore of this managed database.
            type: bool
            returned: always
            sample: null
        catalog_collation:
            description:
                - Collation of the metadata catalog.
            type: str
            returned: always
            sample: null
        create_mode:
            description:
                - Managed database create mode.
            type: str
            returned: always
            sample: null
        create_date:
            description:
                - Creation date of the database.
            type: str
            returned: always
            sample: "2024-05-06T23:59:49.770Z"
        database_name:
            description:
                - The sql mi databse name.
            type: str
            returned: always
            sample: fredtest
        default_secondary_location:
            description:
                - Geo paired region.
            type: str
            returned: always
            sample: westus
        id:
            description:
                - The resource ID.
            type: str
            returned: always
            sample: "/subscriptions/xxx-xxxx/resourceGroups/testRG/providers/Microsoft.Sql/managedInstances/fredsqlmin/databases/fredtest"
        last_backup_name:
            description:
                - Last backup file name for restore of this managed database.
            type: str
            returned: always
            sample: null
        location:
            description:
                - The resource's location.
            type: str
            returned: always
            sample: eastus
        long_term_retention_backup_resource_id:
            description:
                - The name of the Long Term Retention backup to be used for restore of this managed database.
            type: str
            returned: always
            sample: null
        managed_instance_name:
            description:
                - The name of the SQL managed instance.
            type: str
            returned: always
            sample: fredsqlmin
        recoverable_database_id:
            description:
                - The resource identifier of the recoverable database associated with the database.
            type: str
            returned: always
            sample: null
        resource_group:
            description:
                - The resource's resource group.
            type: str
            returned: always
            sample: testRG
        restorable_dropped_database_id:
            description:
                - The restorable dropped database resource id.
            type: str
            returned: always
            sample: null
        restore_point_in_time:
            description:
                - Specifies the point in time (ISO8601 format) of the source database.
            type: str
            returned: always
            sample: null
        source_database_id:
            description:
                - The resource identifier of the source database associated with create operation of this database.
            type: str
            returned: always
            sample: null
        status:
            description:
                - Status of the database.
            type: str
            returned: always
            sample: online
        storage_container_sas_token:
            description:
                - Specifies the storage container sas token.
            type: str
            returned: always
            sample: null
        storage_container_uri:
            description:
                - Specifies the uri of the storage container where backups for this restore are stopped.
            type: str
            returned: always
            sample: null
        tags:
            description:
                - The resource's tags
            type: str
            returned: always
            sample: {key1: value1}
        type:
            description:
                - The resource type.
            type: str
            returned: always
            sample: "Microsoft.Sql/managedInstances/databases"
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
