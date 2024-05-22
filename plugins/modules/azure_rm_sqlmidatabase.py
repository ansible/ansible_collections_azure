#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_sqlmidatabase
version_added: "2.4.0"
short_description: Manage SQL Managed Instance databases
description:
    - Manage SQL Managed Instance databases.

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
    collation:
        description:
            - The collation of the Azure SQL Managed Database collation to use.
            - For example C(SQL_Latin1_General_CP1_CI_AS) or C(Latin1_General_100_CS_AS_SC).
        type: str
    location:
        description:
            - The resource location.
        type: str
    state:
        description:
            - State of the SQL Managed Database.
            - Use C(present) to create or update a automation runbook and use C(absent) to delete.
        type: str
        default: present
        choices:
            - present
            - absent
extends_documentation_fragment:
    - azure.azcollection.azure
    - azure.azcollection.azure_tags

author:
    - xuzhang3 (@xuzhang3)
    - Fred-sun (@Fred-sun)
'''

EXAMPLES = '''
- name: Create a SQL managed instance database
  azure_rm_sqlmidatabase:
    resource_group: testrg
    managed_instance_name: testinstancename
    database_name: newdatabase
    collation: SQL_Latin1_General_CP1_CI_AS
    location: eastus
    tags:
      key2: value2

- name: Delete the SQL managed instance database
  azure_rm_sqlmidatabase:
    resource_group: testrg
    managed_instance_name: testinstancename
    database_name: newdatabase
    state: absent
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


class AzureRMSqlMIDatabase(AzureRMModuleBase):
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
            collation=dict(
                type='str'
            ),
            location=dict(
                type='str'
            ),
            state=dict(
                type='str',
                choices=['present', 'absent'],
                default='present'
            ),
        )
        # store the results of the module operation
        self.results = dict(
            changed=False
        )
        self.resource_group = None
        self.managed_instance_name = None
        self.database_name = None
        self.state = None
        self.parameters = dict()

        super(AzureRMSqlMIDatabase, self).__init__(self.module_arg_spec, supports_check_mode=True, supports_tags=True, facts_module=False)

    def exec_module(self, **kwargs):
        for key in list(self.module_arg_spec.keys()) + ['tags']:
            if hasattr(self, key):
                setattr(self, key, kwargs[key])
            elif kwargs.get(key) is not None:
                self.parameters[key] = kwargs.get(key)

        changed = False
        resource_group = self.get_resource_group(self.resource_group)
        if self.parameters.get('location') is None:
            # Set default location
            self.parameters['location'] = resource_group.location

        old_response = self.get()
        if old_response is None:
            if self.state == 'present':
                changed = True
                if not self.check_mode:
                    self.results['database'] = self.create_database()
        else:
            update_tags, tags = self.update_tags(old_response.get('tags'))
            if update_tags:
                changed = True
                self.parameters['tags'] = tags
            for key in self.parameters.keys():
                if key != 'tags' and self.parameters[key] != old_response.get(key):
                    self.fail("The collection and location not support to update")
            if self.state == 'present':
                if changed and not self.check_mode:
                    self.results['database'] = self.update_database()
                else:
                    self.results['database'] = old_response
            else:
                changed = True
                if not self.check_mode:
                    self.results['database'] = self.delete_database()

        self.results['changed'] = changed
        return self.results

    def create_database(self):
        response = None
        try:
            response = self.sql_client.managed_databases.begin_create_or_update(resource_group_name=self.resource_group,
                                                                                managed_instance_name=self.managed_instance_name,
                                                                                database_name=self.database_name,
                                                                                parameters=self.parameters)
            self.log("Response : {0}".format(response))
        except HttpResponseError as ec:
            self.fail('Create the SQL managed instance database failed, exception as {0}'.format(ec))

        return self.format_item(self.get_poller_result(response))

    def update_database(self):
        response = None
        try:
            response = self.sql_client.managed_databases.begin_update(resource_group_name=self.resource_group,
                                                                      managed_instance_name=self.managed_instance_name,
                                                                      database_name=self.database_name,
                                                                      parameters=self.parameters)
            self.log("Response : {0}".format(response))
        except HttpResponseError as ec:
            self.fail('Update the SQL managed instance database failed, exception as {0}'.format(ec))

        return self.format_item(self.get_poller_result(response))

    def get(self):
        response = None
        try:
            response = self.sql_client.managed_databases.get(resource_group_name=self.resource_group,
                                                             managed_instance_name=self.managed_instance_name,
                                                             database_name=self.database_name)
            self.log("Response : {0}".format(response))
        except HttpResponseError as ec:
            self.log('Could not get facts for SQL managed instance database. Exception as {0}'.format(ec))

        return self.format_item(response)

    def delete_database(self):
        response = None
        try:
            response = self.sql_client.managed_databases.begin_delete(resource_group_name=self.resource_group,
                                                                      managed_instance_name=self.managed_instance_name,
                                                                      database_name=self.database_name)
            self.log("Response : {0}".format(response))
        except HttpResponseError as ec:
            self.fail('Could not get facts for SQL managed instance database. Exception as {0}'.format(ec))

        return self.format_item(self.get_poller_result(response))

    def format_item(self, item):
        if item is None:
            return
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
            'restore_point_in_time': d.get('restore_point_in_time'),
            'default_secondary_location': d.get('default_secondary_location'),
            'catalog_collation': d.get('catalog_collation'),
            'create_mode': d.get('create_mode'),
            'storage_container_uri': d.get('storage_container_uri'),
            'source_database_id': d.get('source_database_id'),
            'restorable_dropped_database_id': d.get('restorable_dropped_database_id'),
            'storage_container_sas_token': d.get('storage_container_sas_token'),
            'recoverable_database_id': d.get('recoverable_database_id'),
            'long_term_retention_backup_resource_id': d.get('long_term_retention_backup_resource_id'),
            'auto_complete_restore': d.get('auto_complete_restore'),
            'last_backup_name': d.get('last_backup_name')
        }
        return d


def main():
    AzureRMSqlMIDatabase()


if __name__ == '__main__':
    main()
