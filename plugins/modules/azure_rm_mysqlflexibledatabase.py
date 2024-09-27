#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_mysqlflexibledatabase
version_added: "2.7.0"
short_description: Manage MySQL Flexible Database instance
description:
    - Create or delete instance of MySQL Flexible Database, not support update.

options:
    resource_group:
        description:
            - The name of the resource group that contains the resource. You can obtain this value from the Azure Resource Manager API or the portal.
        required: True
        type: str
    server_name:
        description:
            - The name of the flexible server.
        required: True
        type: str
    name:
        description:
            - The name of the database.
        required: True
        type: str
    charset:
        description:
            - The charset of the database.
        type: str
    collation:
        description:
            - The collation of the database.
        type: str
    state:
        description:
            - Assert the state of the MySQL Flexible Database.
            - Use C(present) to createe a database and C(absent) to delete it.
        default: present
        type: str
        choices:
            - absent
            - present

extends_documentation_fragment:
    - azure.azcollection.azure

author:
    - xuzhang3 (@xuzhang3)
    - Fred-sun (@Fred-sun)

'''

EXAMPLES = '''
- name: Create (or update) MySQL Flexible Database
  azure_rm_mysqlflexibledatabase:
    resource_group: myResourceGroup
    server_name: testserver
    name: db1
'''

RETURN = '''
id:
    description:
        - Resource ID.
    returned: always
    type: str
    sample: /subscriptions/xxx----xxxx/resourceGroups/myResourceGroup/providers/Microsoft.DBforMySQL/flexibleServer/testserver/databases/db1
resource_group:
    description:
        - Resource group name.
    returned: always
    type: str
    sample: testrg
server_name:
    description:
        - Server name.
    returned: always
    type: str
    sample: testserver
name:
    description:
        - Resource name.
    returned: always
    type: str
    sample: db1
charset:
    description:
        - The charset of the database.
    returned: always
    type: str
    sample: utf8
collation:
    description:
        - The collation of the database.
    returned: always
    type: str
    sample: English_United States.1252
'''

import time

try:
    from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase
    from azure.core.exceptions import ResourceNotFoundError, HttpResponseError
    from azure.core.polling import LROPoller
except ImportError:
    # This is handled in azure_rm_common
    pass


class Actions:
    NoAction, Create, Delete = range(3)


class AzureRMMySqlFlexibleDatabase(AzureRMModuleBase):
    """Configuration class for an Azure RM MySQL Flexible Database resource"""

    def __init__(self):
        self.module_arg_spec = dict(
            resource_group=dict(
                type='str',
                required=True
            ),
            server_name=dict(
                type='str',
                required=True
            ),
            name=dict(
                type='str',
                required=True
            ),
            charset=dict(
                type='str'
            ),
            collation=dict(
                type='str'
            ),
            state=dict(
                type='str',
                default='present',
                choices=['present', 'absent']
            )
        )

        self.resource_group = None
        self.server_name = None
        self.name = None
        self.parameters = dict()

        self.results = dict(changed=False)
        self.state = None
        self.to_do = Actions.NoAction

        super(AzureRMMySqlFlexibleDatabase, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                           supports_check_mode=True,
                                                           supports_tags=False)

    def exec_module(self, **kwargs):
        """Main module execution method"""

        for key in list(self.module_arg_spec.keys()):
            if hasattr(self, key):
                setattr(self, key, kwargs[key])
            elif kwargs[key] is not None:
                if key == "charset":
                    self.parameters["charset"] = kwargs[key]
                elif key == "collation":
                    self.parameters["collation"] = kwargs[key]

        old_response = None
        response = None

        old_response = self.get_mysqldatabase()

        if not old_response:
            self.log("MySQL Flexible Database instance doesn't exist")
            if self.state == 'absent':
                self.log("Old instance didn't exist")
            else:
                self.to_do = Actions.Create
        else:
            self.log("MySQL Flexible Database instance already exists")
            if self.state == 'absent':
                self.to_do = Actions.Delete
            elif self.state == 'present':
                self.log("Need to check if MySQL Flexible Database instance has to be deleted or may be updated")
                if ('collation' in self.parameters) and (self.parameters['collation'].lower() != old_response['collation'].lower()):
                    self.fail("The MySQL Flexible Database not support update")
                if ('charset' in self.parameters) and (self.parameters['charset'].lower() != old_response['charset'].lower()):
                    self.fail("The MySQL Flexible Database not support update")

        if self.to_do == Actions.Create:
            self.log("Need to Create / Update the MySQL Flexible Database instance")

            if self.check_mode:
                self.results['changed'] = True
                return self.results

            response = self.create_mysqldatabase()
            self.results['changed'] = True
            self.log("Creation done")
        elif self.to_do == Actions.Delete:
            self.log("MySQL Flexible Database instance deleted")
            self.results['changed'] = True

            if self.check_mode:
                return self.results

            self.delete_mysqldatabase()
            # make sure instance is actually deleted, for some Azure resources, instance is hanging around
            # for some time after deletion -- this should be really fixed in Azure
            while self.get_mysqldatabase():
                time.sleep(20)
        else:
            self.log("MySQL Flexible Database instance unchanged")
            self.results['changed'] = False
            response = old_response

        if response:
            self.results["id"] = response["id"]
            self.results["name"] = response["name"]
            self.results['resource_group'] = self.resource_group
            self.results['server_name'] = self.server_name
            self.results['collation'] = response['collation']
            self.results['charset'] = response['charset']

        return self.results

    def create_mysqldatabase(self):
        '''
        Creates or updates MySQL Flexible Database with the specified configuration.

        :return: deserialized MySQL Flexible Database instance state dictionary
        '''
        self.log("Creating / Updating the MySQL Flexible Database instance {0}".format(self.name))

        try:
            response = self.mysql_flexible_client.databases.begin_create_or_update(resource_group_name=self.resource_group,
                                                                                   server_name=self.server_name,
                                                                                   database_name=self.name,
                                                                                   parameters=self.parameters)
            if isinstance(response, LROPoller):
                response = self.get_poller_result(response)

        except Exception as exc:
            self.log('Error attempting to create the MySQL Flexible Database instance.')
            self.fail("Error creating the MySQL Flexible Database instance: {0}".format(str(exc)))
        return response.as_dict()

    def delete_mysqldatabase(self):
        '''
        Deletes specified MySQL Flexible Database instance in the specified subscription and resource group.

        :return: True
        '''
        self.log("Deleting the MySQL Flexible Database instance {0}".format(self.name))
        try:
            response = self.mysql_flexible_client.databases.begin_delete(resource_group_name=self.resource_group,
                                                                         server_name=self.server_name,
                                                                         database_name=self.name)
        except Exception as e:
            self.log('Error attempting to delete the MySQL Flexible Database instance.')
            self.fail("Error deleting the MySQL Flexible Database instance: {0}".format(str(e)))

        return True

    def get_mysqldatabase(self):
        '''
        Gets the properties of the specified MySQL Flexible Database.

        :return: deserialized MySQL Flexible Database instance state dictionary
        '''
        self.log("Checking if the MySQL Flexible Database instance {0} is present".format(self.name))
        found = False
        try:
            response = self.mysql_flexible_client.databases.get(resource_group_name=self.resource_group,
                                                                server_name=self.server_name,
                                                                database_name=self.name)
            found = True
            self.log("Response : {0}".format(response))
            self.log("MySQL Flexible Database instance : {0} found".format(response.name))
        except ResourceNotFoundError as e:
            self.log('Did not find the MySQL Flexible Database instance.')
        except HttpResponseError as e:
            self.log("Get MySQL Flexible Database instance error. code: {0}, message: {1}".format(e.status_code, str(e.error)))
        if found is True:
            return response.as_dict()

        return False


def main():
    """Main execution"""
    AzureRMMySqlFlexibleDatabase()


if __name__ == '__main__':
    main()
