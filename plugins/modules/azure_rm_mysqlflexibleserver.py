#!/usr/bin/python
#
# Copyright (c) 2017 Zim Kalinowski, <zikalino@microsoft.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_mysqlflexibleserver
version_added: "0.1.2"
short_description: Manage MySQL Flexible Server instance
description:
    - Create, update and delete instance of MySQL Flexible Server.

options:
    resource_group:
        description:
            - The name of the resource group that contains the resource. You can obtain this value from the Azure Resource Manager API or the portal.
        required: True
        type: str
    name:
        description:
            - The name of the server.
        required: True
        type: str
    sku:
        description:
            - The SKU (pricing tier) of the server.
        type: dict
        suboptions:
            name:
                description:
                    - The name of the sku, typically, tier + family + cores, for example C(B_Gen4_1), C(GP_Gen5_8).
                type: str
            tier:
                description:
                    - The tier of the particular SKU, for example C(Basic).
                type: str
                choices:
                    - basic
                    - standard
            capacity:
                description:
                    - The scale up/out capacity, representing server's compute units.
                type: str
            size:
                description:
                    - The size code, to be interpreted by resource as appropriate.
                type: int
    location:
        description:
            - Resource location. If not set, location from the resource group will be used as default.
        type: str
    storage_profile:
        description:
            - Storage Profile properties of a server.
        type: dict
        suboptions:
            storage_mb:
                description:
                    - The maximum storage allowed for a server.
                type: int
            backup_retention_days:
                description:
                    - Backup retention days for the server
                type: int
            geo_redundant_backup:
                description:
                    - Enable Geo-redundant or not for server backup.
                type: str
                choices:
                    - Disabled
                    - Enabled
            storage_autogrow:
                description:
                    - Enable Storage Auto Grow.
                type: str
                choices:
                    - Disabled
                    - Enabled
    version:
        description:
            - Server version.
        type: str
        choices:
            - '5.7'
            - '8.0'
    enforce_ssl:
        description:
            - Enable SSL enforcement.
        type: bool
        default: False
    admin_username:
        description:
            - The administrator's login name of a server.
            - Can only be specified when the server is being created (and is required for creation).
        type: str
    admin_password:
        description:
            - The password of the administrator login.
        type: str
    create_mode:
        description:
            - Create mode of SQL Server.
        default: Default
        type: str
    restarted:
        description:
            - Set to C(true) with I(state=present) to restart a running mysql server.
        default: False
        type: bool
    state:
        description:
            - Assert the state of the MySQL Flexible Server. Use C(present) to create or update a server and C(absent) to delete it.
        default: present
        type: str
        choices:
            - absent
            - present

extends_documentation_fragment:
    - azure.azcollection.azure
    - azure.azcollection.azure_tags

author:
    - Zim Kalinowski (@zikalino)

'''

EXAMPLES = '''
- name: Create (or update) MySQL Flexible Server
  azure_rm_mysqlflexibleserver:
    resource_group: myResourceGroup
    name: testserver
    sku:
      name: B_Gen5_1
      tier: Basic
    location: eastus
    storage_profile:
      storage_mb: 51200
      backup_retention_days: 7
      geo_redundant_backup: Disabled
      storage_autogrow: Disabled
    enforce_ssl: true
    version: 5.7
    admin_username: cloudsa
    admin_password: password
'''

RETURN = '''
id:
    description:
        - Resource ID.
    returned: always
    type: str
    sample: /subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/myResourceGroup/providers/Microsoft.DBforMySQL/servers/mysqlsrv1b6dd89593
version:
    description:
        - Server version. Possible values include C(5.6), C(5.7), C(8.0).
    returned: always
    type: str
    sample: 5.7
state:
    description:
        - A state of a server that is visible to user. Possible values include C(Ready), C(Dropping), C(Disabled).
    returned: always
    type: str
    sample: Ready
fully_qualified_domain_name:
    description:
        - The fully qualified domain name of a server.
    returned: always
    type: str
    sample: mysqlsrv1b6dd89593.mysql.database.azure.com
'''

import time

try:
    from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase
    from azure.core.exceptions import ResourceNotFoundError
    from azure.core.polling import LROPoller
except ImportError:
    # This is handled in azure_rm_common
    pass

storage_spec = dict(
    storage_size_gb=dict(
        type='int'
    ),
    iops=dict(
        type='int'
    ),
    auto_grow=dict(
        type='str',
        choices=['Disabled', 'Enabled']
    )
)


high_availability_spec = dict(
    mode=dict(type='str', choices=["Disabled", "ZoneRedundant", "SameZone"]),
    standby_availability_zone=dict(type='str')
)


sku_spec = dict(
    name=dict(type='str', required=True),
    tier=dict(type='str', required=True, choices=["Burstable", "GeneralPurpose", "MemoryOptimized"])
)


backup_spec = dict(
    backup_retention_days=dict(type='int'),
    geo_redundant_backup=dict(type='str', choices=["Enabled", "Disabled"])
)


network_spec = dict(
    delegated_subnet_resource_id=dict(type='str'),
    private_dns_zone_resource_id=dict(type='str'),
)


maintenance_window_spec = dict(
    custom_window=dict(type='int'),
    start_hour=dict(type='int'),
    start_minute=dict(type='int'),
    day_of_week=dict(type='int')
)


class Actions:
    NoAction, Create, Update, Delete = range(4)


class AzureRMMySqlFlexibleServers(AzureRMModuleBase):
    """Configuration class for an Azure RM MySQL Flexible Server resource"""

    def __init__(self):
        self.module_arg_spec = dict(
            resource_group=dict(
                type='str',
                required=True
            ),
            name=dict(
                type='str',
                required=True
            ),
            sku=dict(
                type='dict',
                options=sku_spec
            ),
            location=dict(
                type='str'
            ),
            version=dict(
                type='str',
                choices=['5.7', '8.0.21']
            ),
            create_mode=dict(
                type='str',
                default='Default'
            ),
            admin_username=dict(
                type='str'
            ),
            admin_password=dict(
                type='str',
                no_log=True
            ),
            availability_zone=dict(
                type='str'
            ),
            restore_point_in_time=dict(
                type='str'
            ),
            source_server_resource_id=dict(
                type='str'
            ),
            replication_role=dict(
                type='str',
                choices=["None", "Source", "Replica"]
            ),
            backup=dict(
                type='dict',
                options=backup_spec
            ),
            network=dict(
                type='dict',
                options=network_spec
            ),
            maintenance_window=dict(
                type='dict',
                options=maintenance_window_spec
            ),
            storage=dict(
                type='dict',
                options=storage_spec
            ),
            high_availability=dict(
                type='dict',
                options=high_availability_spec
            ),
            status=dict(
                type='str',
                choices=['started', 'restarted', 'stop', 'failover']
            ),
            state=dict(
                type='str',
                default='present',
                choices=['present', 'absent']
            )
        )

        self.resource_group = None
        self.name = None
        self.parameters = dict()
        self.update_parameters = dict()
        self.status = None
        self.tags = None

        self.results = dict(changed=False)
        self.state = None
        self.to_do = Actions.NoAction

        super(AzureRMMySqlFlexibleServers, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                  supports_check_mode=True,
                                                  supports_tags=True)

    def exec_module(self, **kwargs):
        """Main module execution method"""

        for key in list(self.module_arg_spec.keys()) + ['tags']:
            if hasattr(self, key):
                setattr(self, key, kwargs[key])
            elif kwargs[key] is not None:
                if key == "sku":
                    self.parameters["sku"] = kwargs[key]
                    self.update_parameters["sku"] = kwargs[key]
                elif key == "location":
                    self.parameters["location"] = kwargs[key]
                elif key == "storage":
                    self.parameters["storage"] = kwargs[key]
                    self.update_parameters["sku"] = kwargs[key]
                elif key == "version":
                    self.parameters["version"] = kwargs[key]
                elif key == "create_mode":
                    self.parameters["create_mode"] = kwargs[key]
                elif key == "admin_username":
                    self.parameters["administrator_login"] = kwargs[key]
                elif key == "admin_password":
                    self.parameters["administrator_login_password"] = kwargs[key]
                    self.update_parameters["administrator_login_password"] = kwargs[key]
                elif key == 'availability_zone':
                    self.parameters['availability_zone'] = kwargs[key]
                elif key == 'source_server_resource_id':
                    self.parameters['source_server_resource_id'] = kwargs[key]
                elif key == 'restore_point_in_time':
                    self.parameters['restore_point_in_time'] = kwargs[key]
                elif key == 'replication_role':
                    self.parameters['replication_role'] = kwargs[key]
                    self.update_parameters['replication_role'] = kwargs[key]
                elif key == 'backup':
                    self.parameters['backup'] = kwargs[key]
                    self.update_parameters['backup'] = kwargs[key]
                elif key == 'high_availability':
                    self.parameters['high_availability'] = kwargs[key]
                    self.update_parameters['high_availability'] = kwargs[key]
                elif key == 'network':
                    self.parameters['network'] = kwargs[key]
                elif key == 'maintenance_window':
                    self.parameters['maintenance_window'] = kwargs[key]
                    self.update_parameters['maintenance_window'] = kwargs[key]

        self.parameters['tags'] = self.tags

        old_response = None
        response = None
        changed = False

        resource_group = self.get_resource_group(self.resource_group)
        if "location" not in self.parameters:
            self.parameters["location"] = resource_group.location

        old_response = self.get_mysqlserver()

        if not old_response:
            self.log("MySQL Flexible Server instance doesn't exist")
            if self.status is not None:
                self.fail("Mysql server instance doesn't exist, can't be restart/stop/restart/failover")

            if self.state == 'absent':
                self.log("The mysql flexible server didn't exist")
            else:
                changed = True
                self.to_do = Actions.Create
        else:
            self.log("MySQL Flexible Server instance already exists")
            if self.state == 'absent':
                changed = True
                self.to_do = Actions.Delete
            else:
                self.log("Whether the MySQL Flexible Server instance need update")
                update_tags, update_parameters['tags'] = self.update_tags(old_response.get('tags'))
                if update_tags:
                    changed = True
                    self.to_do = Actions.Update

                if not self.default_compare({}, self.update_parameters, old_response, '', dict(compare=[])):
                    changed = True
                    self.to_do = Actions.Update

        if (self.to_do == Actions.Create) or (self.to_do == Actions.Update):
            self.log("Need to Create / Update the MySQL Flexible Server instance")

            if not self.check_mode:
                response = self.create_update_mysqlserver()
                self.log("Creation / Update done")
        elif self.to_do == Actions.Delete:
            self.log("MySQL Flexible Server instance deleted")
            if not self.check_mode:
                self.delete_mysqlserver()
        else:
            self.log("MySQL Flexible Server instance unchanged")
            response = old_response
        
        if self.to_do == Actions.Update and self.status is not None:
            if self.status == 'start':
                self.start_mysqlserver()
                changed = True
            elif self.status == 'restart':
                self.restart_mysqlserver()
                changed = True
            elif self.status == 'stop':
                self.stop_mysqlserver()
                changed = True
            elif self.status == 'failover':
                self.failover_mysqlserver()
                changed = True
            else:
                pass
        self.results['changed'] = False
        self.results['state'] = response
        return self.results

    def failover_mysqlserver(self):
        '''
        Manual failover MySQL Flexible Server.
        '''
        self.log("Failover MySQL Flexible Server instance {0}".format(self.name))

        try:
            response = self.mysql_flexible_client.servers.begin_failover(resource_group_name=self.resource_group,
                                                                         server_name=self.name)
        except Exception as exc:
            self.fail("Error failover mysql flexible server {0} - {1}".format(self.name, str(exc)))
        return True

    def stop_mysqlserver(self):
        '''
        Stop MySQL Flexible Server.
        '''
        self.log("Stop MySQL Flexible Server instance {0}".format(self.name))

        try:
            response = self.mysql_flexible_client.servers.begin_stop(resource_group_name=self.resource_group,
                                                                     server_name=self.name,
                                                                    )
        except Exception as exc:
            self.fail("Error stop mysql flexible server {0} - {1}".format(self.name, str(exc)))
        return True

    def start_mysqlserver(self):
        '''
        Start MySQL Flexible Server.
        '''
        self.log("Start MySQL Flexible Server instance {0}".format(self.name))

        try:
            response = self.mysql_flexible_client.servers.begin_start(resource_group_name=self.resource_group,
                                                                      server_name=self.name,
                                                                     )
        except Exception as exc:
            self.fail("Error starting mysql flexible server {0} - {1}".format(self.name, str(exc)))
        return True

    def restart_mysqlserver(self):
        '''
        Restart MySQL Flexible Server.
        '''
        self.log("Restart MySQL Flexible Server instance {0}".format(self.name))

        try:
            response = self.mysql_flexible_client.servers.begin_restart(resource_group_name=self.resource_group,
                                                                        server_name=self.name,
                                                                        parameters=dict(restart_with_failover='Enabled',
                                                                                        max_failover_seconds=20)
                                                                       )
        except Exception as exc:
            self.fail("Error restarting mysql flexible server {0} - {1}".format(self.name, str(exc)))
        return True

    def create_update_mysqlserver(self):
        '''
        Creates or updates MySQL Flexible Server with the specified configuration.

        :return: deserialized MySQL Flexible Server instance state dictionary
        '''
        self.log("Creating / Updating the MySQL Flexible Server instance {0}".format(self.name))

        try:
            self.parameters['tags'] = self.tags
            if self.to_do == Actions.Create:
                response = self.mysql_flexible_client.servers.begin_create(resource_group_name=self.resource_group,
                                                                           server_name=self.name,
                                                                           parameters=self.parameters)
            else:
                # structure of parameters for update must be changed
                response = self.mysql_flexible_client.servers.begin_update(resource_group_name=self.resource_group,
                                                                           server_name=self.name,
                                                                           parameters=self.udpate_parameters)
            if isinstance(response, LROPoller):
                response = self.get_poller_result(response)

        except Exception as exc:
            self.log('Error attempting to create the MySQL Flexible Server instance.')
            self.fail("Error creating the MySQL Flexible Server instance: {0}".format(str(exc)))
        return response.as_dict()

    def delete_mysqlserver(self):
        '''
        Deletes specified MySQL Flexible Server instance in the specified subscription and resource group.

        :return: True
        '''
        self.log("Deleting the MySQL Flexible Server instance {0}".format(self.name))
        try:
            response = self.mysql_flexible_client.servers.begin_delete(resource_group_name=self.resource_group,
                                                                       server_name=self.name)
        except Exception as e:
            self.log('Error attempting to delete the MySQL Flexible Server instance.')
            self.fail("Error deleting the MySQL Flexible Server instance: {0}".format(str(e)))

        return True

    def get_mysqlserver(self):
        '''
        Gets the properties of the specified MySQL Flexible Server.

        :return: deserialized MySQL Flexible Server instance state dictionary
        '''
        self.log("Checking if the MySQL Flexible Server instance {0} is present".format(self.name))
        found = False
        try:
            response = self.mysql_flexible_client.servers.get(resource_group_name=self.resource_group,
                                                              server_name=self.name)
            found = True
            self.log("Response : {0}".format(response))
            self.log("MySQL Flexible Server instance : {0} found".format(response.name))
        except ResourceNotFoundError as e:
            self.log('Did not find the MySQL Flexible Server instance.')
        if found is True:
            return response.as_dict()

        return False


def main():
    """Main execution"""
    AzureRMMySqlFlexibleServers()


if __name__ == '__main__':
    main()
