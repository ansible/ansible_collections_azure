#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_mysqlflexibleserver_info
version_added: "2.6.0"
short_description: Get Azure MySQL Flexible Server facts
description:
    - Get facts of MySQL Flexible Server.

options:
    resource_group:
        description:
            - The name of the resource group that contains the resource. You can obtain this value from the Azure Resource Manager API or the portal.
        type: str
    name:
        description:
            - The name of the server.
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
- name: Get instance of MySQL Flexible Server
  azure_rm_mysqlflexibleserver_info:
    resource_group: myResourceGroup
    name: server_name

- name: List instances of MySQL Flexible Server and filter by tags
  azure_rm_mysqlflexibleserver_info:
    resource_group: myResourceGroup

- name: List instances of MySQL Flexible Server
  azure_rm_mysqlflexibleserver_info:
    resource_group: myResourceGroup
    tags:
      - key
'''

RETURN = '''
servers:
    description:
        - A list of dictionaries containing facts for MySQL servers.
    returned: always
    type: complex
    contains:
        id:
            description:
                - Resource ID.
            returned: always
            type: str
            sample: /subscriptions/xxxx-xxxx/resourceGroups/testRG/providers/Microsoft.DBforMySQL/flexibleServers/server01
        resource_group:
            description:
                - Resource group name.
            returned: always
            type: str
            sample: testRG
        name:
            description:
                - Resource name.
            returned: always
            type: str
            sample: server01
        location:
            description:
                - The location the resource resides in.
            returned: always
            type: str
            sample: eastus
        sku:
            description:
                - The SKU of the server.
            returned: always
            type: complex
            contains:
                name:
                    description:
                        - The name of the SKU.
                    returned: always
                    type: str
                    sample: Standard_D32s_v3
                tier:
                    description:
                        - The tier of the particular SKU.
                    returned: always
                    type: str
                    sample: GeneralPurpose
        storage:
            description:
                - Storage related properties of a server.
            type: complex
            returned: always
            contains:
                storage_size_gb:
                    description:
                        - Max storage size allowed for a server.
                    returned: always
                    type: int
                    sample: 128000
                iops:
                    description:
                        - Storage IOPS for a server.
                    returned: always
                    type: int
                    sample: 684
                auto_grow:
                    description:
                        - Enable Storage Auto Grow or not.
                    returned: always
                    type: str
                    sample: Disabled
        availability_zone:
            description:
                - Availability Zone information of the server.
            returned: always
            type: str
            sample: 1
        administrator_login:
            description:
                - The administrator's login name of a server.
            returned: always
            type: str
            sample: serveradmin
        backup:
            description:
                - Backup related properties of a server.
            type: complex
            returned: always
            contains:
                backup_retention_days:
                    description:
                        - Backup retention days for the server.
                    type: int
                    returned: always
                    sample: 7
                geo_redundant_backup:
                    description:
                        - Whether or not geo redundant backup is enabled.
                    type: str
                    returned: always
                    sample: Disabled
        version:
            description:
                - Server version.
            returned: always
            type: str
            sample: "5.7"
        state:
            description:
                - A state of a server that is visible to user.
            returned: always
            type: str
            sample: Ready
        fully_qualified_domain_name:
            description:
                - The fully qualified domain name of a server.
            returned: always
            type: str
            sample: myabdud1223.mys.database.azure.com
        high_availability:
            description:
                - High availability related properties of a server.
            type: complex
            returned: always
            contains:
                mode:
                    description:
                        - High availability mode for a server.
                    type: str
                    sample: Disabled
                    returned: always
                standby_availability_zone:
                    description:
                        - Availability zone of the standby server.
                    type: str
                    sample: Availability zone of the standby server.
                    returned: always
        network:
            description:
                - Network related properties of a server.
            type: complex
            returned: always
            contains:
                delegated_subnet_resource_id:
                    description:
                        - Delegated subnet resource id used to setup vnet for a server.
                    type: str
                    sample: null
                    returned: always
                private_dns_zone_resource_id:
                    description:
                        - Private DNS zone resource id.
                    type: str
                    sample: null
                    returned: always
        restore_point_in_time:
            description:
                - Restore point creation time (ISO8601 format), specifying the time to restore from.
            type: str
            returned: always
            sample: null
        source_server_resource_id:
            description:
                - The source MySQL server id.
            type: str
            returned: always
            sample: null
        tags:
            description:
                - Tags assigned to the resource. Dictionary of string:string pairs.
            type: dict
            returned: always
            sample: { tag1: abc }
        type:
            description:
                - The type of the resource.
            type: str
            returned: always
            sample: Microsoft.DBforMySQL/flexibleServers
'''

try:
    from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase
    from azure.core.exceptions import HttpResponseError
except ImportError:
    # This is handled in azure_rm_common
    pass


class AzureRMMySqlFlexibleServerInfo(AzureRMModuleBase):
    def __init__(self):
        # define user inputs into argument
        self.module_arg_spec = dict(
            resource_group=dict(
                type='str',
            ),
            name=dict(
                type='str'
            ),
            tags=dict(
                type='list',
                elements='str'
            )
        )
        self.results = dict(
            changed=False
        )
        self.resource_group = None
        self.name = None
        self.tags = None
        super(AzureRMMySqlFlexibleServerInfo, self).__init__(self.module_arg_spec, supports_check_mode=True, supports_tags=False, facts_module=True)

    def exec_module(self, **kwargs):
        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        if (self.resource_group is not None and self.name is not None):
            self.results['servers'] = self.get()
        elif (self.resource_group is not None):
            self.results['servers'] = self.list_by_resource_group()
        else:
            self.results['servers'] = self.list_all()

        return self.results

    def get(self):
        response = None
        results = []
        try:
            response = self.mysql_flexible_client.servers.get(resource_group_name=self.resource_group,
                                                              server_name=self.name)
            self.log("Response : {0}".format(response))
        except HttpResponseError as e:
            self.log('Could not get facts for MySQL Flexible Server. Exception as {0}'.format(e))

        if response and self.has_tags(response.tags, self.tags):
            results.append(self.format_item(response))

        return results

    def list_by_resource_group(self):
        response = None
        results = []
        try:
            response = self.mysql_flexible_client.servers.list_by_resource_group(resource_group_name=self.resource_group)
            self.log("Response : {0}".format(response))
        except HttpResponseError as e:
            self.log('Could not get facts for MySQL Flexible Servers. Exception as {0}'.format(e))

        if response is not None:
            for item in response:
                if self.has_tags(item.tags, self.tags):
                    results.append(self.format_item(item))
        return results

    def list_all(self):
        response = None
        results = []
        try:
            response = self.mysql_flexible_client.servers.list()
            self.log("Response : {0}".format(response))
        except HttpResponseError as e:
            self.log('Could not get facts for MySQL Flexible Servers. Exception as {0}'.format(e))

        if response is not None:
            for item in response:
                if self.has_tags(item.tags, self.tags):
                    results.append(self.format_item(item))
        return results

    def format_item(self, item):
        results = dict(
            resource_group=self.parse_resource_to_dict(item.id).get('resource_group'),
            id=item.id,
            name=item.name,
            type=item.type,
            tags=item.tags,
            location=item.location,
            sku=dict(),
            administrator_login=item.administrator_login,
            version=item.version,
            availability_zone=item.availability_zone,
            source_server_resource_id=item.source_server_resource_id,
            restore_point_in_time=item.restore_point_in_time,
            state=item.state,
            fully_qualified_domain_name=item.fully_qualified_domain_name,
            storage=dict(),
            backup=dict(),
            high_availability=dict(),
            network=dict(),
        )
        if item.sku not in [None, 'None']:
            results['sku']['name'] = item.sku.name
            results['sku']['tier'] = item.sku.tier
        if item.storage not in [None, 'None']:
            results['storage']['storage_size_gb'] = item.storage.storage_size_gb
            results['storage']['iops'] = item.storage.iops
            results['storage']['auto_grow'] = item.storage.auto_grow
        if item.high_availability not in [None, 'None']:
            results['high_availability']['standby_availability_zone'] = item.high_availability.standby_availability_zone
            results['high_availability']['mode'] = item.high_availability.mode
        if item.backup not in [None, 'None']:
            results['backup']['backup_retention_days'] = item.backup.backup_retention_days
            results['backup']['geo_redundant_backup'] = item.backup.geo_redundant_backup
        if item.network not in [None, 'None']:
            results['network']['delegated_subnet_resource_id'] = item.network.delegated_subnet_resource_id
            results['network']['private_dns_zone_resource_id'] = item.network.private_dns_zone_resource_id
        return results


def main():
    AzureRMMySqlFlexibleServerInfo()


if __name__ == '__main__':
    main()
