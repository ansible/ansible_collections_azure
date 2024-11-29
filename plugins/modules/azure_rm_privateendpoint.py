#!/usr/bin/python
#
# Copyright (c) 2020 Fred-Sun, (@Fred-Sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_privateendpoint
version_added: "1.8.0"
short_description: Manage Azure private endpoint
description:
    - Create, update or delete a private endpoint.
options:
    resource_group:
        description:
            - Name of resource group.
        required: true
        type: str
    location:
        description:
            - Valid Azure location. Defaults to location of the resource group.
        type: str
    name:
        description:
            - Name of the private endpoint.
        required: true
        type: str
    subnet:
        description:
            - The ID of the subnet from which the private IP will be allocated.
            - This parameter is required for create or update.
        type: dict
        suboptions:
            id:
                description:
                    - The ID of the subnet from which the private IP will be allocated.
                type: str
    manual_private_link_service_connections:
        description:
            - A grouping of information about the connection to the remote resource.
            - Used when the network admin does not have access to approve connections to the remote resource.
        type: list
        elements: dict
        suboptions:
            name:
                description:
                    - The name of the resource that is unique within a resource group.
                type: str
            private_link_service_id:
                description:
                    - The resource id of the private endpoint to connect to.
                type: str
            group_ids:
                description:
                    - The ID(s) of the group(s) obtained from the remote resource that this private endpoint should connect to.
                type: list
                elements: str
    private_link_service_connections:
        description:
            - A grouping of information about the connection to the remote resource.
            - This parameter is required for create or update.
        type: list
        elements: dict
        suboptions:
            name:
                description:
                    - The name of the resource that is unique within a resource group.
                type: str
            private_link_service_id:
                description:
                    - The resource id of the private endpoint to connect to.
                type: str
            group_ids:
                description:
                    - The ID(s) of the group(s) obtained from the remote resource that this private endpoint should connect to.
                type: list
                elements: str
    application_security_groups:
        description:
            - The application security group in a resource group.
        type: list
        elements: dict
        suboptions:
            id:
                description:
                    - The application security group's ID.
                type: str
    custom_dns_configs:
        description:
            - An array of custom dns configurations.
        type: list
        elements: dict
        suboptions:
            fqdn:
                description:
                    - Fqdn that resolves to private endpoint ip address.
                type: str
            ip_addresses:
                description:
                    - A list of private ip addresses of the private endpoint.
                type: list
                elements: str
    custom_network_interface_name:
        description:
            - The custom name of the network interface attached to the private endpoint.
        type: str
    ip_configurations:
        description:
            - A list of IP configurations of the private endpoint.
            - This will be used to map to the First Party Service's endpoints.
        type: list
        elements: dict
        suboptions:
            name:
                description:
                    - The name of the resource that is unique within a resource group.
                type: str
            group_id:
                description:
                    - The ID of a group obtained from the remote resource that this private endpoint should connect to.
                type: str
            member_name:
                description:
                    - The member name of a group obtained from the remote resource that this private endpoint should connect to.
                type: str
            private_ip_address:
                description:
                    - A private ip address obtained from the private endpoint's subnet.
                type: str
    state:
        description:
            - State of the virtual network. Use C(present) to create or update and C(absent) to delete.
        default: present
        type: str
        choices:
            - absent
            - present

extends_documentation_fragment:
    - azure.azcollection.azure
    - azure.azcollection.azure_tags

author:
    - Fred-sun (@Fred-sun)

'''

EXAMPLES = '''
- name: Create private endpoint with private_link_service_connections
  azure_rm_privateendpoint:
    name: testprivateendpoint
    resource_group: v-xisuRG
    private_link_service_connections:
      - name: Test_private_link_service
        private_link_service_id: /subscriptions/xxx/resourceGroups/myResourceGroup/providers/Microsoft.Network/privateLinkServices/testervice
    subnet:
      id: /subscriptions/xxx/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/fredvnet/subnets/default
    tags:
      key1: value1
      key2: value2

- name: Create private endpoint with ip_configuration
  azure_rm_privateendpoint:
    name: "privateendpoint02"
    resource_group: "{{ resource_group }}"
    private_link_service_connections:
      - name: Test_private_link_service
        private_link_service_id: /subscriptions/xxx/resourceGroups/myResourceGroup/providers/Microsoft.Network/privateLinkServices/testervice
        group_ids:
          - postgresqlServer
    subnet:
      id: /subscriptions/xxx/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/fredvnet/subnets/default
    application_security_groups:
      - id: "/subscriptions/xxx/resourceGroups/myResoruceGroup/providers/Microsoft.Network/applicationSecurityGroups/app01"
      - id: "/subscriptions/xxx/resourceGroups/myResourceGroup/providers/Microsoft.Network/applicationSecurityGroups/app02"
    custom_network_interface_name: nic01
    ip_configurations:
      - name: ipc01
        group_id: postgresqlServer
        member_name: postgresqlServer
        private_ip_address: 10.1.0.9
    custom_dns_configs:
      - fqdn: testfred001
        ip_addresses:
          - 10.1.0.9

- name: Delete private endpoint
  azure_rm_privateendpoint:
    name: testprivateendpoint
    resource_group: myResourceGroup
    state: absent
'''


RETURN = '''
state:
    description:
        - List of private endpoint dict with same format as M(azure.azcollection.azure_rm_privateendpoint) module paramter.
    returned: always
    type: complex
    contains:
            id:
                description:
                    - Resource ID of the private endpoint.
                sample: /subscriptions/xxx-xxx-xxx/resourceGroups/myResourceGroup/providers/Microsoft.Network/privateEndpoints/testprivateendpoint
                returned: always
                type: str
            etag:
                description:
                    -  A unique read-only string that changes whenever the resource is updated.
                sample: 'W/\"20803842-7d51-46b2-a790-ded8971b4d8a'
                returned: always
                type: str
            network_interfaces:
                description:
                    - List ID of the network interfaces.
                returned: always
                type: list
                sample:  ["/subscriptions/xxx-xxx-xxx/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkInterfaces/fredprivateendpoint002.nic"]
            location:
                description:
                    - Valid Azure location.
                returned: always
                type: str
                sample: eastus
            tags:
                description:
                    - Tags assigned to the resource. Dictionary of string:string pairs.
                returned: always
                type: dict
                sample: { "tag1": "abc" }
            provisioning_state:
                description:
                    - Provisioning state of the resource.
                returned: always
                sample: Succeeded
                type: str
            name:
                description:
                    - Name of the private endpoint.
                returned: always
                type: str
                sample: estprivateendpoint
            subnets_id:
                description:
                    - Subnets associated with the virtual network.
                returned: always
                type: str
                sample: "/subscriptions/xxx-xxx-xxx/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/fredtestRG-vnet/subnets/default"
            manual_private_link_service_connections:
                description:
                    - The resource id of the private endpoint to connect.
                returned: always
                type: list
                sample: ["/subscriptions/xxx/resourceGroups/myRG/providers/Microsoft.Network/privateEndpoints/point/privateLinkServiceConnections/point02",]
            private_link_service_connections:
                description:
                    - The resource id of the private endpoint to connect.
                returned: always
                type: list
                sample: ["/subscriptions/xxx/resourceGroups/myRG/providers/Microsoft.Network/privateEndpoints/point/privateLinkServiceConnections/point",]
            type:
                description:
                    - Resource type.
                returned: always
                type: str
                sample: Microsoft.Network/privateEndpoints
            application_security_groups:
                description:
                    - The application security group in a resource group.
                type: complex
                returned: always
                contains:
                    id:
                        description:
                            - The application security group's ID.
                        type: str
                        returned: when-used
                        sample: "/subscriptions/xxx/resourceGroups/testRG/providers/Microsoft.Network/applicationSecurityGroups/app01"
            custom_dns_configs:
                description:
                    - An array of custom dns configurations.
                type: complex
                returned: always
                contains:
                    fqdn:
                        description:
                            - Fqdn that resolves to private endpoint ip address.
                        type: str
                        returned: when-used
                        sample: "postgresqlsrvprivate02.postgres.database.azure.com"
                    ip_addresses:
                        description:
                            - A list of private ip addresses of the private endpoint.
                        type: complex
                        returned: when-used
                        sample: ["10.1.0.9"]
            custom_network_interface_name:
                description:
                    - The custom name of the network interface attached to the private endpoint.
                type: str
                returned: always
                sample: nic01
            ip_configurations:
                description:
                    - A list of IP configurations of the private endpoint.
                    - This will be used to map to the First Party Service's endpoints.
                type: complex
                returned: always
                contains:
                    name:
                        description:
                            - The name of the resource that is unique within a resource group.
                        type: str
                        returned: when-used
                        sample: ipc01
                    group_id:
                        description:
                            - The ID of a group obtained from the remote resource that this private endpoint should connect to.
                        type: str
                        returned: when-used
                        sample: postgresqlServer
                    member_name:
                        description:
                            - The member name of a group obtained from the remote resource that this private endpoint should connect to.
                        type: str
                        returned: when-used
                        sample: postgresqlServer
                    private_ip_address:
                        description:
                            - A private ip address obtained from the private endpoint's subnet.
                        type: str
                        returned: when-used
                        sample: 10.1.0.9
'''

try:
    from azure.core.exceptions import ResourceNotFoundError
except ImportError:
    # This is handled in azure_rm_common
    pass

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common_ext import AzureRMModuleBaseExt


network_interfaces_spec = dict(
    id=dict(type='str')
)


manual_private_service_connection_spec = dict(
    name=dict(type='str'),
    private_link_service_id=dict(type='str'),
    group_ids=dict(type='list', elements='str')
)


private_service_connection_spec = dict(
    name=dict(type='str'),
    private_link_service_id=dict(type='str'),
    group_ids=dict(type='list', elements='str')
)


subnet_spec = dict(
    id=dict(type='str')
)


custom_dns_config_spec = dict(
    fqdn=dict(type='str'),
    ip_addresses=dict(type='list', elements='str')
)


application_security_group_spec = dict(
    id=dict(type='str')
)


ip_configuration_spec = dict(
    name=dict(type='str'),
    group_id=dict(type='str'),
    member_name=dict(type='str'),
    private_ip_address=dict(type='str')
)


class Actions:
    NoAction, Create, Update, Delete = range(4)


class AzureRMPrivateEndpoint(AzureRMModuleBaseExt):

    def __init__(self):

        self.module_arg_spec = dict(
            resource_group=dict(type='str', required=True),
            name=dict(type='str', required=True),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            location=dict(type='str'),
            subnet=dict(type='dict', options=subnet_spec),
            private_link_service_connections=dict(type='list', elements='dict', options=private_service_connection_spec),
            manual_private_link_service_connections=dict(type='list', elements='dict', options=manual_private_service_connection_spec),
            custom_network_interface_name=dict(type='str'),
            ip_configurations=dict(type='list', elements='dict', options=ip_configuration_spec),
            application_security_groups=dict(type='list', elements='dict', options=application_security_group_spec),
            custom_dns_configs=dict(type='list', elements='dict', options=custom_dns_config_spec)
        )

        self.resource_group = None
        self.name = None
        self.state = None
        self.location = None
        self.body = {}
        self.tags = None

        self.results = dict(
            changed=False,
            state=dict()
        )
        self.to_do = Actions.NoAction
        mutually_exclusive = [['private_link_service_connections', 'manual_private_link_service_connections']]

        super(AzureRMPrivateEndpoint, self).__init__(self.module_arg_spec,
                                                     supports_tags=True,
                                                     supports_check_mode=True,
                                                     mutually_exclusive=mutually_exclusive)

    def exec_module(self, **kwargs):

        for key in list(self.module_arg_spec.keys()) + ['tags']:
            if hasattr(self, key):
                setattr(self, key, kwargs[key])
            elif kwargs[key] is not None:
                self.body[key] = kwargs[key]

        self.inflate_parameters(self.module_arg_spec, self.body, 0)

        resource_group = self.get_resource_group(self.resource_group)
        if not self.location:
            # Set default location
            self.location = resource_group.location
        self.body['location'] = self.location
        self.body['tags'] = self.tags

        self.log('Fetching private endpoint {0}'.format(self.name))
        old_response = self.get_resource()

        if old_response is None:
            if self.state == "present":
                self.to_do = Actions.Create
        else:
            if self.state == 'absent':
                self.to_do = Actions.Delete
            else:
                update_tags, newtags = self.update_tags(old_response.get('tags', {}))
                if update_tags:
                    self.body['tags'] = newtags
                    self.to_do = Actions.Update

        if (self.to_do == Actions.Create) or (self.to_do == Actions.Update):
            self.results['changed'] = True
            if self.check_mode:
                return self.results
            response = self.create_update_resource_private_endpoint(self.body)
        elif self.to_do == Actions.Delete:
            self.results['changed'] = True
            if self.check_mode:
                return self.results
            response = self.delete_private_endpoint()
        else:
            self.results['changed'] = False
            response = old_response
        if response is not None:
            self.results['state'] = response
        return self.results

    def create_update_resource_private_endpoint(self, privateendpoint):
        try:
            poller = self.network_client.private_endpoints.begin_create_or_update(resource_group_name=self.resource_group,
                                                                                  private_endpoint_name=self.name, parameters=privateendpoint)
            new_privateendpoint = self.get_poller_result(poller)
        except Exception as exc:
            self.fail("Error creating or updating private endpoint {0} - {1}".format(self.name, str(exc)))

        return self.private_endpoints_to_dict(new_privateendpoint)

    def delete_private_endpoint(self):
        try:
            poller = self.network_client.private_endpoints.begin_delete(self.resource_group, self.name)
            result = self.get_poller_result(poller)
        except Exception as exc:
            self.fail("Error deleting private endpoint {0} - {1}".format(self.name, str(exc)))
        return result

    def get_resource(self):
        found = False
        try:
            private_endpoint = self.network_client.private_endpoints.get(self.resource_group, self.name)
            results = self.private_endpoints_to_dict(private_endpoint)
            found = True
            self.log("Response : {0}".format(results))
        except ResourceNotFoundError:
            self.log("Did not find the private endpoint resource")
        if found is True:
            return results
        else:
            return None

    def private_endpoints_to_dict(self, privateendpoint):
        results = dict(
            id=privateendpoint.id,
            name=privateendpoint.name,
            location=privateendpoint.location,
            tags=privateendpoint.tags,
            provisioning_state=privateendpoint.provisioning_state,
            type=privateendpoint.type,
            etag=privateendpoint.etag,
            subnet=dict(id=privateendpoint.subnet.id),
            custom_network_interface_name=privateendpoint.custom_network_interface_name,
            custom_dns_configs=[],
            application_security_groups=[],
            ip_configurations=[],
        )
        if privateendpoint.network_interfaces and len(privateendpoint.network_interfaces) > 0:
            results['network_interfaces'] = []
            for interface in privateendpoint.network_interfaces:
                results['network_interfaces'].append(interface.id)
        if privateendpoint.private_link_service_connections and len(privateendpoint.private_link_service_connections) > 0:
            results['private_link_service_connections'] = []
            for connections in privateendpoint.private_link_service_connections:
                results['private_link_service_connections'].append(dict(private_link_service_id=connections.private_link_service_id, name=connections.name))
        if privateendpoint.manual_private_link_service_connections and len(privateendpoint.manual_private_link_service_connections) > 0:
            results['manual_private_link_service_connections'] = []
            for connections in privateendpoint.manual_private_link_service_connections:
                results['manual_private_link_service_connections'].append(dict(
                    private_link_service_id=connections.private_link_service_id, name=connections.name))
        if privateendpoint.ip_configurations:
            for item in privateendpoint.ip_configurations:
                ip_config = dict(
                    name=item.name,
                    group_id=item.group_id,
                    member_name=item.member_name,
                    private_ip_address=item.private_ip_address
                )
                results['ip_configurations'].append(ip_config)
        if privateendpoint.application_security_groups:
            for item in privateendpoint.application_security_groups:
                app_security_group = dict(
                    id=item.id
                )
                results['application_security_groups'].append(app_security_group)
        if privateendpoint.custom_dns_configs:
            for item in privateendpoint.custom_dns_configs:
                dns_config = dict(
                    fqdn=item.fqdn,
                    ip_addresses=item.ip_addresses
                )
                results['custom_dns_configs'].append(dns_config)

        return results


def main():
    AzureRMPrivateEndpoint()


if __name__ == '__main__':
    main()
