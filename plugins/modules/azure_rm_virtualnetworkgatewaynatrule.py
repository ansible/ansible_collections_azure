#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_virtualnetworkgatewaynatrule

version_added: "2.4.0"

short_description: Gets or list the specified local network gateway in a resource group

description:
    - Gets or list the specified local network gateway in a resource group.

options:
    resource_group:
        description:
            - The local network gateway's resource group.
        type: str
        required: true
    virtual_network_gateway_name:
        description:
            - The name of the local network gateway.
        type: str
        required: true
    name:
        description:
            - he name of the resource that is unique within a resource group.
        type: str
        required: true
    type_properties_type:
        description:
            - The type of NAT rule for VPN NAT.
        type: str
        choices:
            - Dynamic
            - Static
    mode:
        description:
            - The Source NAT direction of a VPN NAT.
        type: str
        choices:
            - EgressSnat
            - IngressSnat
    ip_configuration_id:
        description:
            - The IP Configuration ID this NAT rule applies to.
        type: str
    external_mappings:
        description:
            - The private IP address external mapping for NAT.
        type: list
        elements: str
    internal_mappings:
        description:
            - The private IP address internal mapping for NAT.
        type: list
        elements: str
    state:
        description:
            - Use C(present) to create or update the virtual network gateway nat rule.
            - Use C(absent) to delete the nat rule.
        type: str
        default: present
        choices:
            - absent
            - present
extends_documentation_fragment:
    - azure.azcollection.azure
    - azure.azcollection.azure_tags

author:
    - xuzhang3 (@xuzhang3)
    - Fred Sun (@Fred-sun)
'''

EXAMPLES = '''
- name: Create a virtual netowrk nat rule
  azure_rm_virtualnetworkgatewaynatrule:
    resource_group: "{{ resource_group }}"
    virtual_network_gateway_name: "{{ vngname }}"
    name: "{{ natrulename }}"
    type_properties_type: Dynamic
    ip_configuration_id: "/subscriptions/xxx-xxx/resourceGroups/testRG/providers/Microsoft.Network/virtualNetworkGateways/testRG/ipConfigurations/ipconfig"
    mode: EgressSnat
    internal_mappings:
      - 10.1.0.0/24
    external_mappings:
      - 192.168.1.0/24

- name: Delete the virtual netowrk nat rule
  azure_rm_virtualnetworkgatewaynatrule:
    resource_group: "{{ resource_group }}"
    virtual_network_gateway_name: "{{ vngname }}"
    name: "{{ natrulename }}"
    state: absent
'''

RETURN = '''
state:
    description:
        - Gets the nat rules for a particular virtual network gateway
    returned: always
    type: complex
    contains:
        id:
            description:
                - The resource ID.
            type: str
            returned: always
            sample: "/subscriptions/xxx-xxx/resourceGroups/testRG/providers/Microsoft.Network/virtualNetworkGateways/vng01/natRules/natrule"
        internal_mappings:
            description:
                - The private IP address internal mapping for NAT.
            type: list
            returned: always
            sample: ["10.1.0.0/24"]
        external_mappings:
            description:
                - The private IP address external mapping for NAT.
            type: list
            returned: always
            sample: ["192.168.1.0/24"]
        ip_configuration_id:
            description:
                - he IP Configuration ID this NAT rule applies to.
            type: str
            returned: always
            sample:  "/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworkGateways/gateway1/ipConfigurations/default"
        type_properties_type:
            description:
                - The type of NAT rule for VPN NAT.
            type: str
            returned: always
            sample: Static
        mode:
            description:
                - The Source NAT direction of a VPN NAT.
            type: str
            returned: always
            sample: EgressSnat
        name:
            description:
                - The resource name.
            type: str
            returned: always
            sample: natrule_name
        resource_group:
            description:
                - The resource group name.
            type: str
            returned: always
            sample: testRG
        etag:
            description:
                - A unique read-only string that changes whenever the resource is updated.
            type: str
            returned: always
            sample: b5a32693-2e75-49e0-9137-ded19db658d6
        provisioning_state:
            description:
                - The provisioning state of the nat rule resource.
            type: str
            returned: always
            sample: Succeeded
        type:
            description:
                - The resource type.
            type: str
            returned: always
            sample: Microsoft.Network/virtualNetworkGateways/natRules
'''

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase

try:
    from azure.core.exceptions import HttpResponseError
    from azure.core.polling import LROPoller
except Exception:
    # handled in azure_rm_common
    pass


class AzureRMVirtualNetworkNatGateway(AzureRMModuleBase):
    """Utility class to get Azure Kubernetes Service Credentials facts"""

    def __init__(self):

        self.module_arg_spec = dict(
            name=dict(type='str', required=True),
            resource_group=dict(type='str', required=True),
            virtual_network_gateway_name=dict(type='str', required=True),
            type_properties_type=dict(type='str', choices=['Dynamic', 'Static']),
            mode=dict(type='str', choices=['EgressSnat', 'IngressSnat']),
            ip_configuration_id=dict(type='str'),
            external_mappings=dict(type='list', elements='str'),
            internal_mappings=dict(type='list', elements='str'),
            state=dict(type='str', default='present', choices=['present', 'absent'])
        )

        self.type_properties_type = None
        self.mode = None
        self.ip_configuration_id = None
        self.external_mappings = None
        self.internal_mappings = None

        self.results = dict(
            changed=False,
            state=[],
        )
        required_if = [('type_properties_type', 'Dynamic', ['ip_configuration_id'])]

        super(AzureRMVirtualNetworkNatGateway, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                              supports_check_mode=True,
                                                              required_if=required_if,
                                                              supports_tags=True,
                                                              facts_module=False)

    def exec_module(self, **kwargs):

        for key in list(self.module_arg_spec):
            setattr(self, key, kwargs[key])

        old_response = self.get_nat_rule()
        changed = False
        response = None

        if self.state == 'present':
            if old_response is not None:
                if self.type_properties_type is not None and self.type_properties_type != old_response['type_properties_type']:
                    self.fail("NAT type_properties_type cannot be changed.")
                else:
                    self.type_properties_type = old_response['type_properties_type']
                if self.mode is not None and self.mode != old_response['mode']:
                    self.fail("NAT mode cannot be changed.")
                else:
                    self.mode = old_response['mode']
                if self.ip_configuration_id is not None and self.ip_configuration_id != old_response['ip_configuration_id']:
                    changed = True
                else:
                    self.ip_configuration_id = old_response['ip_configuration_id']
                if self.internal_mappings is not None and old_response['internal_mappings'] != self.internal_mappings:
                    changed = True
                else:
                    self.internal_mappings = old_response['internal_mappings']

                if self.external_mappings is not None and self.external_mappings != old_response['external_mappings']:
                    changed = True
                else:
                    self.external_mappings = old_response['external_mappings']
            else:
                changed = True

            internal_mappings = None
            external_mappings = None
            if self.internal_mappings is not None:
                internal_mappings = [self.network_models.VpnNatRuleMapping(address_space=item) for item in self.internal_mappings]
            if self.external_mappings is not None:
                external_mappings = [self.network_models.VpnNatRuleMapping(address_space=item) for item in self.external_mappings]

            natrule_resource = self.network_models.VirtualNetworkGatewayNatRule(name=self.name,
                                                                                type_properties_type=self.type_properties_type,
                                                                                mode=self.mode,
                                                                                ip_configuration_id=self.ip_configuration_id,
                                                                                internal_mappings=internal_mappings,
                                                                                external_mappings=external_mappings)
            if changed:
                if not self.check_mode:
                    response = self.create_or_update_local_network_gateway(natrule_resource)
        else:
            if not self.check_mode:
                if old_response is not None:
                    self.delete_local_network_gateway()
                    changed = True
                    response = None
            else:
                changed = True

        if response is None:
            response = old_response
        self.results['state'] = response
        self.results['changed'] = changed
        return self.results

    def get_nat_rule(self):
        """Gets the specified nat rule"""
        response = None
        try:
            response = self.network_client.virtual_network_gateway_nat_rules.get(self.resource_group, self.virtual_network_gateway_name, self.name)
        except HttpResponseError as ec:
            self.log("Gets the specified local network gateway in a resource group Failed, Exception as {0}".format(ec))
            return None
        return self.format_response(response)

    def create_or_update_local_network_gateway(self, body):
        """Create or Update local network gateway"""
        response = None
        try:
            response = self.network_client.virtual_network_gateway_nat_rules.begin_create_or_update(self.resource_group,
                                                                                                    self.virtual_network_gateway_name, self.name, body)
            if isinstance(response, LROPoller):
                response = self.get_poller_result(response)
        except HttpResponseError as ec:
            self.fail("Create or Updated a local network gateway in a resource group Failed, Exception as {0}".format(ec))

        return self.format_response(response)

    def delete_local_network_gateway(self):
        """Deletes the specified local network gateway"""
        try:
            self.network_client.virtual_network_gateway_nat_rules.begin_delete(self.resource_group, self.virtual_network_gateway_name, self.name)
        except HttpResponseError as ec:
            self.fail("Deletes the specified nat rule, Exception as {0}".format(ec))
        return None

    def format_response(self, item):
        result = dict(
            resource_group=self.resource_group,
            id=item.id,
            name=item.name,
            type=item.type,
            etag=item.etag,
            provisioning_state=item.provisioning_state,
            type_properties_type=item.type_properties_type,
            mode=item.mode,
            internal_mappings=list(),
            external_mappings=list(),
            ip_configuration_id=item.ip_configuration_id
        )

        if item.internal_mappings is not None:
            for value in item.internal_mappings:
                result['internal_mappings'].append(value.address_space)
        if item.external_mappings is not None:
            for value in item.external_mappings:
                result['external_mappings'].append(value.address_space)
        return result


def main():
    """Main module execution code path"""

    AzureRMVirtualNetworkNatGateway()


if __name__ == '__main__':
    main()
