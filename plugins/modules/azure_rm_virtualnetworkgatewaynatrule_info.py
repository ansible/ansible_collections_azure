#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_virtualnetworkgatewaynatrule_info

version_added: "2.4.0"

short_description: Gets or list nat rules for a particular virtual network gateway

description:
    - Gets or list nat rules for a particular virtual network gateway.

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
            - The name of the nat rule.
        type: str

extends_documentation_fragment:
    - azure.azcollection.azure

author:
    - xuzhang3 (@xuzhang3)
    - Fred Sun (@Fred-sun)
'''

EXAMPLES = '''
- name: Gets the nat rule by the name
  azure_rm_virtualnetworkgatewaynatrule_info:
    resource_group: "{{ resource_group }}"
    virtual_network_gateway_name: "{{ local_networkgateway_name }}"
    name: "{{ name }}"

- name: List all nat rules for a particular virtual network gateway
  azure_rm_virtualnetworkgatewaynatrule_info:
    resource_group: "{{ resource_group }}"
    virtual_network_gateway_name: "{{ local_networkgateway_name }}"
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
except Exception:
    # handled in azure_rm_common
    pass


class AzureRMVirtualNetworkGatewayNatRuleInfo(AzureRMModuleBase):
    """Utility class to get Azure Kubernetes Service Credentials facts"""

    def __init__(self):

        self.module_args = dict(
            name=dict(type='str'),
            resource_group=dict(type='str', required=True),
            virtual_network_gateway_name=dict(type='str', required=True),
        )

        self.name = None

        self.results = dict(
            changed=False,
            state=[],
        )

        super(AzureRMVirtualNetworkGatewayNatRuleInfo, self).__init__(derived_arg_spec=self.module_args,
                                                                      supports_check_mode=True,
                                                                      supports_tags=False,
                                                                      facts_module=True)

    def exec_module(self, **kwargs):

        for key in self.module_args:
            setattr(self, key, kwargs[key])

        if self.name is not None:
            self.results['state'] = self.get_by_name()
        else:
            self.results['state'] = self.list_by_virtual_network_gateway()

        return self.results

    def get_by_name(self):
        """Gets the nat rule by name"""
        response = None

        try:
            response = self.network_client.virtual_network_gateway_nat_rules.get(self.resource_group, self.virtual_network_gateway_name, self.name)
        except HttpResponseError as ec:
            self.log("Gets the nat rule by name got a Exception, Exception as {0}".format(ec))
        if response:
            return [self.format_response(response)]
        else:
            return []

    def list_by_virtual_network_gateway(self):
        """Gets all the nat rule in the local network gateway"""
        response = None
        try:
            response = self.network_client.virtual_network_gateway_nat_rules.list_by_virtual_network_gateway(self.resource_group,
                                                                                                             self.virtual_network_gateway_name)
        except HttpResponseError as ec:
            self.log("Gets all nat rule by the local network gateway got Exception, Exception as {0}".format(ec))

        if response:
            return [self.format_response(item) for item in response]
        else:
            return []

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

    AzureRMVirtualNetworkGatewayNatRuleInfo()


if __name__ == '__main__':
    main()
