#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_localnetworkgateway_info

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
    name:
        description:
            - The name of the local network gateway.
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
    - Fred Sun (@Fred-sun)
'''

EXAMPLES = '''
- name: Gets the specified local network gateway in a resource group
  azure_rm_localnetworkgateway_info:
    resource_group: "{{ resource_group }}"
    name: "{{ local_networkgateway_name }}"

- name: Gets all the local network gateways in a resource group
  azure_rm_localnetworkgateway_info:
    resource_group: "{{ resource_group }}"

- name: Gets all the local network gateways in a resource group and filter by tags
  azure_rm_localnetworkgateway_info:
    resource_group: "{{ resource_group }}"
    tags:
      - foo
'''

RETURN = '''
state:
    description:
        - Current state of the Azure Local Network Gateway resource.
    returned: always
    type: complex
    contains:
        id:
            description:
                - The resource ID.
            type: str
            returned: always
            sample: "/subscriptions/xxxx-xxxx/resourceGroups/testRG/providers/Microsoft.Network/localNetworkGateways/testgateway"
        bgp_settings:
            description:
                - Local network gateway's BGP speaker settings.
            type: complex
            contains:
                asn:
                    description:
                        - The BGP speaker's ASN.
                    type: int
                    returned: always
                    sample: 10
                bgp_peering_address:
                    description:
                        - The BGP peering address and BGP identifier of this BGP speaker.
                    type: str
                    returned: always
                    sample: 10.0.0.3
                peer_weight:
                    description:
                        - The weight added to routes learned from this BGP speaker.
                    type: int
                    returned: always
                    sample: 0
        fqdn:
            description:
                - FQDN of local network gateway.
            type: str
            returned: always
            sample: testfqdn.com
        gateway_ip_address:
            description:
                - IP address of local network gateway.
            type: str
            returned: always
            sample: 10.1.1.1
        etag:
            description:
                - A unique read-only string that changes whenever the resource is updated.
            type: str
            returned: always
            sample: b5a32693-2e75-49e0-9137-ded19db658d6
        local_network_address_space:
            description:
                - Local network site address space.
            type: complex
            contains:
                address_prefixes:
                    description:
                        - A list of address blocks reserved for this virtual network in CIDR notation.
                    type: list
                    returned: always
                    sample: ["10.0.0.0/24", "20.0.0.0/24"]
        location:
            description:
                - The resource location.
            type: str
            returned: always
            sample: eastus
        name:
            description:
                - The resource name.
            type: str
            returned: always
            sample: testgateway
        provisioning_state:
            description:
                - The provisioning state of the local network gateway resource.
            type: str
            returned: always
            sample: Succeeded
        tags:
            description:
                - The resource tags.
            type: str
            returned: always
            sample: {'key1': 'value1', 'key2': 'value2'}
        type:
            description:
                - The resource type.
            type: str
            returned: always
            sample: Microsoft.Network/localNetworkGateways
'''

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase

try:
    from azure.core.exceptions import HttpResponseError
except Exception:
    # handled in azure_rm_common
    pass


class AzureRMNetworkGateWayInfo(AzureRMModuleBase):
    """Utility class to get Azure Kubernetes Service Credentials facts"""

    def __init__(self):

        self.module_args = dict(
            name=dict(type='str'),
            resource_group=dict(type='str', required=True),
            tags=dict(type='list', elements='str'),
        )

        self.name = None
        self.tags = None

        self.results = dict(
            changed=False,
            state=[],
        )

        super(AzureRMNetworkGateWayInfo, self).__init__(derived_arg_spec=self.module_args,
                                                        supports_check_mode=True,
                                                        supports_tags=False,
                                                        facts_module=True)

    def exec_module(self, **kwargs):

        for key in self.module_args:
            setattr(self, key, kwargs[key])

        if self.name is not None:
            self.results['state'] = self.get_local_network_gateway()
        else:
            self.results['state'] = self.list_local_network_gateway()

        return self.results

    def get_local_network_gateway(self):
        """Gets the specified local network gateway in a resource group"""
        response = None

        try:
            response = self.network_client.local_network_gateways.get(self.resource_group, self.name)
        except HttpResponseError as ec:
            self.log("Gets the specified local network gateway in a resource group Failed, Exception as {0}".format(ec))
        if response and self.has_tags(response.tags, self.tags):
            return [self.format_response(response)]
        else:
            return []

    def list_local_network_gateway(self):
        """Gets all the local network gateways in a resource group"""
        response = None

        try:
            response = self.network_client.local_network_gateways.list(self.resource_group)
        except HttpResponseError as ec:
            self.log("Gets all the local network gateways in a resource group Failed, Exception as {0}".format(ec))

        if response:
            results = []
            for item in response:
                if self.has_tags(item.tags, self.tags):
                    results.append(self.format_response(item))
            return results
        else:
            return []

    def format_response(self, item):
        result = dict(
            id=item.id,
            name=item.name,
            location=item.location,
            type=item.type,
            tags=item.tags,
            etag=item.etag,
            local_network_address_space=dict(),
            gateway_ip_address=item.gateway_ip_address,
            fqdn=item.fqdn,
            provisioning_state=item.provisioning_state,
            bgp_settings=dict(),
        )

        if item.local_network_address_space is not None:
            result['local_network_address_space']['address_prefixes'] = item.local_network_address_space.address_prefixes
        if item.bgp_settings is not None:
            result['bgp_settings']['asn'] = item.bgp_settings.asn
            result['bgp_settings']['bgp_peering_address'] = item.bgp_settings.bgp_peering_address
            result['bgp_settings']['peer_weight'] = item.bgp_settings.peer_weight
        return result


def main():
    """Main module execution code path"""

    AzureRMNetworkGateWayInfo()


if __name__ == '__main__':
    main()
