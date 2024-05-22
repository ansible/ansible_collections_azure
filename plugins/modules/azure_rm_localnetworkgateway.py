#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_localnetworkgateway

version_added: "2.4.0"

short_description: Manage Azure Local Network Gateway in a resource group

description:
    - Create, update or delete Azure Local Network Gateway in a resource group

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
        required: true
    location:
        description:
            - The location of the local network gateway.
        type: str
    local_network_address_space:
        description:
            - Local network site address space.
        type: dict
        suboptions:
            address_prefixes:
                description:
                    - A list of address blocks reserved for this virtual network in CIDR notation.
                type: list
                elements: str
    gateway_ip_address:
        description:
            - IP address of local network gateway.
        type: str
    fqdn:
        description:
            - FQDN of local network gateway.
        type: str
    bgp_settings:
        description:
            - Local network gateway's BGP speaker settings.
        type: dict
        suboptions:
            asn:
                description:
                    - The BGP speaker's ASN.
                type: int
            bgp_peering_address:
                description:
                    - The BGP peering address and BGP identifier of this BGP speaker.
                type: str
            peer_weight:
                description:
                    - The weight added to routes learned from this BGP speaker.
                type: int
    state:
        description:
            - Use C(present) to create or update a local network gateway.
            - Use C(absent) to delete the local network gateway.
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
- name: Create a new local network gateway
  azure_rm_localnetworkgateway:
    resource_group: "{{ resource_group }}"
    name: "localgateway-name"
    local_network_address_space:
      address_prefixes:
        - 10.0.0.0/24
        - 20.0.0.0/24
    fqdn: fredtest.com
    tags:
      key: value
    bgp_settings:
      asn: 8
      bgp_peering_address: 10.3.0.1
      peer_weight: 3

- name: Delete local network gateway
  azure_rm_localnetworkgateway:
    resource_group: "{{ resource_group }}"
    name: "localgateway-name"
    state: absent
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
    from azure.core.polling import LROPoller
except Exception:
    # handled in azure_rm_common
    pass


bgp_settings_spec = dict(
    asn=dict(type='int'),
    bgp_peering_address=dict(type='str'),
    peer_weight=dict(type='int'),
)


local_network_address_space_spec = dict(
    address_prefixes=dict(type='list', elements='str')
)


class AzureRMNetworkGateWay(AzureRMModuleBase):
    """Utility class to get Azure Kubernetes Service Credentials facts"""

    def __init__(self):

        self.module_arg_spec = dict(
            name=dict(type='str', required=True),
            resource_group=dict(type='str', required=True),
            location=dict(type='str'),
            local_network_address_space=dict(type='dict', options=local_network_address_space_spec),
            gateway_ip_address=dict(type='str'),
            fqdn=dict(type='str'),
            bgp_settings=dict(type='dict', options=bgp_settings_spec),
            state=dict(type='str', default='present', choices=['present', 'absent'])
        )

        self.name = None
        self.location = None
        self.local_network_address_space = None
        self.gateway_ip_address = None
        self.fqdn = None
        self.tags = None
        self.bgp_settings = None

        self.results = dict(
            changed=False,
            state=[],
        )
        mutually_exclusive = [['gateway_ip_address', 'fqdn']]

        super(AzureRMNetworkGateWay, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                    supports_check_mode=True,
                                                    mutually_exclusive=mutually_exclusive,
                                                    supports_tags=True,
                                                    facts_module=False)

    def exec_module(self, **kwargs):

        for key in list(self.module_arg_spec) + ['tags']:
            setattr(self, key, kwargs[key])

        if not self.location:
            # Set default location
            resource_group = self.get_resource_group(self.resource_group)
            self.location = resource_group.location

        old_response = self.get_local_network_gateway()
        changed = False
        update_tags = False

        response = None
        if self.state == 'present':
            if old_response is not None:
                if self.fqdn is not None and self.fqdn != old_response['fqdn']:
                    changed = True
                else:
                    self.fqdn = old_response['fqdn']
                if self.gateway_ip_address is not None and self.gateway_ip_address != old_response['gateway_ip_address']:
                    changed = True
                else:
                    self.gateway_ip_address = old_response['gateway_ip_address']
                if self.bgp_settings is not None and\
                   not all(self.bgp_settings.get(key) == old_response['bgp_settings'].get(key) for key in self.bgp_settings.keys()):
                    changed = True
                if self.local_network_address_space is not None:
                    if old_response['local_network_address_space'].get('address_prefixes') is not None:
                        new_address = list(set(self.local_network_address_space['address_prefixes'] +
                                           old_response['local_network_address_space']['address_prefixes']))
                        if len(new_address) > len(old_response['local_network_address_space'].get('address_prefixes')):
                            changed = True
                        self.local_network_address_space['address_prefixes'] = new_address
                    else:
                        changed = True
                else:
                    self.local_network_address_space['address_prefixes'] = old_response['local_network_address_space'].get('address_prefixes')

                update_tags, new_tags = self.update_tags(old_response.get('tags'))
                if update_tags:
                    # response = self.update_local_network_gateway_tags(new_tags)
                    self.fail("Can't update the local network gateway tags, Exception code as AllPropertiesAreReadOnly")
                    changed = True
            else:
                changed = True

            local_network_address_space = None
            if self.local_network_address_space is not None:
                local_network_address_space = self.network_models.AddressSpace(address_prefixes=self.local_network_address_space['address_prefixes'])
            bgp_settings = None
            if self.bgp_settings is not None:
                bgp_settings = self.network_models.BgpSettings(asn=self.bgp_settings.get('asn'),
                                                               bgp_peering_address=self.bgp_settings.get('bgp_peering_address'),
                                                               peer_weight=self.bgp_settings.get('peer_weight'))

            gateway_resource = self.network_models.LocalNetworkGateway(location=self.location,
                                                                       tags=self.tags,
                                                                       gateway_ip_address=self.gateway_ip_address,
                                                                       fqdn=self.fqdn,
                                                                       local_network_address_space=local_network_address_space,
                                                                       bgp_settings=bgp_settings)
            if changed:
                if not self.check_mode:
                    response = self.create_or_update_local_network_gateway(gateway_resource)

            if old_response is not None:
                update_tags, new_tags = self.update_tags(old_response.get('tags'))
                if update_tags:
                    if not self.check_mode:
                        response = self.update_local_network_gateway_tags(new_tags)
                    changed = True
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

    def get_local_network_gateway(self):
        """Gets the specified local network gateway in a resource group"""
        response = None
        try:
            response = self.network_client.local_network_gateways.get(self.resource_group, self.name)
        except HttpResponseError as ec:
            self.log("Gets the specified local network gateway in a resource group Failed, Exception as {0}".format(ec))
            return None
        return self.format_response(response)

    def create_or_update_local_network_gateway(self, body):
        """Create or Update local network gateway"""
        response = None
        try:
            response = self.network_client.local_network_gateways.begin_create_or_update(self.resource_group, self.name, body)
            if isinstance(response, LROPoller):
                response = self.get_poller_result(response)
        except HttpResponseError as ec:
            self.fail("Create or Updated a local network gateway in a resource group Failed, Exception as {0}".format(ec))

        return self.format_response(response)

    def update_local_network_gateway_tags(self, tags):
        """Updates a local network gateway tags"""
        response = None
        try:
            response = self.network_client.local_network_gateways.update_tags(self.resource_group, self.name, tags)
        except HttpResponseError as ec:
            self.fail("Update a local network gateway tags Failed, Exception as {0}".format(ec))
        return self.format_response(response)

    def delete_local_network_gateway(self):
        """Deletes the specified local network gateway"""
        try:
            self.network_client.local_network_gateways.begin_delete(self.resource_group, self.name)
        except HttpResponseError as ec:
            self.fail("Deletes the specified local network gateway Failed, Exception as {0}".format(ec))
        return None

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

    AzureRMNetworkGateWay()


if __name__ == '__main__':
    main()
