#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_servicebusprivateendpointconnection
version_added: "0.1.2"
short_description: Manage Azure Service Bus
description:
    - Create, update or delete an Azure Service Bus namespaces.
options:
    resource_group:
        description:
            - Name of resource group.
        required: true
        type: str
    name:
        description:
            - Name of the servicebus namespace.
        required: true
        type: str
    state:
        description:
            - Assert the state of the servicebus. Use C(present) to create or update and use C(absen) to delete.
        default: present
        type: str
        choices:
            - absent
            - present
    location:
        description:
            - The servicebus's location.
        type: str
    sku:
        description:
            - Namespace SKU.
        type: str
        choices:
            - standard
            - basic
            - premium
        default: standard
    minimum_tls_version:
        description:
            - The minimum TLS version for the cluster to support.
        type: str
        choices:
            - '1.0'
            - '1.1'
            - '1.2'
    zone_redundant:
        description:
            - Enabling this property creates a Premium Service Bus Namespace in regions supported availability zones.
        type: bool
    encryption:
        description:
            - Properties of BYOK Encryption description.
        type: dict
        suboptions:
            key_vault_properties:
                description:
                    - Properties of KeyVault.
                type: list
                elements: dict
                suboptions:
                    key_name:
                        description:
                            - Name of the Key from KeyVault.
                        type: str
                    key_vault_uri:
                        description:
                            - Uri of KeyVault.
                        type: str
                    key_version:
                        description:
                            - Version of KeyVault.
                        type: str
                    identity:
                        description:
                            - User Identity selected for encryption.
                        type: dict
                        suboptions:
                            user_assigned_identity:
                                description:
                                    - ARM ID of user Identity selected for encryption.
                                type: str
            key_source:
                description:
                    - Enumerates the possible value of keySource for Encryption.
                type: str
                default: Microsoft.KeyVault
            require_infrastructure_encryption:
                description:
                    - Enable Infrastructure Encryption (Double Encryption).
                type: bool
    disable_local_auth:
        description:
            - This property disables SAS authentication for the Service Bus namespace.
        type: bool
    alternate_name:
        description:
            - Alternate name for namespace.
        type: str
    public_network_access:
        description:
            - This determines if traffic is allowed over public network.
            - By default it is C(Enabled).
        type: str
        default: Enabled
        choices:
            - Enabled
            - Disabled
            - SecuredByPerimeter
    premium_messaging_partitions:
        description:
            - The number of partitions of a Service Bus namespace.
            - This property is only applicable to Premium SKU namespaces.
        type: int
        default: 1
        choices:
            - 1
            - 2
            - 4

extends_documentation_fragment:
    - azure.azcollection.azure

author:
    - xuzhang3 (@xuzhang3)
    - Fred-sun (@Fred-sun)

'''

EXAMPLES = '''
- name: Create a namespace
  azure_rm_servicebusprivateendpointconnection:
    name: deadbeef
    location: eastus
    tags:
      key1: value1
'''
RETURN = '''
private_endpoint_connection:
    description:
        - The private endpoint connection facts
    type: complex
    contains:
        id:
            description:
                - Resource ID.
            returned: always
            type: str
            sample: "/subscriptions/xxx-xxx/resourceGroups/test/providers/Microsoft.ServiceBus/namespaces/nsfredrpfx008/privateEndpointConnections/fe17f69a-a0aa-4241-8c06-0f54a268e371"
        name:
            description:
                - Resource name.
            returned: always
            type: str
            sample: fe17f69a-a0aa-4241-8c06-0f54a268e371
        private_endpoint:
            description:
                - Resource name.
            returned: always
            type: str
            sample: fe17f69a-a0aa-4241-8c06-0f54a268e371
        private_link_service_connection_state:
            description:
                - Details about the state of the connection.
            returned: always
            type: complex
            contains:
                description:
                    description:
                        - Description of the connection state.
                    type: str
                    returned: always
                    sample: Jected
                status:
                    description:
                        -
                    type: str
                    returned: always
                    sample: Rejected
        provisioning_state:
            description:
                - Provisioning state of the Private Endpoint Connection..
            returned: always
            type: str
            sample: "Succeeded"
        type:
            description:
                - Resource type.
            returned: always
            type: str
            sample: "Microsoft.ServiceBus/Namespaces/PrivateEndpointConnections"
'''

try:
    from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common_ext import AzureRMModuleBaseExt
except ImportError:
    # This is handled in azure_rm_common
    pass


class AzureRMServiceBusPrivateEndpointConnection(AzureRMModuleBaseExt):
    def __init__(self):
        self.module_arg_spec = dict(
            resource_group=dict(type='str', required=True),
            namespace_name=dict(type='str', required=True),
            name=dict(type='str', required=True),
            private_endpoint=dict(
                type='dict',
                options=dict(
                    id=dict(type='str')
                )
            ),
            private_link_service_connection_state=dict(
                type='dict',
                options=dict(
                    status=dict(type='str', choices=['Pending', 'Approved', 'Rejected', 'Disconnected']),
                    description=dict(type='str')
                )
            ),
            provisioning_state=dict(
                type='str',
                choices=["Creating", "Updating", "Deleting", "Succeeded", "Canceled", "Failed"]
            ),
            state=dict(type='str', default='present', choices=['present', 'absent']),
        )

        self.resource_group = None
        self.name = None
        self.namespace_name = None
        self.private_endpoint = None
        self.private_link_service_connection_state = None
        self.provisioning_state = None
        self.state = None

        self.results = dict(
            changed=False,
            state=dict()
        )

        super(AzureRMServiceBusPrivateEndpointConnection, self).__init__(self.module_arg_spec,
                                                supports_tags=True,
                                                supports_check_mode=True)

    def exec_module(self, **kwargs):
        for key in list(self.module_arg_spec.keys()):
            setattr(self, key, kwargs[key])

        changed = False

        original = self.get()

        if self.state == 'present':
            if not self.check_mode:
                if original:
                        changed = False
                else:
                    changed = True
                    original = self.create()
            else:
                changed = True
        elif self.state == 'absent' and original:
            changed = True
            original = None
            if not self.check_mode:
                self.delete()
                self.results['deleted'] = True

        if original:
            self.results = self.to_dict(original)
        self.results['changed'] = changed
        return self.results

    def create(self):
        self.log('Cannot find namespace, creating a one')
        try:
            parameters = dict(private_link_service_connection_state=self.private_link_service_connection_state,
                              private_endpoint=self.private_endpoint,
                              provisioning_state=self.provisioning_state)
                              
            poller = self.servicebus_client.private_endpoint_connections.create_or_update(self.resource_group, self.name, parameters)
            ns = self.get_poller_result(poller)
        except Exception as exc:
            self.fail('Error creating namespace {0} - {1}'.format(self.name, str(exc)))
        return ns

    def delete(self):
        try:
            self.servicebus_client.private_endpoint_connections.begin_delete(self.resource_group, self.namespace_name, self.name)
            return True
        except Exception as exc:
            self.fail("Error deleting route {0} - {1}".format(self.name, str(exc)))

    def get(self):
        try:
            return self.servicebus_client.private_endpoint_connections.get(self.resource_group, self.namespace_name, self.name)
        except Exception:
            return None

    def to_dict(self, instance):
        return instance.as_dict()


def main():
    AzureRMServiceBusPrivateEndpointConnection()


if __name__ == '__main__':
    main()
