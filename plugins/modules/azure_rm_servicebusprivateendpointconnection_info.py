#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_servicebusprivateendpointconnection_info

version_added: "3.1.0"

short_description: Get or list the specified Private Endpoint Connection

description:
    - Get or list the specified Private Endpoint Connection facts.

options:
    name:
        description:
            - The PrivateEndpointConnection name.
        type: str
    namespace_name:
        description:
            - The namespace name.
        type: str
        required: true
    resource_group:
        description:
            - Name of the Resource group within the Azure subscription.
        type: str
        required: true
extends_documentation_fragment:
    - azure.azcollection.azure

author:
    - xuzhang3 (@xuzhang3)
    - Fred-sun (@Fred-sun)

'''

EXAMPLES = '''
- name: List all Private Endpoint Connection under a namespaces
  azure_rm_servicebusprivateendpointconnection_info:
    resource_group: myResourceGroup
    namespace_name: testbus

- name: Get a Private Endpoint Connection
  azure_rm_servicebusprivateendpointconnection_info:
    resource_group: myResourceGroup
    namespace_name: testbus
    name: connectionname
'''
RETURN = '''
private_endpoint_connection:
    description:
        - List of private endpoint connection dicts.
    returned: always
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
    from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase
except Exception:
    # This is handled in azure_rm_common
    pass


class AzureRMServiceBusPrivateEndpointConnectionInfo(AzureRMModuleBase):

    def __init__(self):

        self.module_arg_spec = dict(
            name=dict(type='str'),
            resource_group=dict(type='str', required=True),
            namespace_name=dict(type='str', required=True)
        )

        self.results = dict(
            changed=False,
            private_endpoint_connection=None
        )

        self.name = None
        self.resource_group = None
        self.namespace_name = None

        super(AzureRMServiceBusPrivateEndpointConnectionInfo, self).__init__(self.module_arg_spec,
                                                                             supports_check_mode=True,
                                                                             supports_tags=False,
                                                                             facts_module=True)

    def exec_module(self, **kwargs):
        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        response = []
        if self.name:
            response = self.get_item()
        else:
            response = self.list_items()

        self.results['private_endpoint_connection'] = [item.as_dict() for item in response]

        return self.results

    def get_item(self):
        try:
            return [self.servicebus_client.private_endpoint_connections.get(self.resource_group, self.namespace_name, self.name)]
        except Exception as exc:
            self.fail("Failed to list items - {0}".format(str(exc)))
        return []

    def list_items(self):
        self.log("List all items in namespace")
        try:
            return self.servicebus_client.private_endpoint_connections.list(self.resource_group, self.namespace_name)
        except Exception as exc:
            self.fail("Failed to list all items - {0}".format(str(exc)))
        return []


def main():
    AzureRMServiceBusPrivateEndpointConnectionInfo()


if __name__ == '__main__':
    main()
