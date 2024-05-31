#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_networkwatcher_info

version_added: "2.5.0"

short_description: Get or list the network watcher facts

description:
    - Get or list the network watcher facts.

options:
    resource_group:
        description:
            - The name of the resource group.
        type: str
    name:
        description:
            - Name of the network watcher.
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
- name: Get the network watcher facts
  azure_rm_networkwatcher_info:
    resource_group: myResourceGroup
    name: mywatcher01

- name: list the network watcher facts
  azure_rm_networkwatcher_info:
    resource_group: myResourceGroup

- name: list the network watcher and filter by tags
  azure_rm_networkwatcher_info:
    tags:
      - key1
      - key2
'''

RETURN = '''
network_watchers:
    description:
        - The facts of the network watcher.
    returned: always
    type: complex
    contains:
        resource_group:
            description:
                - The resource group.
            type: str
            returned: always
            sample: NetworkWatcherRG
        id:
            description:
                - Resource ID.
            returned: always
            type: str
            sample: "/subscriptions/xxx-xxx/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/netwatcher_eastus"
        location:
            description:
                - Resource location.
            returned: always
            type: str
            sample: eastus
        name:
            description:
                - Resource name.
            returned: always
            type: str
            sample: mynetworkwatcher01
        tags:
            description:
                - Resource tags.
            returned: always
            type: dict
            sample: { 'key1':'value1' }
        type:
            description:
                - Resource type.
            returned: always
            type: str
            sample: "Microsoft.Network/networkWatchers"
        provisioning_state:
            description:
                - The provisioning state of the network watcher resource.
            type: str
            returned: always
            sample: Succeeded
'''

try:
    from azure.core.exceptions import ResourceNotFoundError
    from azure.mgmt.core.tools import parse_resource_id
except Exception:
    # This is handled in azure_rm_common
    pass

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase


class AzureRMNetworkWatcherInfo(AzureRMModuleBase):

    def __init__(self):

        self.module_arg_spec = dict(
            resource_group=dict(type='str'),
            name=dict(type='str'),
            tags=dict(type='list', elements='str')
        )

        self.results = dict(
            changed=False,
            network_watchers=[]
        )

        self.resource_group = None
        self.name = None
        self.tags = None

        super(AzureRMNetworkWatcherInfo, self).__init__(self.module_arg_spec,
                                                        supports_check_mode=True,
                                                        supports_tags=False,
                                                        facts_module=True)

    def exec_module(self, **kwargs):
        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        if self.name and self.resource_group:
            response = [self.get_by_name()]
        elif self.resource_group:
            response = self.list_by_resourcegroup()
        else:
            response = self.list_all()

        self.results['network_watchers'] = [self.to_dict(item) for item in response if response is not None]

        return self.results

    def get_by_name(self):
        response = None
        try:
            response = self.network_client.network_watchers.get(self.resource_group, self.name)

        except ResourceNotFoundError as exec:
            self.log("Failed to get network watchers, Exception as {0}".format(exec))

        return response

    def list_by_resourcegroup(self):
        response = None
        try:
            response = self.network_client.network_watchers.list(self.resource_group)
        except Exception as exec:
            self.log("Faild to list network watchers by resource group, exception as {0}".format(exec))
        return response

    def list_all(self):
        response = None
        try:
            response = self.network_client.network_watchers.list_all()
        except Exception as exc:
            self.fail("Failed to list all items - {0}".format(str(exc)))

        return response

    def to_dict(self, body):
        results = dict()
        if body is not None and self.has_tags(body.tags, self.tags):
            results = dict(
                resource_group=parse_resource_id(body.id).get('resource_group'),
                id=body.id,
                name=body.name,
                location=body.location,
                tags=body.tags,
                type=body.type,
                provisioning_state=body.provisioning_state,
            )
            return results
        return None


def main():
    AzureRMNetworkWatcherInfo()


if __name__ == '__main__':
    main()
