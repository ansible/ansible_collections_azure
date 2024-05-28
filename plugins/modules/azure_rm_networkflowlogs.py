#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_networkflowlogs
version_added: "2.5.0"
short_description: Manage the network flow logs
description:
    - Create, update or delete the network flow logs.
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
            - The name of the network flow logs.
        required: true
        type: str
    network_watcher_name:
        description:
            - The name of the network watcher.
        type: str
        required: true
    target_resource_id:
        description:
            -  ID of network security group to which flow log will be applied.
        type: str
    storage_id:
        description:
            - ID of the storage account which is used to store the flow log.
        type: str
    enabled:
        description:
            - Flag to enable/disable flow logging.
        type: bool
    retention_policy:
        description:
            - Parameters that define the retention policy for flow log.
        type: dict
        suboptions:
            days:
                description:
                    - Number of days to retain flow log records.
                type: int
            enabled:
                description:
                    - Flag to enable/disable retention.
                type: bool
    flow_analytic_configuragion:
        description:
            - Parameters that define the configuration of traffic analytics.
        type: dict
        suboptions:
            network_watcher_flow_analytics_configuration:
                description:
                    - Parameters that define the configuration of traffic analytics.
                type: dict
                suboptions:
                    enabled:
                        description:
                            - Flag to enable/disable traffic analytics.
                        type: bool
                    workspace_id:
                        description:
                            - The resource guid of the attached workspace.
                        type: str
                    workspace_region:
                        description:
                            - The location of the attached workspace.
                        type: str
                    workspace_resource_id:
                        description:
                            - Resource Id of the attached workspace.
                        type: str
                    traffic_analytics_interval:
                        description:
                            - The interval in minutes which would decide how frequently TA service should do flow analytics.
                        type: int
    state:
        description:
            - State of the Flow Logs. Use C(present) to create or update and C(absent) to delete.
        default: present
        type: str
        choices:
            - absent
            - present

extends_documentation_fragment:
    - azure.azcollection.azure
    - azure.azcollection.azure_tags

author:
    - xuzhang3 (@xuzhang3)
    - Fred-sun (@Fred-sun)

'''

EXAMPLES = '''
- name: Create a Flow Logs
  azure_rm_networkflowlogs:
    resource_group: myResourceGroup
    name: myNetworkWatcher
    *****
    location: eastus
    tags:
      testing: testing
      delete: on-exit

- name: Delete a Flow Logs
  azure_rm_networkflowlogs:
    resource_group: myResourceGroup
    name: myNetworkWatcher
    state: absent
'''
RETURN = '''
state:
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
        network_watcher_name:
            descrition:
                - The name of the network watcher.
            type: str
            returned: always
            sample: mynetworkwatcher01
        target_resource_id:
            descrition:
                - ID of network security group to which flow log will be applied.
            type: str
            returned: always
            sample: 
        storage_id:
            descrition:
                - ID of the storage account which is used to store the flow log.
            type: str
            returned: always
            sample: 
        enanbled:
            descrition:
                - Flag to enable/disable flow logging.
            type: str
            returned: always
            sample: 
        retention_policy:
            descrition:
                - Parameters that define the retention policy for flow log.
            type: str
            returned: always
            sample: 
        flow_analytics_configuration:
            descrition:
                - Parameters that define the configuration of traffic analytics.
            type: dict
            returned: always
            sample: 
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
except ImportError:
    # This is handled in azure_rm_common
    pass

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase


class AzureRMNetworkWatcher(AzureRMModuleBase):

    def __init__(self):

        self.module_arg_spec = dict(
            resource_group=dict(type='str', required=True),
            network_watcher=dict(type='str', required=True),
            name=dict(type='str', required=True),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            location=dict(type='str'),
            target_resource_id=dict(type='str'),
            storage_id=dict(type='str'),
            enabled=dict(type='bool'),
            retention_policy=dict(type='dict',
                options=dict(
                    days=dict(type='int'),
                    enabled=dict(type='bool'),
                ),
            ),
            flow_analytics_configuration=dict(
                type='dict',
                opitions=dict(
                    network_watcher_flow_analytics_configuration=dict(
                        type='dict'
                        options=dict(
                            enabled=dict(type='bool'),
                            workspace_id=dict(type='str'),
                            workspace_region=dict(type='str'),
                            workspace_resource_id=dict(type='str'),
                            traffic_analytics_interval=dict(type='int')
                    )
                )
            ),
        )

        self.resource_group = None
        self.name = None
        self.state = None
        self.location = None
        self.tags = None

        self.results = dict(
            changed=False,
            state=dict()
        )

        super(AzureRMNetworkWatcher, self).__init__(self.module_arg_spec,
                                                  supports_tags=True,
                                                  supports_check_mode=True)

    def exec_module(self, **kwargs):

        for key in list(self.module_arg_spec.keys()) + ['tags']:
            setattr(self, key, kwargs[key])

        resource_group = self.get_resource_group(self.resource_group)
        if not self.location:
            # Set default location
            self.location = resource_group.location

        changed = False
        results = dict()

        old_response = self.get_by_name()

        if old_response is not None:
            if self.state == 'present':
                update_tags, new_tags = self.update_tags(old_response['tags'])
                if update_tags:
                    changed = True
                    if not self.check_mode:
                        results = self.update_tags(dict(tags=new_tags))
                else:
                    results = old_response
            else:
                changed = True
                if not self.check_mode:
                    results = self.delete_network_watcher()
        else:
            if self.state == 'present':
                changed = True
                if not self.check_mode:
                    results = self.create_or_update(dict(tags=self.tags, location=self.location))
            else:
                changed = False
                self.log("The Flow Logs is not exists")

        self.results['changed'] = changed
        self.results['state'] = results

        return self.results

    def get_by_name(self):
        response = None
        try:
            response = self.network_client.flow_logs.get(self.resource_group, self.network_watcher_name, self.name)

        except ResourceNotFoundError as exec:
            self.log("Failed to get network flow logs, Exception as {0}".format(exec))

        return self.to_dict(response)

    def create_or_update(self, body):
        response = None
        try:
            response = self.to_dict(self.network_client.flow_logs.begin_create_or_update(self.resource_group, self.network_watcher_name, self.name, body))
        except Exception as exc:
            self.fail("Error creating Flow Logs {0} - {1}".format(self.name, str(exc)))

        return response

    def update_tags(self, body):
        response = None
        try:
            response = self.network_client.flow_logs.update_tags(self.resource_group, self.network_watcher_name, self.name, body)
        except Exception as exc:
            self.fail("Error updating Flow Logs {0} - {1}".format(self.name, str(exc)))
        return self.to_dict(response)

    def delete_flow_logs(self):
        try:
            self.network_client.flow_logs.begin_delete(self.resource_group, self.network_watcher_name, self.name)
        except Exception as exc:
            self.fail("Error deleting Flow Logs {0} - {1}".format(self.name, str(exc)))

    def to_dict(self, body):
        results = None
        if body is not None:
            results = dict(
                resource_group=self.resource_group,
                network_watcher_name=self.network_watcher_name,
                id=body.id,
                name=body.name,
                location=body.location,
                tags=body.tags,
                type=body.type,
                provisioning_state=body.provisioning_state,
                target_resource_id=body.target_resource_id,
                storage_id=body.storage_id,
                enabled=body.enabled,
                retention_policy=body.retention_policy,
                flow_analytics_configuration=body.flow_analytics_configuration,
            )
        return results


def main():
    AzureRMNetworkWatcher()


if __name__ == '__main__':
    main()
