#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_networkflowlog_info

version_added: "2.5.0"

short_description: Get or list the network flow logs

description:
    - Get or list the network flow logs facts.

options:
    resource_group:
        description:
            - The name of the resource group.
        type: str
        required: true
    network_watcher_name:
        description:
            - Name of the network watcher.
        type: str
        required: true
    name:
        description:
            - Name of the network flow logs.
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
  azure_rm_networkflowlog_info:
    resource_group: myResourceGroup
    network_watcher_name: mywatcher01
    name: flowlogname

- name: list the network flow logs and filter by tags
  azure_rm_networkflowlog_info:
    resource_group: myResourceGroup
    network_watcher_name: mywatcher01
    tags:
      - key1
'''

RETURN = '''
flow_logs:
    description:
        - The facts of the network flow logs.
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
            sample: /subscriptions/xxx-xxx/resourceGroups/NetWatcherRG/providers/Microsoft.Network/networkWatchers/NetWatcher_eastus/flowLogs/xz-flowlog"
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
            sample: xz-flowlog
        network_watcher_name:
            description:
                - The name of the network watcher.
            type: str
            returned: always
            sample: NetWatcher_eastus
        target_resource_id:
            description:
                - ID of network security group to which flow log will be applied.
            type: str
            returned: always
            sample: /subscriptions/xxx-xxx/resourceGroups/xz3mlwaiserv/providers/Microsoft.Network/virtualNetworks/xz3mlwvnet"
        storage_id:
            description:
                - ID of the storage account which is used to store the flow log.
            type: str
            returned: always
            sample: "/subscriptions/xxx-xxx/resourceGroups/AutoTagFunctionAppRG/providers/Microsoft.Storage/storageAccounts/autotagfunc01"
        enanbled:
            description:
                - Flag to enable/disable flow logging.
            type: str
            returned: always
            sample: true
        retention_policy:
            description:
                - Parameters that define the retention policy for flow log.
            type: complex
            returned: always
            contains:
                day:
                    description:
                        - Number of days to retain flow log records.
                    type: int
                    returned: always
                    sample: 0
                enabled:
                    description:
                        - Flag to enable/disable retention.
                    type: bool
                    returned: always
                    sample: false
        flow_analytics_configuration:
            description:
                - Parameters that define the configuration of traffic analytics.
            type: complex
            returned: always
            contains:
                network_watcher_flow_analytics_configuration:
                    description:
                        - Parameters that define the configuration of traffic analytics.
                    type: complex
                    returned: always
                    contains:
                        enabled:
                            description:
                                - Flag to enable/disable traffic analytics.
                            type: bool
                            returned: always
                            sample: true
                        workspace_id:
                            description:
                                - The resource guid of the attached workspace.
                            type: str
                            returned: always
                            sample: 7c16a8dd-b983-4f75-b78b-a804c169306c
                        workspace_region:
                            description:
                                - The location of the attached workspace.
                            type: str
                            returned: always
                            sample: eastus
                        workspace_resource_id:
                            description:
                                - Resource Id of the attached workspace.
                            type: str
                            returned: always
                            sample: /subscriptions/xxx-xxx/resourceGroups/DefaulUS/providers/Microsoft.OperationalInsights/workspaces/DefaultWorkspace-0-EUS"
                        traffic_analytics_interval:
                            description:
                                - The interval in minutes which would decide how frequently TA service should do flow analytics.
                            type: str
                            returned: always
                            sample: 60
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
            sample: "Microsoft.Network/networkWatchers/flowLogs"
        provisioning_state:
            description:
                - The provisioning state of the network flow logs resource.
            type: str
            returned: always
            sample: Succeeded
'''

try:
    from azure.core.exceptions import ResourceNotFoundError
except Exception:
    # This is handled in azure_rm_common
    pass

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase


class AzureRMNetworkFlowLogInfo(AzureRMModuleBase):

    def __init__(self):

        self.module_arg_spec = dict(
            resource_group=dict(type='str', required=True),
            network_watcher_name=dict(type='str', required=True),
            name=dict(type='str'),
            tags=dict(type='list', elements='str')
        )

        self.results = dict(
            changed=False,
            flow_logs=[]
        )

        self.resource_group = None
        self.network_watcher_name = None
        self.name = None
        self.tags = None

        super(AzureRMNetworkFlowLogInfo, self).__init__(self.module_arg_spec,
                                                        supports_check_mode=True,
                                                        supports_tags=False,
                                                        facts_module=True)

    def exec_module(self, **kwargs):
        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        if self.name:
            response = [self.get_by_name()]
        else:
            response = self.list_by_network_watcher()

        self.results['flow_logs'] = [self.to_dict(item) for item in response if response is not None]

        return self.results

    def get_by_name(self):
        response = None
        try:
            response = self.network_client.flow_logs.get(self.resource_group, self.network_watcher_name, self.name)

        except ResourceNotFoundError as exec:
            self.log("Failed to get network flow logs, Exception as {0}".format(exec))

        return response

    def list_by_network_watcher(self):
        response = []
        try:
            response = self.network_client.flow_logs.list(self.resource_group, self.network_watcher_name)
        except Exception as exec:
            self.log("Faild to list network flow logs by network watcher, exception as {0}".format(exec))
        return response

    def to_dict(self, body):
        results = dict()
        if body is not None and self.has_tags(body.tags, self.tags):
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
                retention_policy=dict(),
                flow_analytics_configuration=dict()
            )
            if body.retention_policy is not None:
                results['retention_policy']['days'] = body.retention_policy.days
                results['retention_policy']['enabled'] = body.retention_policy.enabled
            if body.flow_analytics_configuration is not None:
                results['flow_analytics_configuration']['network_watcher_flow_analytics_configuration'] = dict()
                if body.flow_analytics_configuration.network_watcher_flow_analytics_configuration is not None:
                    new_config = body.flow_analytics_configuration.network_watcher_flow_analytics_configuration
                    results['flow_analytics_configuration']['network_watcher_flow_analytics_configuration']['enabled'] = new_config.enabled
                    results['flow_analytics_configuration']['network_watcher_flow_analytics_configuration']['workspace_id'] = new_config.workspace_id
                    results['flow_analytics_configuration']['network_watcher_flow_analytics_configuration']['workspace_region'] = new_config.workspace_region
                    results['flow_analytics_configuration']['network_watcher_flow_analytics_configuration']['workspace_resource_id'] = \
                        new_config.workspace_resource_id
                    results['flow_analytics_configuration']['network_watcher_flow_analytics_configuration']['traffic_analytics_interval'] = \
                        new_config.traffic_analytics_interval

        return results


def main():
    AzureRMNetworkFlowLogInfo()


if __name__ == '__main__':
    main()
