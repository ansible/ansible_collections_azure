#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: azure_rm_batchaccountpool_info
version_added: "3.0.0"
short_description: Get the Batch Account Pool facts
description:
    - Get the Batch Account Pool facts.

options:
    resource_group:
        description:
            - The name of the resource group in which to create the Batch Account.
        type: str
        required: true
    batch_account_name:
        description:
            - The name of the Batch Account.
        type: str
        required: true
    name:
        description:
            - The name of the batch account pool.
        type: str

extends_documentation_fragment:
    - azure.azcollection.azure

author:
    - xuzhang3 (@xuzhang3)
    - Fred Sun (@Fred-sun)
'''

EXAMPLES = '''
- name: Get the Batch Account Pool by name
  azure_rm_batchaccountpool_info:
    resource_group: MyResGroup
    batch_account_name: batchname01
    name: mypool01

- name: List the Batch Account Pool
  azure_rm_batchaccountpool_info:
    resource_group: MyResGroup
    batch_account_name: batchname01
'''

RETURN = '''
batch_account_pool:
    description:
        - Contains information about an pool in a Batch account.
    type: dict
    returned: always
    sample: {
                "allocation_state": "Steady",
                "allocation_state_transition_time": "2024-11-05T08:58:16.803138Z",
                "batch_account_name": "fredbatch02",
                "creation_time": "2024-11-05T08:58:15.399345Z",
                "current_dedicated_nodes": 0,
                "current_low_priority_nodes": 0,
                "deployment_configuration": {
                    "virtual_machine_configuration": {
                        "image_reference": {
                            "offer": "ubuntu-hpc",
                            "publisher": "microsoft-dsvm",
                            "sku": "2204",
                            "version": "latest"
                        },
                        "node_agent_sku_id": "batch.node.ubuntu 22.04",
                        "node_placement_configuration": {
                            "policy": "Regional"
                        },
                        "os_disk": {
                            "caching": "None",
                            "managed_disk": {
                                "storage_account_type": "Premium_LRS"
                            }
                        }
                    }
                },
                "etag": "0x8DCFD77FC345CFE",
                "id": "/subscriptions/xxx-xxx/resourceGroups/testRG/providers/Microsoft.Batch/batchAccounts/batch01/pools/pool01",
                "inter_node_communication": "Disabled",
                "last_modified": "2024-11-05T08:58:15.399347Z",
                "name": "poolfredbatch02--002",
                "network_configuration": {
                    "dynamic_vnet_assignment_scope": "None",
                    "enable_accelerated_networking": false,
                    "endpoint_configuration": {
                        "inbound_nat_pools": [
                            {
                                "backend_port": 33,
                                "frontend_port_range_end": 49999,
                                "frontend_port_range_start": 1,
                                "name": "nat02",
                                "protocol": "UDP"
                            }
                        ]
                    },
                    "public_ip_address_configuration": {
                        "provision": "BatchManaged"
                    },
                    "subnet_id": "/subscriptions/xxx-xxx/resourceGroups/testrg/providers/Microsoft.Network/virtualNetworks/vnet01/subnets/default"
                },
                "provisioning_state": "Succeeded",
                "provisioning_state_transition_time": "2024-11-05T08:58:15.399345Z",
                "resize_operation_status": {
                    "node_deallocation_option": "Requeue",
                    "resize_timeout": "PT15M",
                    "start_time": "2024-11-05T08:58:15.399317Z",
                    "target_dedicated_nodes": 0
                },
                "resource_group": "v-xisuRG06",
                "scale_settings": {
                    "fixed_scale": {
                        "resize_timeout": "PT15M",
                        "target_dedicated_nodes": 0,
                        "target_low_priority_nodes": 0
                    }
                },
                "target_node_communication_mode": "Default",
                "task_scheduling_policy": {
                    "node_fill_type": "Pack"
                },
                "task_slots_per_node": 1,
                "type": "Microsoft.Batch/batchAccounts/pools",
                "upgrade_policy": {
                    "automatic_os_upgrade_policy": {
                        "disable_automatic_rollback": false,
                        "enable_automatic_os_upgrade": false,
                        "os_rolling_upgrade_deferral": false,
                        "use_rolling_upgrade_policy": false
                    },
                    "mode": "Manual",
                    "rolling_upgrade_policy": {
                        "max_batch_instance_percent": 20,
                        "max_unhealthy_instance_percent": 20,
                        "max_unhealthy_upgraded_instance_percent": 20,
                        "pause_time_between_batches": "P0D",
                        "rollback_failed_instances_on_policy_breach": false
                    }
                },
                "vm_size": "STANDARD_D2S_V3"
            }
'''

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common_ext import AzureRMModuleBase

try:
    from azure.core.exceptions import ResourceNotFoundError
except ImportError:
    # This is handled in azure_rm_common
    pass


class AzureRMBatchAccountPoolInfo(AzureRMModuleBase):
    """Configuration class for an Azure RM Batch Account Pool package resource"""

    def __init__(self):
        self.module_arg_spec = dict(
            resource_group=dict(
                type='str',
                required=True,
            ),
            batch_account_name=dict(
                type='str',
                required=True
            ),
            name=dict(
                type='str',
            ),
        )

        self.resource_group = None
        self.batch_account_name = None
        self.name = None

        self.results = dict(changed=False)

        super(AzureRMBatchAccountPoolInfo, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                          supports_check_mode=True,
                                                          supports_tags=False)

    def exec_module(self, **kwargs):
        """Main module execution method"""

        for key in list(self.module_arg_spec.keys()):
            setattr(self, key, kwargs[key])

        response = []

        if self.name is not None:
            response = [self.get_batchaccount_pool()]
        else:
            response = self.list_by_batchaccount_pool()

        self.results['batch_account_pool'] = [self.format_item(item) for item in response]

        return self.results

    def list_by_batchaccount_pool(self):
        self.log("List all Batch Account in the batch account {0}".format(self.batch_account_name))
        result = []
        response = []
        try:
            response = self.batch_account_client.pool.list_by_batch_account(resource_group_name=self.resource_group,
                                                                            account_name=self.batch_account_name)
            self.log("Response : {0}".format(response))
        except Exception as e:
            self.log('Did not find the Batch Account instance. Exception as {0}'.format(e))
        for item in response:
            result.append(item.as_dict())
        return result

    def get_batchaccount_pool(self):
        '''
        Gets the properties of the specified Batch Account Pool
        '''
        self.log("Fetch the Batch Account instance {0} is present".format(self.name))
        try:
            response = self.batch_account_client.pool.get(resource_group_name=self.resource_group,
                                                          account_name=self.batch_account_name,
                                                          pool_name=self.name)
            self.log("Response : {0}".format(response))
        except ResourceNotFoundError:
            self.log('Did not find the Batch Account Pool instance.')
            return
        return response.as_dict()

    def format_item(self, item):
        if item is None:
            return
        result = item
        result['resource_group'] = self.resource_group
        result['batch_account_name'] = self.batch_account_name
        return result


def main():
    """Main execution"""
    AzureRMBatchAccountPoolInfo()


if __name__ == '__main__':
    main()
