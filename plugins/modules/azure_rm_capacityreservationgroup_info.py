#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_capacityreservationgroup_info

version_added: "2.4.0"

short_description: Get or list the capacity reservation group

description:
    - Get or list the capacity reservation group.

options:
    resource_group:
        description:
            - Name of the resource group.
        type: str
    name:
        description:
            - Name of the capacity reservation group.
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
- name: Get facts of the capacity reservation group by name
  azure_rm_capacityreservationgroup_info:
    resource_group: myResourceGroup
    name: mycapacityreservationgroup

- name: List facts of the capacity reservation group by resource group
  azure_rm_capacityreservationgroup_info:
    resource_group: myResourceGroup

- name: List facts of the capacity reservation group by subscription and filter by tags
  azure_rm_capacityreservationgroup_info:
    tags:
      - testing
      - foo:bar
'''

RETURN = '''
capacity_reservation_group:
    description:
        - Current state of the Capacity Reservation Group.
    returned: always
    type: complex
    contains:
        id:
            description:
                - Resource ID.
            returned: always
            type: str
            sample: "/subscriptions/xxx-xxx/resourceGroups/testRG/providers/Microsoft.Compute/capacityReservationGroups/testname01"
        location:
            description:
                - The Geo-location where the resource lives.
            returned: always
            type: str
            sample: eastus
        name:
            description:
                - Resource name.
            returned: always
            type: str
            sample: testname01
        resource_group:
            description:
                - Name of resource group.
            type: str
            returned: always
            sample: myResourceGroup
        tags:
            description:
                - Resource tags.
            returned: always
            type: dict
            sample: { 'key': 'value' }
        zones:
            description:
                -  A list of all capacity reservation resource ids that belong to capacity reservation group.
            returned: always
            type: list
            sample: ['1', '2']
        type:
            description:
                - The resource type.
            type: str
            returned: always
            sample: "Microsoft.Compute/capacityReservationGroups/capacityReservations"
'''

try:
    from azure.core.exceptions import HttpResponseError
except Exception:
    # This is handled in azure_rm_common
    pass

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase


class AzureRMCapacityReservationGroupInfo(AzureRMModuleBase):

    def __init__(self):

        self.module_arg_spec = dict(
            resource_group=dict(type='str'),
            name=dict(type='str'),
            tags=dict(type='list', elements='str')
        )

        self.results = dict(
            changed=False,
            capacity_reservation_groups=[]
        )

        self.resource_group = None
        self.name = None
        self.tags = None

        super(AzureRMCapacityReservationGroupInfo, self).__init__(self.module_arg_spec,
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

        for item in response:
            if item is not None and self.has_tags(item.tags, self.tags):
                self.results['capacity_reservation_groups'].append(self.to_dict(item))

        return self.results

    def get_by_name(self):
        response = None
        try:
            response = self.compute_client.capacity_reservation_groups.get(self.resource_group, self.name)

        except HttpResponseError as exec:
            self.log("Failed to retrieves information about a capacity reservation group, Exception as {0}".format(exec))

        return response

    def list_by_resourcegroup(self):
        response = None
        try:
            response = self.compute_client.capacity_reservation_groups.list_by_resource_group(self.resource_group)
        except HttpResponseError as exec:
            self.log("Faild to list ssh public keys by resource group, exception as {0}".format(exec))
        return response

    def list_all(self):
        response = None
        try:
            response = self.compute_client.capacity_reservation_groups.list_by_subscription()
        except HttpResponseError as exc:
            self.fail("Failed to list all items - {0}".format(str(exc)))

        return response

    def to_dict(self, body):
        return dict(
            id=body.id,
            resource_group=self.resource_group,
            name=body.name,
            location=body.location,
            tags=body.tags,
            type=body.type,
            zones=body.zones,
        )


def main():
    AzureRMCapacityReservationGroupInfo()


if __name__ == '__main__':
    main()
