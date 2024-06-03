#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_capacityreservation_info

version_added: "2.4.0"

short_description: Get or list the capacity reservation

description:
    - Get or list the capacity reservation.

options:
    resource_group:
        description:
            - Name of the resource group.
        type: str
        required: true
    capacity_reservation_group_name:
        description:
            - Name of the capacity reservation.
        type: str
        required: true
    name:
        description:
            - The name of the capacity reservation.
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
- name: List all capacity reservations by Capacity Reservation Group
  azure_rm_capacityreservation_info:
    resource_group: myResourceGroup
    capacity_reservation_group_name: mycapacityreservationgroup
    tags:
      - key1

- name: Get facts of the capacity reservation
  azure_rm_capacityreservation_info:
    resource_group: myResourceGroup
    capacity_reservation_group_name: mycapacityreservationgroup
    name: mycapacityreservation
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
                -  A list of all capacity reservation resource ids that belong to capacity reservation.
            returned: always
            type: list
            sample: ['1', '2']
        # capacity_reservations:
        # instance_view:
        # type:
        # virtual_machines_associated:
'''

try:
    from azure.core.exceptions import HttpResponseError
    #import logging
    #logging.basicConfig(filename='log.log', level=logging.INFO)
except Exception:
    # This is handled in azure_rm_common
    pass

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase


class AzureRMCapacityReservationInfo(AzureRMModuleBase):

    def __init__(self):

        self.module_arg_spec = dict(
            resource_group=dict(type='str', required=True),
            capacity_reservation_group_name=dict(type='str', required=True),
            name=dict(type='str'),
            tags=dict(type='list', elements='str')
        )

        self.results = dict(
            changed=False,
            capacity_reservation=[]
        )

        self.resource_group = None
        self.capacity_reservation_group_name = None
        self.name = None
        self.tags = None

        super(AzureRMCapacityReservationInfo, self).__init__(self.module_arg_spec,
                                                             supports_check_mode=True,
                                                             supports_tags=False,
                                                             facts_module=True)

    def exec_module(self, **kwargs):
        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        if self.name is not None:
            response = [self.get_by_name()]
        else:
            response = self.list_by_capacity_reservation_group()

        for item in response:
            if item is not None and self.has_tags(item.tags, self.tags):
                self.results['capacity_reservations'].append(self.to_dict(item))

        return self.results

    def get_by_name(self):
        response = None
        try:
            response = self.compute_client.capacity_reservations.get(self.resource_group, self.capacity_reservation_group_name, self.name)

        except HttpResponseError as exec:
            self.log("Failed to retrieves information about a capacity reservation, Exception as {0}".format(exec))

        return response

    def list_by_capacity_reservation_group(self):
        response = None
        try:
            response = self.compute_client.capacity_reservations.list_by_capacity_reservation_group(self.resource_group, self.capacity_reservation_group_name)
        except HttpResponseError as exec:
            self.log("Faild to list capacity reservation by the capacity reservation group, exception as {0}".format(exec))
        return response

    def to_dict(self, body):
        return body.as_dict()
        return dict(
            id=body.id,
            resource_group=self.resource_group,
            name=body.name,
            location=body.location,
            tags=body.tags,
            type=body.type,
            zones=body.zones,
            capacity_reservations=body.capacity_reservations,
            virtual_machines_associated=body.virtual_machines_associated,
            instance_view=body.instance_view,
        )


def main():
    AzureRMCapacityReservationInfo()


if __name__ == '__main__':
    main()
