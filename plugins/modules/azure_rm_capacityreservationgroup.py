#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_capacityreservationgroup
version_added: "2.4.0"
short_description: Manage Capacity Reservation Group
description:
    - Create, update or delete the Capacity Reservation Group.
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
            - The name of the Capacity Reservation Group.
        required: true
        type: str
    zones:
        description:
            - Availability Zones to use for this capacity reservation group.
            - The zones can be assigned only during creation.
            - If not provided, the group supports only regional resources in the region.
            - If provided, enforces each capacity reservation in the group to be in one of the zones.
        type: list
        elements: str
        choices:
            - '1'
            - '2'
            - '3'
    state:
        description:
            - State of the Capacity Reservation Group. Use C(present) to create or update and C(absent) to delete.
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
- name: Create a Capacity Reservation Group
  azure_rm_capacityreservationgroup:
    resource_group: myResourceGroup
    name: testname01
    zones:
      - 1
      - 2
    tags:
      key: value

- name: Delete the Capacity Reservation Group
  azure_rm_capacityreservationgroup:
    resource_group: myResourceGroup
    name: testname01
    state: absent
'''
RETURN = '''
state:
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
'''

try:
    from azure.core.exceptions import ResourceNotFoundError
except ImportError:
    # This is handled in azure_rm_common
    pass

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase


class AzureRMCapacityReservationGroup(AzureRMModuleBase):

    def __init__(self):

        self.module_arg_spec = dict(
            resource_group=dict(type='str', required=True),
            name=dict(type='str', required=True),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            location=dict(type='str'),
            zones=dict(type='list', elements='str', choices=['1', '2', '3']),
        )

        self.resource_group = None
        self.name = None
        self.state = None
        self.location = None
        self.zones = None

        self.body = dict()

        self.results = dict(
            changed=False,
            state=dict()
        )

        super(AzureRMCapacityReservationGroup, self).__init__(self.module_arg_spec,
                                                              supports_tags=True,
                                                              supports_check_mode=True)

    def exec_module(self, **kwargs):

        for key in list(self.module_arg_spec.keys()) + ['tags']:
            setattr(self, key, kwargs[key])
            for key in ['tags', 'zones']:
                self.body[key] = kwargs[key]

        old_response = self.get_by_name()

        changed = False
        results = None

        if old_response is not None:
            if self.state == 'present':
                update_tags, self.body['tags'] = self.update_tags(old_response['tags'])
                if self.location is not None and self.location.lower() != old_response.get('location').lower():
                    self.fail('The parameters location not support to udpate')
                elif self.body.get('zones') is not None and not all(key in old_response['zones'] for key in self.body[key]):
                    self.fail('The parameters zones not support to udpate')
                elif update_tags:
                    changed = True
                    if not self.check_mode:
                        results = self.update_capacity_reservation_groups(dict(tags=self.body['tags']))
                else:
                    results = old_response
            else:
                changed = True
                if not self.check_mode:
                    results = self.delete_capacity_reservation_groups()
        else:
            resource_group = self.get_resource_group(self.resource_group)
            if self.location is None:
                # Set default location
                self.body['location'] = resource_group.location

            if self.state == 'present':
                changed = True
                if not self.check_mode:
                    results = self.create_capacity_reservation_groups(self.body)
            else:
                changed = False
                self.log("The Capacity Reservation Group is not exists")

        self.results['changed'] = changed
        self.results['state'] = results

        return self.results

    def get_by_name(self):
        response = None
        try:
            response = self.compute_client.capacity_reservation_groups.get(self.resource_group, self.name)

        except ResourceNotFoundError as exec:
            self.log("Failed to get ssh public keys, Exception as {0}".format(exec))

        return self.to_dict(response)

    def create_capacity_reservation_groups(self, body):
        response = None
        try:
            response = self.to_dict(self.compute_client.capacity_reservation_groups.create_or_update(self.resource_group, self.name, body))
        except Exception as exc:
            self.fail("Error creating Capacity Reservation Group {0} - {1}".format(self.name, str(exc)))

        return self.to_dict(response)

    def update_capacity_reservation_groups(self, body):
        response = None
        try:
            response = self.compute_client.capacity_reservation_groups.update(self.resource_group, self.name, body)
        except Exception as exc:
            self.fail("Error updating Capacity Reservation Group {0} - {1}".format(self.name, str(exc)))
        return self.to_dict(response)

    def delete_capacity_reservation_groups(self):
        try:
            self.compute_client.capacity_reservation_groups.delete(self.resource_group, self.name)
        except Exception as exc:
            if self.get_by_name() is not None:
                self.fail("Error deleting Capacity Reservation Group {0} - {1}".format(self.name, str(exc)))

    def to_dict(self, body):
        if body is None:
            results = None
        elif isinstance(body, dict):
            results = dict(
                resource_group=self.resource_group,
                id=body.get('id'),
                name=body.get('name'),
                location=body.get('location'),
                zones=body.get('zones'),
                tags=body.get('tags'))
        else:
            results = dict(
                resource_group=self.resource_group,
                id=body.id,
                name=body.name,
                location=body.location,
                zones=body.zones,
                tags=body.tags)
        return results


def main():
    AzureRMCapacityReservationGroup()


if __name__ == '__main__':
    main()
