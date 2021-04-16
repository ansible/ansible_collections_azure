#!/usr/bin/python
#
# Copyright (c) 2020 Praveen Ghuge (@praveenghuge), Karl Dasan (@karldas30), Sakar Mehra (@sakar97)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase

__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_notificationhub_info
short_description: Get Azure Notification Hub
description:
    - Get facts of Azure Notification Hub

options:
    resource_group:
        description:
            - The name of the resource group.
        required: True
    name:
        description:
            - The name of the Notification hub.
        required: True


extends_documentation_fragment:
- azure.azcollection.azure


author:
    - Praveen Ghuge (@praveenghuge)
'''


EXAMPLES = '''
  - name: Get facts of specific notification hub
    community.azure.azure_rm_notificationhub_info:
      resource_group: myResourceGroup
      name: myNotificationHub

'''

RETURN = '''
'''

try:
    from msrestazure.azure_exceptions import CloudError
except ImportError:
    # This is handled in azure_rm_common
    pass


class AzureNotificationHubInfo(AzureRMModuleBase):
    def __init__(self):


        self.module_arg_spec = dict(
            resource_group=dict(
                type='str',
                required=True
            ),
            namespace_name=dict(
                type='str',
            ),
            name=dict(
                type='str',
            )
        )
        # store the results of the module operation
        self.results = dict(
            changed=False)
        self.resource_group = None
        self.namespace_name = None
        self.name = None
        self.tags = None

        super(AzureNotificationHubInfo, self).__init__(
            self.module_arg_spec, supports_tags=False)

    def exec_module(self, **kwargs):

        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])
        
        if self.name is None and self.namespace_name is None:
            results = self.list_all_namespace()
            self.results['namespaces'] = [
                self.namespace_to_dict(x) for x in results]
        elif self.name and self.namespace_name:
            results = self.get_notification_hub()
            self.results['notificationhub'] = [
                self.notification_hub_to_dict(x) for x in results]
        elif self.namespace_name:
            results = self.get_namespace()
            self.results['namespace'] = [
                self.namespace_to_dict(x) for x in results]
        
        return self.results

    def get_namespace(self):
        response = None
        results = []
        try:
            response = self.notification_hub_client.namespaces.get(
                self.resource_group, self.namespace_name)
            self.log("Response : {0}".format(response))

        except CloudError as e:
            self.fail('Could not get info for namespace. {0}').format(
                str(e))

        if response and self.has_tags(response.tags, self.tags):
            results = [response]
        return results

    def get_notification_hub(self):
        response = None
        results = []
        try:
            response = self.notification_hub_client.notification_hubs.get(
                self.resource_group, self.namespace_name, self.name)
            self.log("Response : {0}".format(response))

        except CloudError as e:
            self.fail('Could not get info for notification hub. {0}').format(
                str(e))

        if response and self.has_tags(response.tags, self.tags):
            results = [response]
        return results



    def list_all_namespace(self):
        self.log('List items for resource group')
        try:
            response = self.notification_hub_client.namespaces.list(
                self.resource_group)

        except CloudError as exc:
            self.fail(
                "Failed to list for resource group {0} - {1}".format(self.resource_group, str(exc)))

        results = []
        for item in response:
            if self.has_tags(item.tags, self.tags):
                results.append(item)
        return results

    def namespace_to_dict(self, item):
        # turn notification hub object into a dictionary (serialization)
        notification_hub = item.as_dict()
        result = dict(
            additional_properties=notification_hub.get(
                'additional_properties', {}),
            name=notification_hub.get('name', None),
            type=notification_hub.get('type', None),
            location=notification_hub.get(
                'location', '').replace(' ', '').lower(),
            sku=notification_hub.get("sku").get("name"),
            tags=notification_hub.get('tags', None),
            provisioning_state=notification_hub.get(
                'provisioning_state', None),
            region=notification_hub.get('region', None),
            metric_id=notification_hub.get('metric_id', None),
            service_bus_endpoint=notification_hub.get(
                'service_bus_endpoint', None),
            scale_unit=notification_hub.get('scale_unit', None),
            enabled=notification_hub.get('enabled', None),
            critical=notification_hub.get('critical', None),
            data_center=notification_hub.get('data_center', None),
            namespace_type=notification_hub.get('namespace_type', None)
        )
        return result

    def notification_hub_to_dict(self, item):
        # turn notification hub object into a dictionary (serialization)
        notification_hub = item.as_dict()
        result = dict(
            additional_properties=notification_hub.get(
                'additional_properties', {}),
            name=notification_hub.get('name', None),
            type=notification_hub.get('type', None),
            location=notification_hub.get(
                'location', '').replace(' ', '').lower(),
            tags=notification_hub.get('tags', None),
            name_properties_name=notification_hub.get(
                'name_properties_name', None),
            registration_ttl=notification_hub.get('registration_ttl', None),
            authorization_rules=notification_hub.get('authorization_rules', None),
            apns_credential=notification_hub.get(
                'apns_credential', None),
            wns_credential=notification_hub.get('wns_credential', None),
            gcm_credential=notification_hub.get('gcm_credential', None),
            mpns_credential=notification_hub.get('mpns_credential', None),
            adm_credential=notification_hub.get('adm_credential', None),
            baidu_credential=notification_hub.get('baidu_credential', None)
        )
        return result


def main():
    AzureNotificationHubInfo()


if __name__ == '__main__':
    main()
