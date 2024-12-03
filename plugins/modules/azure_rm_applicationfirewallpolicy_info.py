#!/usr/bin/python
#
# Copyright (c) 2021 Ross Bender (@l3ender)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_applicationfirewallpolicy_info
version_added: "1.10.0"
short_description: Retrieve Application Gateway instance facts
description:
    - Get facts for a Application Gateway instance.
options:
    name:
        description:
            - Only show results for a specific application gateway.
        type: str
    resource_group:
        description:
            - Limit results by resource group.
        type: str

extends_documentation_fragment:
    - azure.azcollection.azure

author:
    - Ross Bender (@l3ender)
'''

EXAMPLES = '''
- name: Get facts for web application firewall policy by name.
  azure_rm_applicationfirewallpolicy_info:
    name: MyAppgw
    resource_group: MyResourceGroup

- name: Get facts for web application firewall policy in resource group.
  azure_rm_applicationfirewallpolicy_info:
    resource_group: MyResourceGroup

- name: Get facts for all web application firewall policy.
  azure_rm_applicationfirewallpolicy_info:
'''

RETURN = '''
gateways:
    description:
        - A list of dictionaries containing facts for an application gateway.
    returned: always
    type: list
    elements: dict
    contains:
        id:
            description:
                - Application gateway resource ID.
            returned: always
            type: str
            sample: /subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/myResourceGroup/providers/Microsoft.Network/applicationGateways/myAppGw
        name:
            description:
                - Name of application gateway.
            returned: always
            type: str
            sample: myAppGw
        resource_group:
            description:
                - Name of resource group.
            returned: always
            type: str
            sample: myResourceGroup
        location:
            description:
                - Location of application gateway.
            returned: always
            type: str
            sample: centralus
        operational_state:
            description:
                - Operating state of application gateway.
            returned: always
            type: str
            sample: Running
        provisioning_state:
            description:
                - Provisioning state of application gateway.
            returned: always
            type: str
            sample: Succeeded
        ssl_policy:
            description:
                - SSL policy of the application gateway.
            returned: always
            type: complex
            version_added: "1.11.0"
            contains:
                policy_type:
                    description:
                        - The type of SSL policy.
                    returned: always
                    type: str
                    sample: predefined
                policy_name:
                    description:
                        - The name of the SSL policy.
                    returned: always
                    type: str
                    sample: ssl_policy20170401_s
'''

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase
from ansible.module_utils.common.dict_transformations import _camel_to_snake

try:
    from azure.core.exceptions import ResourceNotFoundError
    from azure.mgmt.core.tools import parse_resource_id
except ImportError:
    # This is handled in azure_rm_common
    pass


class AzureRMApplicationFirewallPolicyInfo(AzureRMModuleBase):

    def __init__(self):

        self.module_arg_spec = dict(
            name=dict(type='str'),
            resource_group=dict(type='str'),
        )

        self.results = dict(
            changed=False,
        )

        self.name = None
        self.resource_group = None
        required_if = [('name', '*', ['resource_group'])]

        super(AzureRMApplicationFirewallPolicyInfo, self).__init__(self.module_arg_spec,
                                                            supports_check_mode=True,
                                                            supports_tags=False,
                                                            required_if=required_if,
                                                            facts_module=True)

    def exec_module(self, **kwargs):
        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        if self.name is not None:
            self.results["firewall_policy"] = self.get()
        elif self.resource_group is not None:
            self.results["firewall_policy"] = self.list_by_rg()
        else:
            self.results["firewall_policy"] = self.list_all()

        return self.results

    def get(self):
        response = None
        results = []
        try:
            response = self.network_client.web_application_firewall_policies.get(resource_group_name=self.resource_group, policy_name=self.name)
        except ResourceNotFoundError:
            pass

        if response is not None:
            results.append(self.format_response(response))

        return results

    def list_by_rg(self):
        response = None
        results = []
        try:
            response = self.network_client.web_application_firewall_policies.list(resource_group_name=self.resource_group)
        except Exception as exc:
            request_id = exc.request_id if exc.request_id else ''
            self.fail("Error listing web application firewall policy in resource groups {0}: {1} - {2}".format(self.resource_group, request_id, str(exc)))

        for item in response:
            results.append(self.format_response(item))

        return results

    def list_all(self):
        response = None
        results = []
        try:
            response = self.network_client.web_application_firewall_policies.list_all()
        except Exception as exc:
            self.fail("Error listing all web application firewall policy: {0}".format(str(exc)))

        for item in response:
            results.append(self.format_response(item))

        return results

    def format_response(self, item):
        id_dict = parse_resource_id(item.id)
        d = dict(
            id=item.id,
            resource_group=id_dict.get('resource_group'),
            name=item.name,
            type=item.type,
            location=item.location,
            tags=item.tags,
            etag=item.etag,
            provisioning_state=item.provisioning_state,
            policy_settings=dict(),
            custom_rules=dict(),
            managed_rules=dict()
        )
        if item.managed_rules is not None:
            if item.managed_rules.exceptions is not None:
                d['managed_rules']['exceptions'] = [value.as_dict() for value in item.managed_rules.exceptions]
            else:
                d['managed_rules']['exceptions'] = None
            if item.managed_rules.exclusions is not None:
                d['managed_rules']['exclusions'] = [value.as_dict() for value in item.managed_rules.exclusions]
            else:
                d['managed_rules']['exclusions'] = None
            if item.managed_rules.managed_rule_sets is not None:
                d['managed_rules']['managed_rule_sets'] = [value.as_dict() for value in item.managed_rules.managed_rule_sets]
            else:
                d['managed_rules']['managed_rule_sets'] = None
        else:
            d['managed_rules'] = None
        if item.policy_settings is not None:
            d['policy_settings']['state'] = item.policy_settings.state
            d['policy_settings']['mode'] = item.policy_settings.mode
            d['policy_settings']['request_body_check'] = item.policy_settings.request_body_check
            d['policy_settings']['request_body_inspect_limit_in_kb'] = item.policy_settings.request_body_inspect_limit_in_kb
            d['policy_settings']['request_body_enforcement'] = item.policy_settings.request_body_enforcement
            d['policy_settings']['max_request_body_size_in_kb'] = item.policy_settings.max_request_body_size_in_kb
            d['policy_settings']['file_upload_enforcement'] = item.policy_settings.file_upload_enforcement
            d['policy_settings']['file_upload_limit_in_mb'] = item.policy_settings.file_upload_limit_in_mb
            d['policy_settings']['custom_block_response_status_code'] = item.policy_settings.custom_block_response_status_code
            d['policy_settings']['js_challenge_cookie_expiration_in_mins'] = item.policy_settings.js_challenge_cookie_expiration_in_mins
            if item.policy_settings.log_scrubbing is not None:
                d['policy_settings'] = dict
                d['policy_settings']['log_scrubbing']['match_variable'] = item.policy_settings.log_scrubbing.match_variable
                d['policy_settings']['log_scrubbing']['selector_match_operator'] = item.policy_settings.log_scrubbing.selector_match_operator
                d['policy_settings']['log_scrubbing']['selector'] = item.policy_settings.log_scrubbing.selector
                d['policy_settings']['log_scrubbing']['state'] = item.policy_settings.log_scrubbing.state
            else:
                d['policy_settings']['log_scrubbing'] = None
        else:
            d['policy_settings'] = None
        if item.custom_rules is not None:
            d['custom_rules']['priority'] = item.custom_rules.priority
            d['custom_rules']['rule_type'] = item.custom_rules.rule_type
            d['custom_rules']['priority'] = item.custom_rules.action
            d['custom_rules']['name'] = item.custom_rules.name
            d['custom_rules']['state'] = item.custom_rules.state
            d['custom_rules']['rate_limit_duration'] = item.custom_rules.rate_limit_duration
            d['custom_rules']['rate_limit_threshold'] = item.custom_rules.rate_limit_threshold
            if item.custom_rules.group_by_user_session is not None:
                d['custom_rules']['group_by_user_session'] = [value.as_dict() for value in item.custom_rules.group_by_user_session]
            else:
                d['custom_rules']['group_by_user_session'] = None
            if item.custom_rules.match_conditions is not None:
                d['custom_rules']['match_conditions'] = item.custom_rules.match_conditions.as_dict()
            else:
                d['custom_rules']['match_conditions'] = None
        else:
            d['custom_rules'] = None

        return d


def main():
    AzureRMApplicationFirewallPolicyInfo()


if __name__ == '__main__':
    main()
