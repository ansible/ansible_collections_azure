#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_applicationfirewallpolicy_info
version_added: "3.1.0"
short_description: Retrieve Application firewall policy instance facts
description:
    - Get or list the application firewall facts.
options:
    name:
        description:
            - The name of the application firewall policy's name.
        type: str
    resource_group:
        description:
            - The name of the resource group.,
        type: str
    tags:
        description:
            - The application firewall policy's tags key.
            - For filter the resource.
        type: list
        elements: str

extends_documentation_fragment:
    - azure.azcollection.azure

author:
    - xuzhang3 (@xuzhang3)
    - Fred-sun (@Fred-sun)
'''

EXAMPLES = '''
- name: Get the application firewall policy by name
  azure_rm_applicationfirewallpolicy_info:
    name: Myfirewallpolicy01
    resource_group: MyResourceGroup

- name: List the application firewall policy by resource group
  azure_rm_applicationfirewallpolicy_info:
    resource_group: MyResourceGroup

- name: List all application firewall policy
  azure_rm_applicationfirewallpolicy_info:
'''

RETURN = '''
firewall_policy:
    description:
        - A list of the application firewall policy facts
    returned: always
    type: complex
    contains:
        id:
            description:
                - The application firewall policy's ID.
            returned: always
            type: str
            sample: "/subscriptions/xxx-xxx/resourceGroups/v-xisuRG/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/firewallpolicy"
        name:
            description:
                - Name of application firewall policy.
            returned: always
            type: str
            sample: firewallpolicy
        resource_group:
            description:
                - Name of resource group.
            returned: always
            type: str
            sample: myResourceGroup
        location:
            description:
                - Location of application firewall policy.
            returned: always
            type: str
            sample: eastus
        provisioning_state:
            description:
                - Provisioning state of application firewall policy.
            returned: always
            type: str
            sample: Succeeded
        type:
            description:
                - The type of the application firewall policy.
            returned: always
            type: str
            sample: Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies
        tags:
            description:
                - The application firewall policy tags.
            type: dict
            returned: always
            sample: {"key1": "value1"}
        custom_rules:
            description:
                - The custom rules inside the policy.
            type: complex
            returned: when used
            contains:
                action:
                    description:
                        - The name of the resource that is unique within a policy.
                        - This name can be used to access the resource.
                    type: str
                    returned: always
                    sample: Block
                match_conditions:
                    description:
                        - List of match conditions.
                    type: list
                    returned: always
                    sample: [{'match_values': ['10.1.0.4'], 'match_variables': [{'variable_name': 'RemoteAddr'}],
                              'negation_condition': false, 'operator': 'IPMatch', 'transforms': []}]
                name:
                    description:
                        - The name of the resource that is unique within a policy.
                        - This name can be used to access the resource.
                    type: str
                    returned: always
                    sample: testrule01
                priority:
                    description:
                        - Priority of the rule.
                        - Rules with a lower value will be evaluated before rules with a higher value.
                    type: int
                    returned: always
                    sample: 33
                rule_type:
                    description:
                        - The rule type.
                    type: str
                    returned: always
                    sample: MatchRule
                state:
                    description:
                        - Describes if the custom rule is in enabled or disabled state.
                    type: str
                    returned: always
                    sample: Enabled
        managed_rules:
            description:
                - Describes the managedRules structure.
            type: complex
            returned: when used
            contains:
                exclusions:
                    description:
                        - The exceptions that are applied on the policy.
                    type: list
                    returned: always
                    sample: []
                managed_rule_sets:
                    description:
                        - The managed rule sets that are associated with the policy.
                    type: list
                    returned: always
                    sample: [{"rule_group_overrides": [],
                              "rule_set_type": "Microsoft_DefaultRuleSet",
                              "rule_set_version": "2.1"
                             }]
        policy_settings:
            description:
                - The PolicySettings for policy.
            type: complex
            returned: when used
            contains:
                file_upload_enforcement:
                    description:
                        - Whether allow WAF to enforce file upload limits.
                    type: bool
                    returned: always
                    sample: true
                file_upload_limit_in_mb:
                    description:
                        - Maximum file upload size in Mb for WAF.
                    type: int
                    returned: always
                    sample: 100
                js_challenge_cookie_expiration_in_mins:
                    description:
                        - Web Application Firewall JavaScript Challenge Cookie Expiration time in minutes.
                    type: int
                    returned: always
                    sample: 30
                max_request_body_size_in_kb:
                    description:
                        - Maximum request body size in Kb for WAF.
                    type: int
                    returned: always
                    sample: 128
                mode:
                    description:
                        - The mode of the policy.
                    type: str
                    returned: always
                    sample: Detection
                request_body_check:
                    description:
                        - Whether to allow WAF to check request Body.
                    type: bool
                    returned: always
                    sample: false
                request_body_enforcement:
                    description:
                        - Whether allow WAF to enforce request body limits.
                    type: bool
                    returned: always
                    sample: false
                state:
                    description:
                        - The state of the policy.
                    type: str
                    returned: always
                    sample: Enabled
'''

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase

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
            tags=dict(type='list', elements='str')
        )

        self.results = dict(
            changed=False,
        )

        self.name = None
        self.resource_group = None
        self.tags = None

        super(AzureRMApplicationFirewallPolicyInfo, self).__init__(self.module_arg_spec,
                                                                   supports_check_mode=True,
                                                                   supports_tags=False,
                                                                   facts_module=True)

    def exec_module(self, **kwargs):
        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        if self.name is not None:
            if self.resource_group is not None:
                response = self.get()
            else:
                self.fail("Missing resource_group when configed name")
        elif self.resource_group is not None:
            response = self.list_by_rg()
        else:
            response = self.list_all()
        self.results["firewall_policy"] = [item for item in response if self.has_tags(item.get('tags'), self.tags)]
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
            self.fail("Error listing web application firewall policy in resource groups {0}: {1}".format(self.resource_group, str(exc)))

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
        d = item.as_dict()
        id_dict = parse_resource_id(item.id)
        d['resource_group'] = id_dict.get('resource_group')

        return d


def main():
    AzureRMApplicationFirewallPolicyInfo()


if __name__ == '__main__':
    main()
