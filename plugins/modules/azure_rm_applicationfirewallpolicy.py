#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_applicationfirewallpolicy
version_added: "3.0.1"
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

extends_documentation_fragment:
    - azure.azcollection.azure
    - azure.azcollection.azure_tags

author:
    - xuzhang3 (@xuzhang3)
    - Fred-sun (@Fred-sun)
'''

EXAMPLES = '''
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
            descritption:
                - The application firewall policy tags.
            type: dict
            rekturned: always
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
                              'negation_condition': false, 'operator': 'IPMatch', 'transforms': []]
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
from ansible.module_utils.common.dict_transformations import _camel_to_snake

try:
    from azure.core.exceptions import ResourceNotFoundError
    from azure.mgmt.core.tools import parse_resource_id
except ImportError:
    # This is handled in azure_rm_common
    pass


policy_setting_spec = dict(
    state=dict(type='str', choices=['Disabled', 'Enabled']),
    mode=dict(type='str', choices=['Prevention', 'Detection']),
    request_body_check=dict(type='bool'),
    request_body_inspect_limit_in_kb=dict(type='int'),
    request_body_enforcement=dict(type='bool'),
    file_upload_enforcement=dict(type='bool'),
    file_upload_limit_in_mb=dict(type='int'),
    custom_block_response_status_code=dict(type='int'),
    custom_block_response_body=dict(type='str'),
    js_challenge_cookie_expiration_in_mins=dict(type='int'),
    log_scrubbing=dict(type='dict',
                       options=dict(
                           state=dict(type='str', choices=['Enabled', 'Disabled']),
                           scrubbing_rules=dict(type='list', elements='dict',
                               options=dict(
                                   match_variable=dict(type='str', choices=["RequestHeaderNames", "RequestCookieNames", "RequestArgNames", "RequestPostArgNames", "RequestJSONArgNames", "RequestIPAddress"]),
                                   selector_match_operator=dict(type='str', choices=["Equals", "EqualsAny"]),
                                   selector=dict(type='str'),
                                   state=dict(type='str', choices=['Enabled', 'Disabled']),
                               )
                           )
                       )
    )
    
)


custom_rule_spec = dict(
    priority=dict(type='int', required=True),
    rule_type=dict(type='str', required=True, choices=['MatchRule', 'RateLimitRule', 'Invalid']),
    match_conditions=dict(
        type='list',
        elements='dict',
        required=True,
        options=dict(
            match_variables=dict(
                type='list',
                required=True,
                options=dict(
                    variable_name=dict(
                        type='str',
                        choices=["RemoteAddr", "RequestMethod", "QueryString", "PostArgs", "RequestUri", "RequestHeaders", "RequestBody", "RequestCookies"]
                    ),
                    selector=dict(type='str')
                )
            ),
            operator=dict(
                type='str',
                required=True,
                choices=["IPMatch", "Equal", "Contains", "LessThan", "GreaterThan", "LessThanOrEqual", "GreaterThanOrEqual", "BeginsWith", "EndsWith", "Regex", "GeoMatch", "Any"]
            ),
            match_values=dict(
                type='list',
                elements='str',
                required=True
            ),
            transforms=dict(
                type='list',
                elements='str',
                choices=['Uppercase', 'Lowercase', 'Trim', 'UrlDecode', 'UrlEncode', 'RemoveNulls', 'HtmlEntityDecode']
            ),
            negation_conditon=dict(
                type='bool'
            ),
        )
    ),
    action=dict(type='str', choices=['Allow', 'Block', 'Log', 'JSChallenge']),
    name=dict(type='str'),
    state=dict(type='Disabled', 'Enabled'),
    rate_limit_duration=dict(type='str', choices=['OneMin', 'FiveMins']),
    rate_limit_threshold=dict(type='int'),
    group_by_user_session=dict(
        type='list',
        elements='dict',
        options=dict(
            group_by_variables=dict(
                type='list',
                elements='dict',
                options=dict(
                    variable_name=dict(
                        type='str',
                        choices=["ClientAddr", "GeoLocation", "None"]
                    )
                )
            )
        )
    )
)


managed_rule_spec = dict(
    exceptions=dict(
        match_variable=dict(type='str', choices=["RequestURI", "RemoteAddr", "RequestHeader"], required=True),
        value_match_operator=dict(type='str', required=True, choices=["Equals", "Contains", "StartsWith", "EndsWith", "IPMatch"]),
        values=dict(type='list', elements='str'),
        selector_match_operator=dict(type='list', choices=["Equals", "Contains", "StartsWith", "EndsWith"]),
        selector=dict(type='str'),
        exception_managed_rule_sets=dict(
            type='list',
            elements='dict',
            options=dict(
                rule_set_type=dict(type='str'),
                rule_set_version=dict(type='str'),
                rule_groups=dict(
                    type='list',
                    elements='dict',
                    options=dict(
                        rule_group_name=dict(type='str', required=True),
                        rules=dict(
                            type='list',
                            elements='dict',
                            options=dict(
                                rule_id=dict(type='str')
                            )
                        )
                    )
                )
            )
        )
    ),
    managed_rule_sets=dict(
        type='list',
        elements='dict',
        options=dict(
            rule_set_type=dict(type='str', required=True),
            rule_set_version=dict(type='str', required=True),
            rule_group_overrides=dict(
                type='list',
                elements='dict',
                options=dict(
                    rule_group_name=dict(type='str', required=True),
                    rules=dict(
                        type='list',
                        elements='dict',
                        options=dict(
                            rule_id=dict(type='str'),
                            state=dict(type='str', choices=['Enabled', 'Disabled']),
                            action=dict(type='str', choices=["AnomalyScoring", "Allow", "Block", "Log", "JSChallenge"]),
                            sensitivity=dict(type='str', choices=["None", "Low", "Medium", "High"])
                        )
                    )
                )
            )
        )
    ),
    exclusions=dict(
        match_variable=dict(
            type='str',
            required=True,
            choices=["RequestHeaderNames", "RequestCookieNames", "RequestArgNames", "RequestHeaderKeys", "RequestHeaderValues", "RequestCookieKeys", "RequestCookieValues", "RequestArgKeys", "RequestArgValues"])
        ),
        selector_match_operator=dict(
            type='str',
            required=True,
            choices=["Equals", "Contains", "StartsWith", "EndsWith", "EqualsAny"]
        ),
        selector=dict(
            type='str',
            required=True
        ),
        exclusion_managed_rule_sets=dict(
            type='list',
            elements='dict',
            options=dict(
                rule_set_type=dict(type='str', required=True),
                rule_set_version=dict(type='str', required=True),
                rule_groups=dict(
                    type='list',
                    elements='dict',
                    options=dict(
                        rule_group_name=dict(type='str', required=True),
                        rules=dict(
                            type='list',
                            elements='dict',
                            options=dict(
                                rule_id=dict(type='str')
                            )
                        )
                    )
                )
            )
        )
    )
)

class AzureRMApplicationFirewallPolicy(AzureRMModuleBase):

    def __init__(self):

        self.module_arg_spec = dict(
            name=dict(type='str', required=True),
            resource_group=dict(type='str', required=True),
            location=dict(type='str'),
            policy_settings=dict(type='dict', options=policy_setting_spec),
            custom_rules=dict(type='list', elements='dict', options=custom_rule_spec),
            managed_rules=dict(type='list', elements='dict', option=managed_rule_spec),
            state=dict(type='str', choices=['present', 'absent'], default='present')
        )

        self.results = dict(
            changed=False,
        )

        self.name = None
        self.resource_group = None
        self.state = None
        self.body = dict()

        super(AzureRMApplicationFirewallPolicy, self).__init__(self.module_arg_spec,
                                                            supports_check_mode=True,
                                                            supports_tags=True,
                                                            facts_module=True)

    def exec_module(self, **kwargs):
        for key in self.module_arg_spec + ['tags']:
            if hasattr(self, key):
                setattr(self, key, kwargs[key])
            elif kwargs[key] is not None:
                self.body[key] = kwargs[key]

        old_response = self.get()
        changed = False

        resource_group = self.get_resource_group(self.resource_group)
        if not self.body.get('location'):
            # Set default location
            self.body['location'] = resource_group.location

        if old_response is not None:
            if self.state == 'present':
                if not self.default_compare({}, self.body, old_response, '', dict(compare=[])):
                    changed = True
                    if not self.check_mode:
                        self.create_or_update(self.body)
            else:
                changed = True
                if not self.check_mode:
                    self.delete()
        else:
            if self.state == 'present':
                changed = True
                self.create_or_update(self.body)

        self.results["firewall_policy"] = self.get()
        self.results['changed'] = changed

        return self.results

    def get(self):
        response = None
        try:
            response = self.network_client.web_application_firewall_policies.get(resource_group_name=self.resource_group, policy_name=self.name)
        except ResourceNotFoundError:
            pass

        if response is not None:
            return self.format_response(response)

        return response

    def create_or_update(self):
        response = None
        try:
            response = self.network_client.web_application_firewall_policies.create_or_update(resource_group_name=self.resource_group,
                                                                                              policy_name=self.name
                                                                                              parameters=self.body)
        except Exception as exc:
            self.fail("Error creating or update the application firewall policy in resource groups {0}: {1} - {2}".format(self.resource_group, request_id, str(exc)))

        if response is not None:
            return self.format_response(response)
        else:
            return None

    def delete(self):
        try:
            self.network_client.web_application_firewall_policies.begin_delete(resource_group_name=self.resource_group,
                                                                               policy_name=self.name)
        except Exception as exc:
            self.fail("Error deleting the application firewall policy: {0}".format(str(exc)))

        return None

    def format_response(self, item):
        d = item.as_dict()
        id_dict = parse_resource_id(item.id)
        d['resource_group'] = id_dict.get('resource_group')

        return d


def main():
    AzureRMApplicationFirewallPolicy()


if __name__ == '__main__':
    main()
