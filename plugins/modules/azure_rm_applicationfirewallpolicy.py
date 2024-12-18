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
version_added: "3.1.0"
short_description: Manage the Application firewall policy instance
description:
    - Creating, Updating or Deleting the application firewall policy instance.
options:
    name:
        description:
            - The name of the application firewall policy's name.
        type: str
        required: true
    resource_group:
        description:
            - The name of the resource group.,
        type: str
        required: true
    location:
        description:
            - Valid Azure location. Defaults to the location of the resource group.
        type: str
    policy_settings:
        description:
            - The PolicySettings for policy.
        type: dict
        suboptions:
            state:
                description:
                    - The state of the policy.
                type: str
                choices:
                    - Disabled
                    - Enabled
            mode:
                description:
                    - The mode of the policy.
                type: str
                choices:
                    - Prevention
                    - Detection
            request_body_check:
                description:
                    - Whether to allow WAF to check request Body.
                type: bool
            request_body_inspect_limit_in_kb:
                description:
                    - Max inspection limit in KB for request body inspection for WAF.
                type: int
            request_body_enforcement:
                description:
                    - Whether allow WAF to enforce request body limits.
                type: bool
            max_request_body_size_in_kb:
                description:
                    - Maximum request body size in Kb for WAF.
                type: int
            file_upload_enforcement:
                description:
                    - Whether allow WAF to enforce file upload limits.
                type: bool
            file_upload_limit_in_mb:
                description:
                    - Maximum file upload size in Mb for WAF.
                type: int
            custom_block_response_status_code:
                description:
                    - If the action type is block, customer can override the response status code.
                type: int
            custom_block_response_body:
                description:
                    - If the action type is block, customer can override the response body.
                    - The body must be specified in base64 encoding.
                type: str
            js_challenge_cookie_expiration_in_mins:
                description:
                    - Web Application Firewall JavaScript Challenge Cookie Expiration time in minutes.
                type: int
            log_scrubbing:
                description:
                    - To scrub sensitive log fields.
                type: dict
                suboptions:
                    state:
                        description:
                            - State of the log scrubbing config.
                        type: str
                        choices:
                            - Enabled
                            - Disabled
                    scrubbing_rules:
                        description:
                            - The rules that are applied to the logs for scrubbing.
                        type: list
                        elements: dict
                        suboptions:
                            match_variable:
                                description:
                                    - The variable to be scrubbed from the logs.
                                type: str
                                required: true
                                choices:
                                    - RequestHeaderNames
                                    - RequestCookieNames
                                    - RequestArgNames
                                    - RequestPostArgNames
                                    - RequestJSONArgNames
                                    - RequestIPAddress
                            selector_match_operator:
                                description:
                                    - "When matchVariable is a collection, operate on the selector to specify which
                                       elements in the collection this rule applies to."
                                required: true
                                type: str
                                choices:
                                    - Equals
                                    - EqualsAny
                            selector:
                                description:
                                    - When matchVariable is a collection, operator used to specify which elements in the collection this rule applies to.
                                type: str
                            state:
                                description:
                                    - Defines the state of log scrubbing rule.
                                type: str
                                choices:
                                    - Enabled
                                    - Disabled
    custom_rules:
        description:
            - The custom rules inside the policy.
        type: list
        elements: dict
        suboptions:
            priority:
                description:
                    - Priority of the rule.
                    - Rules with a lower value will be evaluated before rules with a higher value.
                required: true
                type: int
            rule_type:
                description:
                    - The rule type.
                required: true
                type: str
                choices:
                    - MatchRule
                    - RateLimitRule
                    - Invalid
            match_conditions:
                description:
                    - List of match conditions.
                type: list
                elements: dict
                required: true
                suboptions:
                    match_variables:
                        description:
                            - List of match variables.
                        required: true
                        type: list
                        elements: dict
                        suboptions:
                            variable_name:
                                description:
                                    - Match Variable.
                                required: true
                                type: str
                                choices:
                                    - RemoteAddr
                                    - RequestMethod
                                    - QueryString
                                    - PostArgs
                                    - RequestUri
                                    - RequestHeaders
                                    - RequestBody
                                    - RequestCookies
                            selector:
                                description:
                                    - The selector of match variable.
                                type: str
                    operator:
                        description:
                            - The operator to be matched.
                        required: true
                        type: str
                        choices:
                            - IPMatch
                            - Equal
                            - Contains
                            - LessThan
                            - GreaterThan
                            - LessThanOrEqual
                            - GreaterThanOrEqual
                            - BeginsWith
                            - EndsWith
                            - Regex
                            - GeoMatch
                            - Any
                    negation_conditon:
                        description:
                            - Whether this is negate condition or not.
                        type: bool
                    match_values:
                        description:
                            - Match value.
                        required: true
                        type: list
                        elements: str
                    transforms:
                        description:
                            - List of transforms.
                        type: list
                        elements: str
                        choices:
                            - Uppercase
                            - Lowercase
                            - Trim
                            - UrlDecode
                            - UrlEncode
                            - RemoveNulls
                            - HtmlEntityDecode
            action:
                description:
                    - Type of Actions.
                type: str
                choices:
                    - Allow
                    - Block
                    - Log
                    - JSChallenge
            name:
                description:
                    - The name of the resource that is unique within a policy.
                    - This name can be used to access the resource.
                type: str
            state:
                description:
                    - Describes if the custom rule is in enabled or disabled state. Defaults to Enabled if not specified.
                type: str
                choices:
                    - Disabled
                    - Enabled
            rate_limit_duration:
                description:
                    - Duration over which Rate Limit policy will be applied.
                    - Applies only when ruleType is RateLimitRule.
                type: str
                choices:
                    - OneMin
                    - FiveMins
            rate_limit_threshold:
                description:
                    - Rate Limit threshold to apply in case ruleType is RateLimitRule.
                    - Must be greater than or equal to 1.
                type: int
            group_by_user_session:
                description:
                    - List of user session identifier group by clauses.
                type: list
                elements: dict
                suboptions:
                    group_by_variables:
                        description:
                            - List of group by clause variables.
                        type: list
                        elements: dict
                        suboptions:
                            variable_name:
                                description:
                                    - User Session clause variable.
                                type: str
                                choices:
                                    - ClientAddr
                                    - GeoLocation
                                    - None
    managed_rules:
        description:
            - Describes the managedRules structure.
        type: dict
        suboptions:
            exclusions:
                description:
                    - The Exclusions that are applied on the policy.
                type: list
                elements: dict
                suboptions:
                    match_variable:
                        description:
                            - The variable to be excluded.
                        required: true
                        type: str
                        choices:
                            - RequestHeaderNames
                            - RequestCookieNames
                            - RequestArgNames
                            - RequestHeaderKeys
                            - RequestHeaderValues
                            - RequestCookieKeys
                            - RequestCookieValues
                            - RequestArgKeys
                            - RequestArgValues
                    selector_match_operator:
                        description:
                            - When matchVariable is a collection, operate on the selector to specify which elements in the collection this exclusion applies to.
                        required: true
                        type: str
                        choices:
                            - Equals
                            - Contains
                            - StartsWith
                            - EndsWith
                            - EqualsAny
                    selector:
                        description:
                            - When matchVariable is a collection, operator used to specify which elements in the collection this exclusion applies to.
                        required: true
                        type: str
                    exclusion_managed_rule_sets:
                        description:
                            - The managed rule sets that are associated with the exclusion.
                        type: list
                        elements: dict
                        suboptions:
                            rule_set_type:
                                description:
                                    - Defines the rule set type to use.
                                type: str
                                required: true
                            rule_set_version:
                                description:
                                    - Defines the version of the rule set to use.
                                type: str
                                required: true
                            rule_groups:
                                description:
                                    - Defines the rule groups to apply to the rule set.
                                type: list
                                elements: dict
                                suboptions:
                                    rule_group_name:
                                        description:
                                            - The managed rule group for exclusion.
                                        type: str
                                        required: true
                                    rules:
                                        description:
                                            - List of rules that will be excluded. If none specified, all rules in the group will be excluded.
                                        type: list
                                        elements: dict
                                        suboptions:
                                            rule_id:
                                                description:
                                                    - Identifier for the managed rule.
                                                type: str
            managed_rule_sets:
                description:
                    - The managed rule sets that are associated with the policy.
                required: true
                type: list
                elements: dict
                suboptions:
                    rule_set_type:
                        description:
                            - Defines the rule set type to use.
                        type: str
                        required: true
                    rule_set_version:
                        description:
                            - Defines the version of the rule set to use.
                        required: true
                        type: str
                    rule_group_overrides:
                        description:
                            - Defines the rule group overrides to apply to the rule set.
                        type: list
                        elements: dict
                        suboptions:
                            rule_group_name:
                                description:
                                    - The managed rule group to override.
                                required: true
                                type: str
                            rules:
                                description:
                                    - List of rules that will be disabled.
                                    - If none specified, all rules in the group will be disabled.
                                type: list
                                elements: dict
                                suboptions:
                                    rule_id:
                                        description:
                                            - Identifier for the managed rule.
                                        required: true
                                        type: str
                                    state:
                                        description:
                                            - The state of the managed rule. Defaults to C(Disabled) if not specified.
                                        type: str
                                        choices:
                                            - Enabled
                                            - Disabled
                                    action:
                                        description:
                                            - Describes the override action to be applied when rule matches.
                                        type: str
                                        choices:
                                            - AnomalyScoring
                                            - Allow
                                            - Block
                                            - Log
                                            - JSChallenge
                                    sensitivity:
                                        description:
                                            - Describes the override sensitivity to be applied when rule matches.
                                        type: str
                                        choices:
                                            - None
                                            - Low
                                            - Medium
                                            - High
    state:
        description:
            - Assert the state of the firewall policy.
            - Use C(present) to create or update a and C(absent) to delete.
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
- name: Create a new application firewall policy
  azure_rm_applicationfirewallpolicy:
    resource_group: "{{ resource_group }}"
    name: "new{{ rpfx }}02"
    location: australiasoutheast
    policy_settings:
      file_upload_enforcement: true
      file_upload_limit_in_mb: 88
      js_challenge_cookie_expiration_in_mins: 30
      max_request_body_size_in_kb: 128
      mode: Detection
      request_body_check: true
      request_body_enforcement: true
      request_body_inspect_limit_in_kb: 128
      state: Enabled
      custom_block_response_status_code: 200
      custom_block_response_body: Fredtest
      log_scrubbing:
        state: Enabled
        scrubbing_rules:
          - match_variable: RequestHeaderNames
            selector_match_operator: Equals
            selector: '*'
            state: Enabled
    custom_rules:
      - action: Block
        match_conditions:
          - match_values:
              - 10.1.0.0/24
              - 10.2.0.0/24
            match_variables:
              - variable_name: RemoteAddr
            negation_conditon: true
            operator: IPMatch
            transforms:
              - Uppercase
              - Lowercase
        name: ruledefine01
        priority: 21
        rule_type: MatchRule
        state: Enabled
      - action: Block
        group_by_user_session:
          - group_by_variables:
              - variable_name: ClientAddr
        match_conditions:
          - match_values:
              - 10.1.0.0/24
              - 10.2.0.0/24
            match_variables:
              - variable_name: RemoteAddr
            negation_conditon: false
            operator: IPMatch
        name: ruledefine02
        priority: 22
        rule_type: RateLimitRule
        rate_limit_threshold: 100
        rate_limit_duration: OneMin
        state: Enabled
    managed_rules:
      exclusions:
        - match_variable: RequestHeaderNames
          selector_match_operator: Equals
          selector: IPMatch
          exclusion_managed_rule_sets:
            - rule_set_type: Microsoft_DefaultRuleSet
              rule_set_version: 2.1
      managed_rule_sets:
        - rule_set_type: Microsoft_BotManagerRuleSet
          rule_set_version: 1.0
        - rule_set_type: Microsoft_DefaultRuleSet
          rule_set_version: 2.1

- name: Delete the application firewall policy
  azure_rm_applicationfirewallpolicy:
    resource_group: "{{ resource_group }}"
    name: firewallpolicy
    state: absent
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

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common_ext import AzureRMModuleBaseExt

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
    max_request_body_size_in_kb=dict(type='int'),
    file_upload_enforcement=dict(type='bool'),
    file_upload_limit_in_mb=dict(type='int'),
    custom_block_response_status_code=dict(type='int'),
    custom_block_response_body=dict(type='str'),
    js_challenge_cookie_expiration_in_mins=dict(type='int'),
    log_scrubbing=dict(
        type='dict',
        options=dict(
            state=dict(type='str', choices=['Enabled', 'Disabled']),
            scrubbing_rules=dict(
                type='list',
                elements='dict',
                options=dict(
                    match_variable=dict(
                        type='str',
                        required=True,
                        choices=["RequestHeaderNames", "RequestCookieNames", "RequestArgNames",
                                 "RequestPostArgNames", "RequestJSONArgNames", "RequestIPAddress"]
                    ),
                    selector_match_operator=dict(type='str', required=True, choices=["Equals", "EqualsAny"]),
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
                elements='dict',
                options=dict(
                    variable_name=dict(
                        type='str',
                        required=True,
                        choices=["RemoteAddr", "RequestMethod", "QueryString", "PostArgs", "RequestUri", "RequestHeaders", "RequestBody", "RequestCookies"]
                    ),
                    selector=dict(type='str')
                )
            ),
            operator=dict(
                type='str',
                required=True,
                choices=["IPMatch", "Equal", "Contains", "LessThan", "GreaterThan", "LessThanOrEqual",
                         "GreaterThanOrEqual", "BeginsWith", "EndsWith", "Regex", "GeoMatch", "Any"]
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
    state=dict(type='str', choices=['Disabled', 'Enabled']),
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
    managed_rule_sets=dict(
        type='list',
        elements='dict',
        required=True,
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
                            rule_id=dict(type='str', required=True),
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
        type='list',
        elements='dict',
        options=dict(
            match_variable=dict(
                type='str',
                required=True,
                choices=["RequestHeaderNames", "RequestCookieNames", "RequestArgNames", "RequestHeaderKeys",
                         "RequestHeaderValues", "RequestCookieKeys", "RequestCookieValues", "RequestArgKeys", "RequestArgValues"]
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
)


class AzureRMApplicationFirewallPolicy(AzureRMModuleBaseExt):

    def __init__(self):

        self.module_arg_spec = dict(
            name=dict(type='str', required=True),
            resource_group=dict(type='str', required=True),
            location=dict(type='str'),
            policy_settings=dict(type='dict', options=policy_setting_spec),
            custom_rules=dict(type='list', elements='dict', options=custom_rule_spec),
            managed_rules=dict(type='dict', options=managed_rule_spec),
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
        for key in list(self.module_arg_spec.keys()) + ['tags']:
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
                if not self.check_mode:
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

    def create_or_update(self, body):
        response = None
        try:
            response = self.network_client.web_application_firewall_policies.create_or_update(resource_group_name=self.resource_group,
                                                                                              policy_name=self.name,
                                                                                              parameters=body)
        except Exception as exc:
            self.fail("Error creating or update the application firewall policy in resource groups {0}: {1}".format(self.resource_group, str(exc)))

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
