#!/usr/bin/python
#
# Copyright (c) 2016 Matt Davis, <mdavis@ansible.com>
#                    Chris Houseknecht, <house@redhat.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_storageaccount
version_added: "0.1.0"
short_description: Manage Azure storage accounts
description:
    - Create, update or delete a storage account.
options:
    resource_group:
        description:
            - Name of the resource group to use.
        required: true
        type: str
        aliases:
            - resource_group_name
    name:
        description:
            - Name of the storage account to update or create.
        type: str
        required: true
    state:
        description:
            - State of the storage account. Use C(present) to create or update a storage account and use C(absent) to delete an account.
            - C(failover) is used to failover the storage account to its secondary. This process can take up to a hour.
        default: present
        type: str
        choices:
            - absent
            - present
            - failover
    location:
        description:
            - Valid Azure location. Defaults to location of the resource group.
        type: str
    account_type:
        description:
            - Type of storage account. Required when creating a storage account.
            - C(Standard_ZRS) and C(Premium_LRS) accounts cannot be changed to other account types.
            - Other account types cannot be changed to C(Standard_ZRS) or C(Premium_LRS).
        type: str
        choices:
            - Premium_LRS
            - Standard_GRS
            - Standard_LRS
            - Standard_RAGRS
            - Standard_ZRS
            - Premium_ZRS
            - Standard_RAGZRS
            - Standard_GZRS
        aliases:
            - type
    custom_domain:
        description:
            - User domain assigned to the storage account.
            - Must be a dictionary with I(name) and I(use_sub_domain) keys where I(name) is the CNAME source.
            - Only one custom domain is supported per storage account at this time.
            - To clear the existing custom domain, use an empty string for the custom domain name property.
            - Can be added to an existing storage account. Will be ignored during storage account creation.
        type: dict
        aliases:
            - custom_dns_domain_suffix
    kind:
        description:
            - The kind of storage.
            - The C(FileStorage) and (BlockBlobStorage) only used when I(account_type=Premium_LRS) or I(account_type=Premium_ZRS).
        default: 'Storage'
        type: str
        choices:
            - Storage
            - StorageV2
            - BlobStorage
            - BlockBlobStorage
            - FileStorage
    is_hns_enabled:
        description:
            - Account HierarchicalNamespace enabled if sets to true.
            - When I(is_hns_enabled=True), I(kind) cannot be C(Storage).
        type: bool
    enable_nfs_v3:
        description:
            - NFS 3.0 protocol.
        type: bool
    access_tier:
        description:
            - The access tier for this storage account. Required when I(kind=BlobStorage).
        type: str
        choices:
            - Hot
            - Cool
    force_delete_nonempty:
        description:
            - Attempt deletion if resource already exists and cannot be updated.
        type: bool
        default: False
        aliases:
            - force
    https_only:
        description:
            - Allows https traffic only to storage service when set to C(True).
            - If omitted, new account creation will default to True, while existing accounts will not be change.
        type: bool
    minimum_tls_version:
        description:
            - The minimum required version of Transport Layer Security (TLS) for requests to a storage account.
            - If omitted, new account creation will default to null which is currently interpreted to TLS1_0. Existing accounts will not be modified.
        type: str
        choices:
            - TLS1_0
            - TLS1_1
            - TLS1_2
        version_added: "1.0.0"
    public_network_access:
        description:
            - Allow or disallow public network access to Storage Account.
        type: str
        choices:
            - Enabled
            - Disabled
        version_added: "1.12.0"
    allow_blob_public_access:
        description:
            - Allows blob containers in account to be set for anonymous public access.
            - If set to false, no containers in this account will be able to allow anonymous public access.
            - If omitted, new account creation will default to null which is currently interpreted to True. Existing accounts will not be modified.
        type: bool
        version_added: "1.1.0"
    network_acls:
        description:
            - Manages the Firewall and virtual networks settings of the storage account.
        type: dict
        suboptions:
            default_action:
                description:
                    - Default firewall traffic rule.
                    - If I(default_action=Allow) no other settings have effect.
                type: str
                choices:
                    - Allow
                    - Deny
                default: Allow
            bypass:
                description:
                    - When I(default_action=Deny) this controls which Azure components can still reach the Storage Account.
                    - The list is comma separated.
                    - It can be any combination of the example C(AzureServices), C(Logging), C(Metrics).
                    - If no Azure components are allowed, explicitly set I(bypass="").
                default: AzureServices
                type: str
            virtual_network_rules:
                description:
                    - A list of subnets and their actions.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - The complete path to the subnet.
                        type: str
                    action:
                        description:
                            - The only logical I(action=Allow) because this setting is only accessible when I(default_action=Deny).
                        default: 'Allow'
                        type: str
            ip_rules:
                description:
                    - A list of IP addresses or ranges in CIDR format.
                type: list
                elements: dict
                suboptions:
                    value:
                        description:
                            - The IP address or range.
                        type: str
                    action:
                        description:
                            - The only logical I(action=Allow) because this setting is only accessible when I(default_action=Deny).
                        default: 'Allow'
                        type: str
    blob_cors:
        description:
            - Specifies CORS rules for the Blob service.
            - You can include up to five CorsRule elements in the request.
            - If no blob_cors elements are included in the argument list, nothing about CORS will be changed.
            - If you want to delete all CORS rules and disable CORS for the Blob service, explicitly set I(blob_cors=[]).
        type: list
        elements: dict
        suboptions:
            allowed_origins:
                description:
                    - A list of origin domains that will be allowed via CORS, or "*" to allow all domains.
                type: list
                elements: str
                required: true
            allowed_methods:
                description:
                    - A list of HTTP methods that are allowed to be executed by the origin.
                type: list
                elements: str
                required: true
            max_age_in_seconds:
                description:
                    - The number of seconds that the client/browser should cache a preflight response.
                type: int
                required: true
            exposed_headers:
                description:
                    - A list of response headers to expose to CORS clients.
                type: list
                elements: str
                required: true
            allowed_headers:
                description:
                    - A list of headers allowed to be part of the cross-origin request.
                type: list
                elements: str
                required: true
    static_website:
        description:
            - Manage static website configuration for the storage account.
        type: dict
        version_added: "1.13.0"
        suboptions:
            enabled:
                description:
                    - Indicates whether this account is hosting a static website.
                type: bool
                default: false
            index_document:
                description:
                    - The default name of the index page under each directory.
                type: str
            error_document404_path:
                description:
                    - The absolute path of the custom 404 page.
                type: str
    large_file_shares_state:
        description:
            - Allow large file shares if sets to Enabled.
        type: str
        choices:
            - Enabled
            - Disabled
    encryption:
        description:
            - The encryption settings on the storage account.
        type: dict
        suboptions:
            services:
                description:
                    -  List of services which support encryption.
                type: dict
                suboptions:
                    table:
                        description:
                            - The encryption function of the table storage service.
                        type: dict
                        suboptions:
                            enabled:
                                description:
                                    - Whether to encrypt the table type.
                                type: bool
                    queue:
                        description:
                            - The encryption function of the queue storage service.
                        type: dict
                        suboptions:
                            enabled:
                                description:
                                    - Whether to encrypt the queue type.
                                type: bool
                    file:
                        description:
                            - The encryption function of the file storage service.
                        type: dict
                        suboptions:
                            enabled:
                                description:
                                    - Whether to encrypt the file type.
                                type: bool
                    blob:
                        description:
                            - The encryption function of the blob storage service.
                        type: dict
                        suboptions:
                            enabled:
                                description:
                                    - Whether to encrypt the blob type.
                                type: bool
            key_source:
                description:
                    - The encryption keySource (provider).
                type: str
                default: Microsoft.Storage
                choices:
                    - Microsoft.Storage
                    - Microsoft.Keyvault
            require_infrastructure_encryption:
                description:
                    - A boolean indicating whether or not the service applies a secondary layer of encryption with platform managed keys for data at rest.
                type: bool

extends_documentation_fragment:
    - azure.azcollection.azure
    - azure.azcollection.azure_tags

author:
    - Chris Houseknecht (@chouseknecht)
    - Matt Davis (@nitzmahone)
'''

EXAMPLES = '''
- name: remove account, if it exists
  azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    state: absent

- name: create an account
  azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    tags:
      testing: testing
      delete: on-exit

- name: Create an account with kind of FileStorage
  azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: c1h0002
    type: Premium_LRS
    kind: FileStorage
    tags:
      testing: testing

- name: configure firewall and virtual networks
  azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    network_acls:
      bypass: AzureServices,Metrics
      default_action: Deny
      virtual_network_rules:
        - id: /subscriptions/mySubscriptionId/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVnet/subnets/mySubnet
          action: Allow
      ip_rules:
        - value: 1.2.3.4
          action: Allow
        - value: 123.234.123.0/24
          action: Allow

- name: create an account with blob CORS
  azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh002
    type: Standard_RAGRS
    blob_cors:
      - allowed_origins:
          - http://www.example.com/
        allowed_methods:
          - GET
          - POST
        allowed_headers:
          - x-ms-meta-data*
          - x-ms-meta-target*
          - x-ms-meta-abc
        exposed_headers:
          - x-ms-meta-*
        max_age_in_seconds: 200
'''


RETURN = '''
state:
    description:
        - Current state of the storage account.
    returned: always
    type: complex
    contains:
        account_type:
            description:
                - Type of storage account.
            returned: always
            type: str
            sample: Standard_RAGRS
        custom_domain:
            description:
                - User domain assigned to the storage account.
            returned: always
            type: complex
            contains:
                name:
                    description:
                        - CNAME source.
                    returned: always
                    type: str
                    sample: testaccount
                use_sub_domain:
                    description:
                        - Whether to use sub domain.
                    returned: always
                    type: bool
                    sample: true
        encryption:
            description:
                - The encryption settings on the storage account.
            type: complex
            returned: always
            contains:
                key_source:
                    description:
                        - The encryption keySource (provider).
                    type: str
                    returned: always
                    sample: Microsoft.Storage
                require_infrastructure_encryption:
                    description:
                        - A boolean indicating whether or not the service applies a secondary layer of encryption with platform managed keys for data at rest.
                    type: bool
                    returned: always
                    sample: false
                services:
                    description:
                        - List of services which support encryption.
                    type: dict
                    returned: always
                    contains:
                        file:
                            description:
                                - The encryption function of the file storage service.
                            type: dict
                            returned: always
                            sample: {'enabled': true}
                        table:
                            description:
                                - The encryption function of the table storage service.
                            type: dict
                            returned: always
                            sample: {'enabled': true}
                        queue:
                            description:
                                - The encryption function of the queue storage service.
                            type: dict
                            returned: always
                            sample: {'enabled': true}
                        blob:
                            description:
                                - The encryption function of the blob storage service.
                            type: dict
                            returned: always
                            sample: {'enabled': true}
        id:
            description:
                - Resource ID.
            returned: always
            type: str
            sample: "/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/myResourceGroup/providers/Microsoft.Storage/storageAccounts/clh0003"
        is_hns_enabled:
            description:
                - Account HierarchicalNamespace enabled if sets to true.
            type: bool
            returned: always
            sample: true
        enable_nfs_v3:
            description:
                - NFS 3.0 protocol.
            type: bool
            returned: always
            sample: false
        location:
            description:
                - Valid Azure location. Defaults to location of the resource group.
            returned: always
            type: str
            sample: eastus2
        name:
            description:
                - Name of the storage account to update or create.
            returned: always
            type: str
            sample: clh0003
        network_acls:
            description:
                - A set of firewall and virtual network rules
            returned: always
            type: dict
            sample: {
                    "bypass": "AzureServices",
                    "default_action": "Deny",
                    "virtual_network_rules": [
                        {
                            "action": "Allow",
                            "id": "/subscriptions/mySubscriptionId/resourceGroups/myResourceGroup/ \
                                   providers/Microsoft.Network/virtualNetworks/myVnet/subnets/mySubnet"
                            }
                        ],
                    "ip_rules": [
                        {
                            "action": "Allow",
                            "value": "1.2.3.4"
                        },
                        {
                            "action": "Allow",
                            "value": "123.234.123.0/24"
                        }
                    ]
                    }
        primary_endpoints:
            description:
                - The URLs to retrieve the public I(blob), I(queue), or I(table) object from the primary location.
            returned: always
            type: dict
            sample: {
                    "blob": "https://clh0003.blob.core.windows.net/",
                    "queue": "https://clh0003.queue.core.windows.net/",
                    "table": "https://clh0003.table.core.windows.net/"
                    }
        primary_location:
            description:
                - The location of the primary data center for the storage account.
            returned: always
            type: str
            sample: eastus2
        provisioning_state:
            description:
                - The status of the storage account.
                - Possible values include C(Creating), C(ResolvingDNS), C(Succeeded).
            returned: always
            type: str
            sample: Succeeded
        failover_in_progress:
            description:
                - Status indicating the storage account is currently failing over to its secondary location.
            returned: always
            type: bool
            sample: False
        resource_group:
            description:
                - The resource group's name.
            returned: always
            type: str
            sample: Testing
        secondary_endpoints:
            description:
                - The URLs to retrieve the public I(blob), I(queue), or I(table) object from the secondary location.
            returned: always
            type: dict
            sample: {
                    "blob": "https://clh0003-secondary.blob.core.windows.net/",
                    "queue": "https://clh0003-secondary.queue.core.windows.net/",
                    "table": "https://clh0003-secondary.table.core.windows.net/"
                    }
        secondary_location:
            description:
                - The location of the geo-replicated secondary for the storage account.
            returned: always
            type: str
            sample: centralus
        status_of_primary:
            description:
                - The status of the primary location of the storage account; either C(available) or C(unavailable).
            returned: always
            type: str
            sample: available
        status_of_secondary:
            description:
                - The status of the secondary location of the storage account; either C(available) or C(unavailable).
            returned: always
            type: str
            sample: available
        https_only:
            description:
                -  Allows https traffic only to storage service when set to C(true).
            returned: always
            type: bool
            sample: false
        minimum_tls_version:
            description:
                -  The minimum TLS version permitted on requests to storage.
            returned: always
            type: str
            sample: TLS1_2
        public_network_access:
            description:
                -  Public network access to Storage Account allowed or disallowed.
            returned: always
            type: str
            sample: Enabled
        allow_blob_public_access:
            description:
                -  Public access to all blobs or containers in the storage account allowed or disallowed.
            returned: always
            type: bool
            sample: true
        tags:
            description:
                - Resource tags.
            returned: always
            type: dict
            sample: { 'tags1': 'value1' }
        type:
            description:
                - The storage account type.
            returned: always
            type: str
            sample: "Microsoft.Storage/storageAccounts"
        large_file_shares_state:
            description:
                - Allow large file shares if sets to Enabled.
            type: str
            returned: always
            sample: Enabled
        static_website:
            description:
                - Static website configuration for the storage account.
            returned: always
            version_added: "1.13.0"
            type: complex
            contains:
                enabled:
                    description:
                        - Whether this account is hosting a static website.
                    returned: always
                    type: bool
                    sample: true
                index_document:
                    description:
                        - The default name of the index page under each directory.
                    returned: always
                    type: str
                    sample: index.html
                error_document404_path:
                    description:
                        - The absolute path of the custom 404 page.
                    returned: always
                    type: str
                    sample: error.html
'''


from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase
from azure.core.exceptions import ResourceNotFoundError
import logging
logging.basicConfig(filename='log.log', level=logging.INFO)


class AzureRMStorageAccountManagementPolicy(AzureRMModuleBase):

    def __init__(self):

        self.module_arg_spec = dict(
            resource_group=dict(required=True, type='str', aliases=['resource_group_name']),
            storage_account_name=dict(type='str', required=True),
            state=dict(default='present', choices=['present', 'absent']),
            rules=dict(
                type='list',
                elements='dict',
                options=dict(
                    enabled=dict(type='bool'),
                    name=dict(type='str', required=True),
                    type=dict(type='str', required=True, choices=['Lifecycle']),
                    definition=dict(
                        type='dict',
                        options=dict(
                            actions=dict(
                                type='dict',
                                required=True,
                                options=dict(
                                    base_blob=dict(
                                        type='dict',
                                        options=dict(
                                            tier_to_cool=dict(
                                                type='dict',
                                                options=dict(
                                                    days_after_modification_greater_than=dict(type='float'),
                                                    days_after_last_access_time_greater_than=dict(type='float')
                                                )
                                            ),
                                            tier_to_archive=dict(
                                                type='dict',
                                                options=dict(
                                                    days_after_modification_greater_than=dict(type='float'),
                                                    days_after_last_access_time_greater_than=dict(type='float')
                                                )
                                            ),
                                            delete=dict(
                                                type='dict',
                                                options=dict(
                                                    days_after_modification_greater_than=dict(type='float'),
                                                    days_after_last_access_time_greater_than=dict(type='float')
                                                )
                                            ),
                                            enable_auto_tier_to_hot_from_cool=dict(type='bool')
                                        )
                                    ),
                                    snapshot=dict(
                                        type='dict',
                                        options=dict(
                                            tier_to_cool=dict(
                                                type='dict',
                                                options=dict(
                                                    days_after_creation_greater_than=dict(type='float', required=True)
                                                )
                                            ),
                                            tier_to_archive=dict(
                                                type='dict',
                                                options=dict(
                                                    days_after_creation_greater_than=dict(type='float', required=True)
                                                )
                                            ),
                                            delete=dict(
                                                type='dict',
                                                options=dict(
                                                    days_after_creation_greater_than=dict(type='float', required=True)
                                                )
                                            )
                                        )
                                    ),
                                    version=dict(
                                        type='dict',
                                        options=dict(
                                            tier_to_cool=dict(
                                                type='dict',
                                                options=dict(
                                                    days_after_creation_greater_than=dict(
                                                        type='float',
                                                    )
                                                )
                                            ),
                                            tier_to_archive=dict(
                                                type='dict',
                                                options=dict(
                                                    days_after_creation_greater_than=dict(
                                                        type='float',
                                                    )
                                                )
                                            ),
                                            delete=dict(
                                                type='dict',
                                                options=dict(
                                                    days_after_creation_greater_than=dict(
                                                        type='float',
                                                        required=True
                                                    )
                                                )
                                            )
                                        )
                                    )
                                )
                            ),
                            filters=dict(
                                type='dict',
                                options=dict(
                                    prefix_match=dict(type='list', elements='str'),
                                    blob_types=dict(type='list', elements='str', required=True),
                                    #blob_index_match=dict(
                                    #    type='list',
                                    #    elements='dict',
                                    #    options=dict(
                                    #        name=dict(type='str', required=True),
                                    #        op=dict(type='str', required=True),
                                    #        value=dict(type='str', required=True)
                                    #    )
                                    #)
                                )
                            )
                        )
                    )
                )
            )
        )

        self.results = dict(
            changed=False,
            state=dict()
        )

        self.resource_group = None
        self.storage_account_name = None
        self.state = None
        self.rules = []

        super(AzureRMStorageAccountManagementPolicy, self).__init__(self.module_arg_spec,
                                                                    supports_tags=False,
                                                                    supports_check_mode=True)

    def exec_module(self, **kwargs):

        for key in list(self.module_arg_spec.keys()):
            setattr(self, key, kwargs[key])

        managed_policy = self.get_management_policy()
        changed = False

        if self.state == 'present':
            if managed_policy is not None:
                rule_name = [item['name'] for item in managed_policy['policy']['rules']]
                for item in self.rules:
                    if item['name'] in rule_name:
                        for tt in managed_policy['policy']['rules']:
                            if item['name'] == tt['name']:
                                old_item = tt
                                changed = self.compare(old_item, item)
                                break
                    else:
                        changed = True

#                rule_name = [item['name'] for item in self.rules]
#                for item in managed_policy['policy']['rules']:
#                    if item['name'] in rule_name:
#                        for tt in self.rules:
#                            if item['name'] == tt['name']:
#                                new_item = tt
#                                update = self.compare(item, new_item) 
#                                break
#                        if update:
#                            changed = True
#                        else:
#                    else:
#                        self.rules.append(item)
#                        changed = True
                if changed and not self.check_mode:
                    self.create_or_update_management_policy(self.rules)
            else:
                changed = True
                if not self.check_mode:
                    self.create_or_update_management_policy(self.rules)
        else:
            if managed_policy is not None:
                changed = True
                if not self.check_mode:
                    self.delete_management_policy()

        self.results['state'] = self.get_management_policy()
        self.results['changed'] = changed

        return self.results

    def get_management_policy(self):
        self.log('Get info for storage account management policy')

        response = None
        try:
            response = self.storage_client.management_policies.get(self.resource_group, self.storage_account_name, 'default')
        except ResourceNotFoundError as ec:
            self.log("Failed to obtain the storage acount management policy, detail as {0}".format(ec))
            return
        return self.format_to_dict(response)

    def create_or_update_management_policy(self, rules):
        self.log("Creating or updating storage account mangement policy")

        try:
            #rule = self.storage_models.ManagementPolicySchema(rules=rules)
            import json
            logging.info('333'*10)
            logging.info(dict(rules=rules))
            logging.info(json.dumps(dict(rules=rules)))
            logging.info('ppp'*10)
            policy = self.storage_models.ManagementPolicy(policy=json.dumps(dict(rules=rules)))
            logging.info(policy)
            logging.info(policy.policy)
            logging.info('ttt'*10)
            #rules = [{'name': 'olcmtest2', 'type': 'Lifecycle', 'enabled': True, 'definition': {'actions': {'base_blob': "{'tier_to_archive': {'days_after_modification_greater_than': 90}, 'tier_to_cool': {'days_after_modification_greater_than': 90}, 'delete': {'days_after_modification_greater_than': 90}, 'enable_auto_tier_to_hot_from_cool': True}", 'snapshot': {'delete': {'days_after_creation_greater_than': 90.0}}}, 'filters': {'prefix_match': ['olcmtestcontainer2'], 'blob_types': ['blockBlob']}}}]
            #rules = [{'name': 'olcmtest2', 'type': 'Lifecycle', 'enabled': True, 'definition': {'actions': {'base_blob': "{'tier_to_archive': {'days_after_modification_greater_than': 90}, 'tier_to_cool': {'days_after_modification_greater_than': 90}, 'delete': {'days_after_modification_greater_than': 90}, 'enable_auto_tier_to_hot_from_cool': True}", 'snapshot': {'delete': {'days_after_creation_greater_than': 90.0}, 'tier_to_cool': None, 'tier_to_archive': None}, 'version': None}, 'filters': {'prefix_match': ['olcmtestcontainer2'], 'blob_types': ['blockBlob'], 'blob_index_match': None}}}]

            self.storage_client.management_policies.create_or_update(resource_group_name=self.resource_group,
                                                                          account_name=self.storage_account_name,
                                                                          management_policy_name='default',
                                                                          #properties=dict(policy=rule))
                                                                          #properties=policy)
                                                                          #properties=policy)
                                                                          #properties=json.dumps(dict(rules=rules)))
                                                                          properties=dict(policy=json.dumps(dict(rules=rules))))
        except Exception as e:
            self.log('Error creating or updating storage account management policy.')
            self.fail("Failed to create or updating storage account management policy: {0}".format(str(e)))
        return self.get_management_polic()

    def delete_management_policy(self):
        try:
            self.storage_client.management_policies.delete(self.resource_group, self.storage_account_name, 'default')
        except Exception as e:
            self.fail("Failed to delete the storage account management policy: {0}".format(str(e)))

    def format_to_dict(self, obj):
        result = dict()
        result['id'] = obj.id
        result['resource_group'] = self.resource_group
        result['storage_account_name'] = self.storage_account_name
        result['name'] = obj.name
        result['type'] = obj.type
        result['last_modified_time'] = obj.last_modified_time
        result['policy'] = dict(rules=[])
        if obj.policy is not None:
            result['policy'] = obj.policy.as_dict()

        return result
    
    def compare(self, old, new):
        if new is None:
            return False
        elif old is None:
            return True
        elif isinstance(new, dict):
            if not isinstance(old, dict):
                return True
            for key in new.keys():
                if self.compare(old[key], new.get(key)):
                    return True
        elif isinstance(new, list):
            if len(new) != len(old):
                return True
            elif len(old) == 0:
                return False
            else:
                for item in new:
                    if item not in old:
                        return True
        else:
            if isinstance(new, bool) and isinstance(old, bool) and bool(new) == bool(old):
                return False
            else:
                return True
            if new == old:
                return False
            else:
                return True


def main():
    AzureRMStorageAccountManagementPolicy()


if __name__ == '__main__':
    main()
