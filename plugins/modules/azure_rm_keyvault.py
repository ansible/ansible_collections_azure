#!/usr/bin/python
#
# Copyright (c) 2017 Zim Kalinowski, <zikalino@microsoft.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_keyvault
version_added: "0.1.2"
short_description: Manage Key Vault instance
description:
    - Create, update and delete instance of Key Vault.

options:
    resource_group:
        description:
            - The name of the Resource Group to which the server belongs.
        required: True
        type: str
    vault_name:
        description:
            - Name of the vault.
            - It is mutually exclusive with I(hsm_name)
        required: False
        type: str
    hsm_name:
        description:
            - Name of the HSM.
            - It is mutually exclusive with I(vault_name)
        required: False
        type: str
    administrators:
        description:
            - List of administrator OID's for data plane operations for Managed HSM.
            - It is mutually exclusive with I(vault_name)
        required: False
        type: list
        elements: str
        default: []
    identity:
        description:
            - Identity for the HSM, not valid for vault_name.
            - It is mutually exclusive with I(vault_name)
        type: dict
        version_added: '3.0.0'
        suboptions:
            type:
                description:
                    - Type of the managed identity
                choices:
                    - UserAssigned
                    - None
                default: None
                type: str
            user_assigned_identity:
                description:
                    - User Assigned Managed Identity associated to this resource
                required: false
                type: str
    location:
        description:
            - Resource location. If not set, location from the resource group will be used as default.
        type: str
    vault_tenant:
        description:
            - The Azure Active Directory tenant ID that should be used for authenticating requests to the key vault.
        type: str
        aliases:
          - tenant_id
    sku:
        description:
            - SKU details.
        type: dict
        suboptions:
            family:
                description:
                    - SKU family name.
                type: str
                required: True
            name:
                description:
                    - SKU name to specify whether the key vault is a standard vault or a premium vault.
                required: True
                type: str
                choices:
                    - 'standard'
                    - 'premium'
    access_policies:
        description:
            - An array of 0 to 16 identities that have access to the key vault.
            - All identities in the array must use the same tenant ID as the key vault's tenant ID.
            - It is mutually exclusive with I(hsm_name)
        type: list
        elements: dict
        suboptions:
            tenant_id:
                description:
                    - The Azure Active Directory tenant ID that should be used for authenticating requests to the key vault.
                    - Current keyvault C(tenant_id) value will be used if not specified.
                type: str
            object_id:
                description:
                    - The object ID of a user, service principal or security group in the Azure Active Directory tenant for the vault.
                    - The object ID must be unique for the list of access policies.
                    - Please note this is not application id. Object id can be obtained by running "az ad sp show --id <application id>".
                type: str
                required: True
            application_id:
                description:
                    -  Application ID of the client making request on behalf of a principal.
                type: str
            keys:
                description:
                    - List of permissions to keys.
                type: list
                elements: str
                choices:
                    - 'encrypt'
                    - 'decrypt'
                    - 'wrapkey'
                    - 'unwrapkey'
                    - 'sign'
                    - 'verify'
                    - 'get'
                    - 'list'
                    - 'create'
                    - 'update'
                    - 'import'
                    - 'delete'
                    - 'backup'
                    - 'restore'
                    - 'recover'
                    - 'purge'
            secrets:
                description:
                    - List of permissions to secrets.
                type: list
                elements: str
                choices:
                    - 'get'
                    - 'list'
                    - 'set'
                    - 'delete'
                    - 'backup'
                    - 'restore'
                    - 'recover'
                    - 'purge'
            certificates:
                description:
                    - List of permissions to certificates.
                type: list
                elements: str
                choices:
                    - 'get'
                    - 'list'
                    - 'delete'
                    - 'create'
                    - 'import'
                    - 'update'
                    - 'managecontacts'
                    - 'getissuers'
                    - 'listissuers'
                    - 'setissuers'
                    - 'deleteissuers'
                    - 'manageissuers'
                    - 'recover'
                    - 'purge'
                    - 'backup'
                    - 'restore'
            storage:
                description:
                    - List of permissions to storage accounts.
                type: list
                elements: str
    enabled_for_deployment:
        description:
            - Property to specify whether Azure Virtual Machines are permitted to retrieve certificates stored as secrets from the key vault.
            - It is mutually exclusive with I(hsm_name)
        type: bool
    enabled_for_disk_encryption:
        description:
            - Property to specify whether Azure Disk Encryption is permitted to retrieve secrets from the vault and unwrap keys.
            - It is mutually exclusive with I(hsm_name)
        type: bool
    enabled_for_template_deployment:
        description:
            - Property to specify whether Azure Resource Manager is permitted to retrieve secrets from the key vault.
            - It is mutually exclusive with I(hsm_name)
        type: bool
    enable_soft_delete:
        description:
            - Property to specify whether the soft delete functionality is enabled for this key vault.
        type: bool
        default: True
    enable_purge_protection:
        description:
            - Property specifying whether protection against purge is enabled for this vault.
        type: bool
        default: False
    soft_delete_retention_in_days:
        description:
            - Property specifying the number of days to retain deleted vaults.
        type: int
    recover_mode:
        description:
            - Create vault in recovery mode.
        type: bool
    state:
        description:
            - Assert the state of the KeyVault. Use C(present) to create or update an KeyVault and C(absent) to delete it.
        default: present
        type: str
        choices:
            - absent
            - present

extends_documentation_fragment:
    - azure.azcollection.azure
    - azure.azcollection.azure_tags

author:
    - Zim Kalinowski (@zikalino)

'''

EXAMPLES = '''
- name: Create instance of Key Vault
  azure_rm_keyvault:
    resource_group: myResourceGroup
    vault_name: samplekeyvault
    enabled_for_deployment: true
    vault_tenant: 72f98888-8666-4144-9199-2d7cd0111111
    sku:
      name: standard
      family: A
    access_policies:
      - tenant_id: 72f98888-8666-4144-9199-2d7cd0111111
        object_id: 99998888-8666-4144-9199-2d7cd0111111
        keys:
          - get
          - list
'''

RETURN = '''
id:
    description:
        - The Azure Resource Manager resource ID for the key vault.
    returned: always
    type: str
    sample: id
'''

import time
from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common_ext import AzureRMModuleBaseExt

try:
    from azure.core.polling import LROPoller
    from azure.core.exceptions import ResourceNotFoundError
    from azure.mgmt.keyvault import KeyVaultManagementClient
    from azure.mgmt.keyvault.models import (ManagedServiceIdentity, UserAssignedIdentity, NetworkRuleSet,
                                            NetworkRuleBypassOptions, NetworkRuleAction, ManagedHsmProperties,
                                            ManagedHsm, ManagedHsmSku)
except ImportError:
    # This is handled in azure_rm_common
    pass


class Actions:
    NoAction, Create, Update, Delete = range(4)


class AzureRMVaults(AzureRMModuleBaseExt):
    """Configuration class for an Azure RM Key Vault resource"""

    def __init__(self):
        self.module_arg_spec = dict(
            resource_group=dict(
                type='str',
                required=True
            ),
            vault_name=dict(
                type='str'
            ),
            hsm_name=dict(
                type='str'
            ),
            location=dict(
                type='str'
            ),
            vault_tenant=dict(
                type='str',
                aliases=['tenant_id']
            ),
            sku=dict(
                type='dict'
            ),
            administrators=dict(
                type='list',
                default=[],
                elements='str'
            ),
            identity=dict(
                type='dict',
                options=dict(
                    type=dict(
                        type='str',
                        choices=['UserAssigned', 'None'],
                        default='None'
                    ),
                    user_assigned_identity=dict(
                        type="str",
                    ),
                ),
            ),
            access_policies=dict(
                type='list',
                elements='dict',
                options=dict(
                    tenant_id=dict(type='str'),
                    object_id=dict(type='str', required=True),
                    application_id=dict(type='str'),
                    # FUTURE: add `choices` support once choices supports lists of values
                    keys=dict(
                        type='list',
                        elements='str',
                        no_log=True,
                        choices=['encrypt', 'decrypt', 'wrapkey', 'unwrapkey', 'sign', 'verify', 'get',
                                 'list', 'create', 'update', 'import', 'delete', 'backup', 'restore', 'recover', 'purge']
                    ),
                    secrets=dict(
                        type='list',
                        elements='str',
                        no_log=True,
                        choices=['get', 'list', 'set', 'delete', 'backup', 'restore', 'recover', 'purge']
                    ),
                    certificates=dict(
                        type='list',
                        elements='str',
                        choices=['get', 'list', 'delete', 'create', 'import', 'update', 'managecontacts',
                                 'getissuers', 'listissuers', 'setissuers', 'deleteissuers', 'manageissuers', 'recover', 'purge', 'backup', 'restore']
                    ),
                    storage=dict(type='list', elements='str')
                )
            ),
            enabled_for_deployment=dict(
                type='bool'
            ),
            enabled_for_disk_encryption=dict(
                type='bool'
            ),
            enabled_for_template_deployment=dict(
                type='bool'
            ),
            enable_soft_delete=dict(
                type='bool',
                default=True
            ),
            soft_delete_retention_in_days=dict(
                type='int'
            ),
            enable_purge_protection=dict(
                type='bool',
                default=False
            ),
            recover_mode=dict(
                type='bool'
            ),
            state=dict(
                type='str',
                default='present',
                choices=['present', 'absent']
            )
        )

        self.module_required_if = [['state', 'present', ['vault_tenant']]]

        self.resource_group = None
        self.vault_name = None
        self.hsm_name = None
        self.parameters = dict()
        self.tags = None
        self.identity = None
        self.administrators = None

        self.results = dict(changed=False)
        self.mgmt_client = None
        self.state = None
        self.to_do = Actions.NoAction
        self._managed_identity = None

        required_one_of = [('vault_name', 'hsm_name')]
        mutually_exclusive = [('vault_name', 'hsm_name'),
                              ('vault_name', 'identity'),
                              ('vault_name', 'administrators'),
                              ('hsm_name', 'enabled_for_deployment'),
                              ('hsm_name', 'enabled_for_disk_encryption'),
                              ('hsm_name', 'enabled_for_template_deployment'),
                              ('hsm_name', 'access_policies')]

        super(AzureRMVaults, self).__init__(derived_arg_spec=self.module_arg_spec,
                                            supports_check_mode=True,
                                            supports_tags=True,
                                            mutually_exclusive=mutually_exclusive,
                                            required_one_of=required_one_of,
                                            required_if=self.module_required_if)

    @property
    def managed_identity(self):
        if not self._managed_identity:
            self._managed_identity = {"identity": ManagedServiceIdentity,
                                      "user_assigned": UserAssignedIdentity
                                      }
        return self._managed_identity

    def exec_module(self, **kwargs):
        """Main module execution method"""

        # translate Ansible input to SDK-formatted dict in self.parameters
        for key in list(self.module_arg_spec.keys()) + ['tags']:
            if hasattr(self, key):
                setattr(self, key, kwargs[key])
            elif kwargs[key] is not None:
                if key == "location":
                    self.parameters["location"] = kwargs[key]
                elif key == "vault_tenant":
                    self.parameters.setdefault("properties", {})["tenant_id"] = kwargs[key]
                elif key == "sku" and self.vault_name is not None:
                    self.parameters.setdefault("properties", {})["sku"] = kwargs[key]
                elif key == "sku" and self.hsm_name is not None:
                    self.parameters["sku"] = kwargs[key]
                elif key == "access_policies":
                    access_policies = kwargs[key]
                    for policy in access_policies:
                        if 'keys' in policy:
                            policy.setdefault("permissions", {})["keys"] = policy["keys"]
                            policy.pop("keys", None)
                        if 'secrets' in policy:
                            policy.setdefault("permissions", {})["secrets"] = policy["secrets"]
                            policy.pop("secrets", None)
                        if 'certificates' in policy:
                            policy.setdefault("permissions", {})["certificates"] = policy["certificates"]
                            policy.pop("certificates", None)
                        if 'storage' in policy:
                            policy.setdefault("permissions", {})["storage"] = policy["storage"]
                            policy.pop("storage", None)
                        if policy.get('tenant_id') is None:
                            # default to key vault's tenant, since that's all that's currently supported anyway
                            policy['tenant_id'] = kwargs['vault_tenant']
                    self.parameters.setdefault("properties", {})["access_policies"] = access_policies
                elif key == "enabled_for_deployment":
                    self.parameters.setdefault("properties", {})["enabled_for_deployment"] = kwargs[key]
                elif key == "enabled_for_disk_encryption":
                    self.parameters.setdefault("properties", {})["enabled_for_disk_encryption"] = kwargs[key]
                elif key == "enabled_for_template_deployment":
                    self.parameters.setdefault("properties", {})["enabled_for_template_deployment"] = kwargs[key]
                elif key == "enable_soft_delete":
                    self.parameters.setdefault("properties", {})["enable_soft_delete"] = kwargs[key]
                elif key == "enable_purge_protection":
                    self.parameters.setdefault("properties", {})["enable_purge_protection"] = kwargs[key]
                elif key == "soft_delete_retention_in_days":
                    self.parameters.setdefault("properties", {})["soft_delete_retention_in_days"] = kwargs[key]
                elif key == "recover_mode":
                    self.parameters.setdefault("properties", {})["create_mode"] = 'recover' if kwargs[key] else 'default'

        old_response = None
        response = None

        self.mgmt_client = self.get_mgmt_svc_client(KeyVaultManagementClient,
                                                    base_url=self._cloud_environment.endpoints.resource_manager,
                                                    api_version="2023-07-01")

        resource_group = self.get_resource_group(self.resource_group)

        if "location" not in self.parameters:
            self.parameters["location"] = resource_group.location

        old_response = self.get_instance()

        curr_identity = old_response.get('identity') if old_response else None
        update_identity, identity_result = self.update_single_managed_identity(curr_identity=curr_identity,
                                                                               new_identity=self.identity)
        if update_identity:
            self.parameters["identity"] = identity_result

        if not old_response:
            self.log("Old instance doesn't exist")
            if self.state == 'absent':
                self.log("Old instance didn't exist")
            else:
                self.to_do = Actions.Create
                if not self.parameters['properties']['enable_purge_protection']:
                    self.parameters['properties'].pop('enable_purge_protection')
        else:
            self.log("Instance already exists")
            if self.state == 'absent':
                self.to_do = Actions.Delete
            elif self.state == 'present':
                self.log("Need to check if instance has to be deleted or may be updated")
                if not self.parameters['properties']['enable_purge_protection'] and \
                        ('enable_purge_protection' not in old_response['properties'] or
                         not old_response['properties']['enable_purge_protection']):
                    self.parameters['properties'].pop('enable_purge_protection')
                if ('location' in self.parameters) and (self.parameters['location'] != old_response['location']):
                    self.to_do = Actions.Update
                elif (('tenant_id' in self.parameters['properties']) and
                        (self.parameters['properties']['tenant_id'] != old_response['properties']['tenant_id'])):
                    self.to_do = Actions.Update
                elif (('enabled_for_deployment' in self.parameters['properties']) and
                        (self.parameters['properties']['enabled_for_deployment'] != old_response['properties'].get('enabled_for_deployment', None))):
                    self.to_do = Actions.Update
                elif (('enabled_for_disk_encryption' in self.parameters['properties']) and
                        (self.parameters['properties']['enabled_for_disk_encryption'] !=
                         old_response['properties'].get('enabled_for_disk_encryption', None))):
                    self.to_do = Actions.Update
                elif (('enabled_for_template_deployment' in self.parameters['properties']) and
                        (self.parameters['properties']['enabled_for_template_deployment'] !=
                         old_response['properties'].get('enabled_for_template_deployment', None))):
                    self.to_do = Actions.Update
                elif (('enable_soft_delete' in self.parameters['properties']) and
                        (self.parameters['properties']['enable_soft_delete'] != old_response['properties'].get('enable_soft_delete', None))):
                    self.to_do = Actions.Update
                elif (('soft_delete_retention_in_days' in self.parameters['properties']) and
                        (self.parameters['properties']['soft_delete_retention_in_days'] != old_response['properties'].get('soft_delete_retention_in_days'))):
                    self.to_do = Actions.Update
                elif (('enable_purge_protection' in self.parameters['properties']) and
                      (self.parameters['properties']['enable_purge_protection'] != old_response['properties'].get('enable_purge_protection'))):
                    self.to_do = Actions.Update
                elif ('create_mode' in self.parameters['properties']) and (self.parameters['properties']['create_mode'] == 'recover'):
                    self.to_do = Actions.Update
                elif 'access_policies' in self.parameters['properties']:
                    if len(self.parameters['properties']['access_policies']) != len(old_response['properties']['access_policies']):
                        self.to_do = Actions.Update
                    else:
                        # FUTURE: this list isn't really order-dependent- we should be set-ifying the rules list for order-independent comparison
                        for i in range(len(old_response['properties']['access_policies'])):
                            n = self.parameters['properties']['access_policies'][i]
                            o = old_response['properties']['access_policies'][i]
                            if n.get('tenant_id', False) != o.get('tenant_id', False):
                                self.to_do = Actions.Update
                                break
                            if n.get('object_id', None) != o.get('object_id', None):
                                self.to_do = Actions.Update
                                break
                            if n.get('application_id', None) != o.get('application_id', None):
                                self.to_do = Actions.Update
                                break
                            if sorted(n.get('permissions', {}).get('keys', []) or []) != sorted(o.get('permissions', {}).get('keys', []) or []):
                                self.to_do = Actions.Update
                                break
                            if sorted(n.get('permissions', {}).get('secrets', []) or []) != sorted(o.get('permissions', {}).get('secrets', []) or []):
                                self.to_do = Actions.Update
                                break
                            if sorted(n.get('permissions', {}).get('certificates', []) or []) != sorted(o.get('permissions', {}).get('certificates', []) or []):
                                self.to_do = Actions.Update
                                break
                            if sorted(n.get('permissions', {}).get('storage', []) or []) != sorted(o.get('permissions', {}).get('storage', []) or []):
                                self.to_do = Actions.Update
                                break

                update_tags, newtags = self.update_tags(old_response.get('tags', dict()))

                if self.hsm_name and \
                        self.administrators != old_response["properties"]["initial_admin_object_ids"]:
                    self.to_do = Actions.Update

                if update_tags:
                    self.to_do = Actions.Update
                    self.tags = newtags

                if update_identity:
                    self.to_do = Actions.Update

        if (self.to_do == Actions.Create) or (self.to_do == Actions.Update):
            self.log("Need to Create / Update the instance")

            if self.check_mode:
                self.results['changed'] = True
                return self.results

            self.parameters["tags"] = self.tags

            if self.vault_name is not None:
                response = self.create_update_keyvault()
            else:
                response = self.create_update_hsm()

            if response is None:
                response = self.get_instance()

            if not old_response:
                self.results['changed'] = True
            else:
                self.results['changed'] = old_response.__ne__(response)
            self.log("Creation / Update done")
        elif self.to_do == Actions.Delete:
            self.log("Instance deleted")
            self.results['changed'] = True

            if self.check_mode:
                return self.results

            if self.vault_name is not None:
                self.delete_keyvault()
            else:
                self.hsm_begin_delete()
            # make sure instance is actually deleted, for some Azure resources, instance is hanging around
            # for some time after deletion -- this should be really fixed in Azure
            while self.get_instance():
                time.sleep(20)
        else:
            self.log("Instance unchanged")
            self.results['changed'] = False
            response = old_response

        if response:
            self.results["id"] = response["id"]

        return self.results

    def create_update_keyvault(self):
        '''
        Creates or updates Key Vault with the specified configuration.

        :return: deserialized Key Vault instance state dictionary
        '''
        self.log("Creating / Updating the Key Vault instance {0}".format(self.vault_name))

        try:
            response = self.mgmt_client.vaults.begin_create_or_update(resource_group_name=self.resource_group,
                                                                      vault_name=self.vault_name,
                                                                      parameters=self.parameters)
            if isinstance(response, LROPoller):
                response = self.get_poller_result(response)

        except Exception as exc:
            self.log('Error attempting to create the Key Vault instance.')
            self.fail("Error creating the Key Vault instance: {0}".format(str(exc)))
        return response and response.as_dict() or None

    def create_update_hsm(self):
        '''
        Creates or updates HSM with the specified configuration.

        :return: deserialized HSM instance state dictionary
        '''
        self.log("Creating / Updating the HSM instance {0}".format(self.hsm_name))

        tenant_id = self.parameters.get('properties', {}).get('tenant_id')
        enable_purge_protection = self.parameters.get('properties', {}).get('enable_purge_protection')
        retention_days = self.parameters.get('properties', {}).get('soft_delete_retention_in_days')
        administrators = self.administrators
        bypass = None
        default_action = None
        public_network_access = None
        properties = ManagedHsmProperties(tenant_id=tenant_id,
                                          enable_purge_protection=enable_purge_protection,
                                          soft_delete_retention_in_days=retention_days,
                                          initial_admin_object_ids=administrators,
                                          network_acls=_create_network_rule_set(bypass, default_action),
                                          public_network_access=public_network_access)
        sku = self.parameters.get('sku')
        parameters = ManagedHsm(location=self.parameters.get('location'),
                                tags=self.parameters.get('tags'),
                                sku=ManagedHsmSku(name=sku.get('name'), family=sku.get('family')),
                                identity=self.parameters.get('identity'),
                                properties=properties)
        try:
            response = self.mgmt_client.managed_hsms.begin_create_or_update(resource_group_name=self.resource_group,
                                                                            name=self.hsm_name,
                                                                            parameters=parameters)
            if isinstance(response, LROPoller):
                response = self.get_poller_result(response)

        except Exception as exc:
            self.log('Error attempting to create the HSM instance.')
            self.fail("Error creating the HSM instance: {0}".format(str(exc)))
        return response and response.as_dict() or None

    def delete_keyvault(self):
        '''
        Deletes specified Key Vault instance in the specified subscription and resource group.

        :return: True
        '''
        self.log("Deleting the Key Vault instance {0}".format(self.vault_name))
        try:
            response = self.mgmt_client.vaults.delete(resource_group_name=self.resource_group,
                                                      vault_name=self.vault_name)
        except Exception as e:
            self.log('Error attempting to delete the Key Vault instance.')
            self.fail("Error deleting the Key Vault instance: {0}".format(str(e)))

        return True

    def hsm_begin_delete(self):
        '''
        Deletes specified hsm instance in the specified subscription and resource group.

        :return: True
        '''
        self.log("Deleting the hsm instance {0}".format(self.hsm_name))
        try:
            response = self.mgmt_client.managed_hsms.begin_delete(resource_group_name=self.resource_group,
                                                                  name=self.hsm_name)
        except Exception as e:
            self.log('Error attempting to delete the hsm instance.')
            self.fail("Error deleting the hsm instance: {0}".format(str(e)))

        return True

    def get_instance(self):
        '''
        Gets the properties of the specified Key Vault or HSM.

        :return: deserialized Key Vault or HSM instance state dictionary
        '''
        found = False

        if self.vault_name is not None:
            self.log("Checking if the Key Vault instance {0} is present".format(self.vault_name))
            try:
                response = self.mgmt_client.vaults.get(resource_group_name=self.resource_group,
                                                       vault_name=self.vault_name)
                found = True
                self.log("Response : {0}".format(response))
                self.log("Key Vault instance : {0} found".format(response.name))
            except ResourceNotFoundError as e:
                self.log('Did not find the Key Vault instance.')

        if self.hsm_name is not None:
            self.log("Checking if the hsm instance {0} is present".format(self.hsm_name))
            try:
                response = self.mgmt_client.managed_hsms.get(resource_group_name=self.resource_group,
                                                             name=self.hsm_name)
                found = True
                self.log("Response : {0}".format(response))
                self.log("HSM instance : {0} found".format(response.name))
            except ResourceNotFoundError as e:
                self.log('Did not find the hsm instance.')

        if found is True:
            return response.as_dict()

        return False


def _create_network_rule_set(bypass=None, default_action=None):
    return NetworkRuleSet(bypass=bypass or NetworkRuleBypassOptions.azure_services.value,
                          default_action=default_action or NetworkRuleAction.allow.value)


def main():
    """Main execution"""
    AzureRMVaults()


if __name__ == '__main__':
    main()
