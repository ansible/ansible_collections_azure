#!/usr/bin/python
#
# Copyright (c) 2025 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: azure_rm_keyvaultcertificate
version_added: "3.1.0"
short_description: Get Azure Key Vault certificate facts
description:
    - Get or list facts of Azure Key Vault certificate(deleted).

options:
    vault_uri:
        description:
            - Vault uri where the certificate stored in.
        required: True
        type: str
    name:
        description:
            - Certificate name. If not set, will list all certificates in vault_uri.
        type: str
    version:
        description:
            - The version of the certificate.
        type: str
    show_deleted_certificate:
        description:
            - Set to I(show_delete_certificate=true) to show deleted certificates. Set to I(show_deleted_certificate=false) to show not deleted certificates.
        type: bool
        default: false
    tags:
        description:
            - Limit results by providing a list of tags. Format tags as 'key' or 'key:value'.
        type: list
        elements: str

extends_documentation_fragment:
    - azure.azcollection.azure
    - azure.azcollection.azure_tags

author:
    - xuzhang3 (@xuzhang3)
    - Fred-sun (@Fred-sun)

'''

EXAMPLES = '''
- name: Get certificate facts
  azure_rm_keyvaultcertificate:
    vault_uri: "https://myVault.vault.azure.net"
    name: myCertificate

- name: Get specific versions of certificate
  azure_rm_keyvaultcertificate:
    vault_uri: "https://myVault.vault.azure.net"
    name: mySecret
    version: 2809225bcb674ff380f330471b3c3eb0

- name: Get deleted certificate
  azure_rm_keyvaultcertificate:
    vault_uri: "https://myVault.vault.azure.net"
    name: mySecret
    show_deleted_certificate: true

- name: List deleted certificate
  azure_rm_keyvaultcertificate:
    vault_uri: "https://myVault.vault.azure.net"
    show_deleted_certificate: true
'''

RETURN = '''
certificates:
    description:
        - The facts of certificates in Azure Key Vault.
    returned: always
    type: complex
    contains:
        cer:
            description:
                - CER contents of the X509 certificate.
            type: str
            returned: always
            sample: "bytearray(b'0\\x82\\......................\\x8d1s{\\x92S\\x16')"
        deleted_on:
            description:
                - The time when the certificate was deleted, in UTC.
            returned: always
            type: str
            sample: 2025-01-14T09:41:20+00:00
        recovery_id:
            description:
                - The url of the recovery object, used to identify and recover the deleted certificate.
            type: str
            returned: always
            sample: "https://vaultrfred01.vault.azure.net/deletedcertificates/cert02"
        scheduled_purge_date:
            description:
                - The time when the certificate is scheduled to be purged, in UTC.
            returned: always
            type: dict
            sample: 2025-02-14T09:41:20+00:00
        policy:
            description:
                - The management policy of the deleted certificate.
            returned: always
            type: complex
            contains:
                attributes:
                    description:
                        - Certificate attributes.
                    type: complex
                    returned: always
                    contains:
                        created:
                            description:
                                - Creation datetime.
                            returned: always
                            type: str
                            sample: "2025-01-14T09:41:20+00:00"
                        not_before:
                            description:
                                - Not before datetime.
                            type: str
                            sample: None
                        expires:
                            description:
                                - Expiration datetime.
                            type: str
                            sample: None
                        updated:
                            description:
                                - Update datetime.
                            returned: always
                            type: str
                            sample: "2025-01-15T09:41:20+00:00"
                        enabled:
                            description:
                                - Indicate whether the certificate is enabled.
                            returned: always
                            type: str
                            sample: true
                        recovery_level:
                            description:
                                - Reflects the deletion recovery level currently in effect for certificates in the current vault.
                                - If it contains 'Purgeable' the certificate can be permanently deleted by a privileged user,
                                - Otherwise, only the system can purge the certificate, at the end of the retention interval.
                            returned: always
                            type: str
                            sample: None
                        recoverable_days:
                            description:
                                - Reflects the deletion recovery days.
                            type: int
                            returned: always
                            sample: None
                issuer_name:
                    description:
                        - Name of the referenced issuer object or reserved names.
                    type: str
                    returned: always 
                    sample: Self
                subject:
                    description:
                        - The subject name of the certificate.
                        - Should be a valid X509 distinguished name.
                        - Either subject or one of the subject alternative name parameters are required for creating a certificate.
                        - This will be ignored when importing a certificate; the subject will be parsed from the imported certificate.
                    type: str
                    returned: always 
                    sample: CN=anhui.com
                san_emails:
                    description:
                        - Subject alternative emails of the X509 object.
                        - Either subject or one of the subject alternative name parameters are required for creating a certificate.
                    type: str
                    returned: always 
                    sample: None
                san_dns_names:
                    description:
                        - Subject alternative DNS names of the X509 object.
                        - Either subject or one of the subject alternative name parameters are required for creating a certificate.
                    type: str
                    returned: always 
                    sample: None
                san_user_principal_names:
                    description:
                        - Subject alternative user principal names of the X509 object.
                        - Either subject or one of the subject alternative name parameters are required for creating a certificate.
                    type: str
                    returned: always 
                    sample: None
                exportable:
                    description:
                        - Indicates if the private key can be exported.
                    type: bool
                    returned: always
                    sample: true
                key_type:
                    description:
                        - The type of key pair to be used for the certificate.
                    type: str
                    returned: always 
                    sample: RSA
                key_size:
                    description:
                        - The key size in bits. For example: 2048, 3072, or 4096 for RSA.
                    type: int
                    returned: always 
                    sample: 2048
                reuse_key:
                    description:
                        - Indicates if the same key pair will be used on certificate renewal.
                    type: bool
                    returned: always
                    sample: false
                key_curve_name:
                    description:
                        - Elliptic curve name. For valid values, see KeyCurveName.
                    type: str
                    returned: always
                    sample: None
                enhanced_key_usage:
                    description:
                        - The extended ways the key of the certificate can be used.
                    type: list
                    returned: always
                    sample: ['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2']
                key_usage:
                    description:
                        - List of key usages.
                    type: list
                    returned: always
                    sample: ["digitalSignature", "keyEncipherment"]
                content_type:
                    description:
                        - If not specified, the media type (MIME type) of the secret backing the certificate.
                    type: str
                    returned: always 
                    sample: application/x-pkcs12
                validity_in_months:
                    description:
                        - The duration that the certificate is valid in months.
                    type: int
                    returned: always 
                    sample: 12
                lifetime_actions:
                    description:
                        - Actions that will be performed by Key Vault over the lifetime of a certificate.
                    type: list
                    returned: always
                    sample: [{'action': 'AutoRenew', 'days_before_expiry': None, 'lifetime_percentage': 80}]
                certificate_type:
                    description:
                        - Type of certificate to be requested from the issuer provider.
                    type: str
                    returned: str
                    sample: None
                certificate_transparency:
                    description:
                        - Indicates if the certificates generated under this policy should be published to certificate transparency logs.
                    type: bool
                    returned: always
                    sample: None
        properties:
            description:
                - The certificate's properties.
            type: complex
            returned: always
            contains:
                id:
                    description:
                        - Id of the certificate. If specified all other 'Id' arguments should be omitted.
                    type: str
                    returned: always
                    sample: "https://vaultrfred01.vault.azure.net/certificates/cert02/62409e6304c642f193209729b8360d2c"
                vault_id:
                    description:
                        - ID of the Key Vault.
                    type: str
                    returned: always
                    sample: "https://vaultrfred01.vault.azure.net"
                x509_thumbprint:
                    description:
                        - The X509 Thumbprint of the Key Vault Certificate represented as a hexadecimal string.
                    type: str
                    returned: always
                    sample: 1blAnHN9ddng0qh1pYoUDY2lp1E=
                tags:
                    description:
                        - List of the certificate tags.
                    type: dict
                    returned: always
                    sample: {'key': 'value'}
                attributes:
                    description:
                        - Certificate attributes.
                    type: complex
                    returned: always
                    contains:
                        created:
                            description:
                                - Creation datetime.
                            returned: always
                            type: str
                            sample: "2025-01-14T09:41:20+00:00"
                        not_before:
                            description:
                                - Not before datetime.
                            type: str
                            sample: "2025-02-14T09:41:20+00:00"
                        expires:
                            description:
                                - Expiration datetime.
                            type: str
                            sample: "2025-03-14T09:41:20+00:00
                        updated:
                            description:
                                - Update datetime.
                            returned: always
                            type: str
                            sample: "2025-01-15T09:41:20+00:00"
                        enabled:
                            description:
                                - Indicate whether the certificate is enabled.
                            returned: always
                            type: str
                            sample: true
                        recovery_level:
                            description:
                                - Reflects the deletion recovery level currently in effect for certificates in the current vault.
                                - If it contains 'Purgeable' the certificate can be permanently deleted by a privileged user,
                                - Otherwise, only the system can purge the certificate, at the end of the retention interval.
                            returned: always
                            type: str
                            sample: Recoverable+Purgeable
'''

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase

try:
    from azure.keyvault.certificates import CertificateClient
    from azure.core.exceptions import ResourceNotFoundError
    import base64
except ImportError:
    # This is handled in azure_rm_common
    pass


def certificatebundle_to_dict(certificate):
    response = dict(policy=dict(), properties=dict(), cer=None)
    if certificate.cer is not None:
        response['cer'] = str(certificate.cer)
    if certificate.policy is not None:
        response['policy']['issuer_name'] = certificate.policy._issuer_name
        response['policy']['subject'] = certificate.policy._subject
        response['policy']['exportable'] = certificate.policy._exportable
        response['policy']['key_type'] = certificate.policy._key_type
        response['policy']['reuse_key'] = certificate.policy._reuse_key
        response['policy']['key_curve_name'] = certificate.policy._key_curve_name
        response['policy']['enhanced_key_usage'] = certificate.policy._enhanced_key_usage
        response['policy']['key_usage'] = certificate.policy._key_usage
        response['policy']['content_type'] = certificate.policy._content_type
        response['policy']['validity_in_months'] = certificate.policy._validity_in_months
        response['policy']['certificate_type'] = certificate.policy._certificate_type
        response['policy']['certificate_transparency'] = certificate.policy._certificate_transparency
        response['policy']['san_emails'] = certificate.policy._san_emails
        response['policy']['san_dns_names'] = certificate.policy._san_dns_names
        response['policy']['san_user_principal_names'] = certificate.policy._san_user_principal_names
        response['policy']['attributes'] = dict()
        if certificate.policy._attributes is not None:
            response['policy']['attributes']['enabled'] = certificate.policy._attributes.enabled
            response['policy']['attributes']['not_before'] = certificate.policy._attributes.not_before
            response['policy']['attributes']['expires'] = certificate.policy._attributes.expires
            response['policy']['attributes']['created'] = certificate.policy._attributes.created
            response['policy']['attributes']['updated'] = certificate.policy._attributes.updated
            response['policy']['attributes']['recoverable_days'] = certificate.policy._attributes.recoverable_days
            response['policy']['attributes']['recovery_level'] = certificate.policy._attributes.recovery_level
        else:
            response['policy']['attributes'] = None
        if certificate.policy._lifetime_actions is not None:
            response['policy']['lifetime_actions'] = []
            for item in certificate.policy._lifetime_actions:
                response['policy']['lifetime_actions'].append(dict(action=item.action,
                                                                   lifetime_percentage=item.lifetime_percentage,
                                                                   days_before_expiry=item.days_before_expiry))
        else:
            response['policy']['lifetime_actions'] = None
    else:
        response['policy'] = None

    if certificate.properties is not None:
        response['properties']['attributes'] = dict(enabled=certificate.properties._attributes.enabled,
                                                    not_before=certificate.properties._attributes.not_before,
                                                    expires=certificate.properties._attributes.expires,
                                                    created=certificate.properties._attributes.created,
                                                    updated=certificate.properties._attributes.updated,
                                                    recovery_level=certificate.properties._attributes.recovery_level)
        response['properties']['id'] = certificate.properties._id
        response['properties']['vault_id'] = certificate.properties._vault_id.vault_url if certificate.properties._vault_id is not None else None
        response['properties']['x509_thumbprint'] = base64.b64encode(certificate.properties._x509_thumbprint).decode('utf-8')
        response['properties']['tags'] = certificate.properties._tags
    else:
        response['properties'] = None

    return response


def policy_bundle_to_dict(policy):
    policy = dict()
    if policy is not None:
        policy['issuer_name'] = policy._issuer_name
        policy['subject'] = policy._subject
        policy['exportable'] = policy._exportable
        policy['key_type'] = policy._key_type
        policy['key_size'] = policy._key_size
        policy['reuse_key'] = policy._reuse_key
        policy['key_curve_name'] = policy._key_curve_name
        policy['enhanced_key_usage'] = policy._enhanced_key_usage
        policy['key_usage'] = policy._key_usage
        policy['content_type'] = policy._content_type
        policy['validity_in_months'] = policy._validity_in_months
        policy['certificate_type'] = policy._certificate_type
        policy['certificate_transparency'] = policy._certificate_transparency
        policy['san_emails'] = policy._san_emails
        policy['san_dns_names'] = policy._san_dns_names
        policy['san_user_principal_names'] = policy._san_user_principal_names
        policy['attributes'] = dict()
        if policy._attributes is not None:
            policy['attributes']['enabled'] = policy._attributes.enabled
            policy['attributes']['not_before'] = policy._attributes.not_before
            policy['attributes']['expires'] = policy._attributes.expires
            policy['attributes']['created'] = policy._attributes.created
            policy['attributes']['updated'] = policy._attributes.updated
            policy['attributes']['recoverable_days'] = policy._attributes.recoverable_days
            policy['attributes']['recovery_level'] = policy._attributes.recovery_level
        else:
            policy['attributes'] = None
        if policy._lifetime_actions is not None:
            policy['lifetime_actions'] = []
            for item in policy._lifetime_actions:
                policy['lifetime_actions'].append(dict(action=item.action,
                                                                   lifetime_percentage=item.lifetime_percentage,
                                                                   days_before_expiry=item.days_before_expiry))
        else:
            policy['lifetime_actions'] = None
    else:
        policy = None

    return policy


def deleted_certificatebundle_to_dict(certificate):
    response = dict(policy=dict(), properties=dict(), cer=None)
    response['recovery_id'] = certificate._recovery_id
    response['scheduled_purge_date'] = certificate._scheduled_purge_date
    response['deleted_on'] = certificate._deleted_on
    if certificate.cer is not None:
        response['cer'] = str(certificate.cer)
    if certificate.policy is not None:
        response['policy']['issuer_name'] = certificate.policy._issuer_name
        response['policy']['subject'] = certificate.policy._subject
        response['policy']['exportable'] = certificate.policy._exportable
        response['policy']['key_type'] = certificate.policy._key_type
        response['policy']['key_size'] = certificate.policy._key_size
        response['policy']['reuse_key'] = certificate.policy._reuse_key
        response['policy']['key_curve_name'] = certificate.policy._key_curve_name
        response['policy']['enhanced_key_usage'] = certificate.policy._enhanced_key_usage
        response['policy']['key_usage'] = certificate.policy._key_usage
        response['policy']['content_type'] = certificate.policy._content_type
        response['policy']['validity_in_months'] = certificate.policy._validity_in_months
        response['policy']['certificate_type'] = certificate.policy._certificate_type
        response['policy']['certificate_transparency'] = certificate.policy._certificate_transparency
        response['policy']['san_emails'] = certificate.policy._san_emails
        response['policy']['san_dns_names'] = certificate.policy._san_dns_names
        response['policy']['san_user_principal_names'] = certificate.policy._san_user_principal_names
        response['policy']['attributes'] = dict()
        if certificate.policy._attributes is not None:
            response['policy']['attributes']['enabled'] = certificate.policy._attributes.enabled
            response['policy']['attributes']['not_before'] = certificate.policy._attributes.not_before
            response['policy']['attributes']['expires'] = certificate.policy._attributes.expires
            response['policy']['attributes']['created'] = certificate.policy._attributes.created
            response['policy']['attributes']['updated'] = certificate.policy._attributes.updated
            response['policy']['attributes']['recoverable_days'] = certificate.policy._attributes.recoverable_days
            response['policy']['attributes']['recovery_level'] = certificate.policy._attributes.recovery_level
        else:
            response['policy']['attributes'] = None
        if certificate.policy._lifetime_actions is not None:
            response['policy']['lifetime_actions'] = []
            for item in certificate.policy._lifetime_actions:
                response['policy']['lifetime_actions'].append(dict(action=item.action,
                                                                   lifetime_percentage=item.lifetime_percentage,
                                                                   days_before_expiry=item.days_before_expiry))
        else:
            response['policy']['lifetime_actions'] = None
    else:
        response['policy'] = None

    if certificate.properties is not None:
        response['properties']['attributes'] = dict(enabled=certificate.properties._attributes.enabled,
                                                    not_before=certificate.properties._attributes.not_before,
                                                    expires=certificate.properties._attributes.expires,
                                                    created=certificate.properties._attributes.created,
                                                    updated=certificate.properties._attributes.updated,
                                                    recovery_level=certificate.properties._attributes.recovery_level)
        response['properties']['id'] = certificate.properties._id
        response['properties']['vault_id'] = certificate.properties._vault_id.vault_url if certificate.properties._vault_id is not None else None
        response['properties']['x509_thumbprint'] = base64.b64encode(certificate.properties._x509_thumbprint).decode('utf-8')
        response['properties']['tags'] = certificate.properties._tags
    else:
        response['properties'] = None
    return response


policy_spec = dict(
    issuer_name=dict(type='str'),
    subject=dict(type='str'),
    exportable=dict(type='bool',),
    key_type=dict(type='str', choices=['EC', 'EC_HSM', 'RSA', 'RSA-HSM', 'oct', 'oct-HSM']),
    key_size=dict(type='int'),
    reuse_key=dict(type='bool',),
    key_curve_name=dict(type='str', choices=['P-256', 'P-384', 'P-521', 'P-256K']),
    enhanced_key_usage=dict(type='list', element='str'),
    key_usage=dict(
        type='list',
        elements='str',
        choices=['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly']
    ),
    content_type=dict(type='str', choices=['application/x-pkcs12', 'application/x-pem-file']),
    validity_in_months=dict(type='int',),
    certificate_type=dict(type='str'),
    certificate_transparency=dict(type='bool'),
    san_emails=dict(type='list', elements='str'),
    san_dns_names=dict(type='list', elements='str'),
    san_user_principal_names=dict(type='list', elements='str'),
    lifetime_actions=dict(
        type='dict',
        options=dict(
            action=dict(type='str', choices=['EmailContacts', 'AutoRenew']),
            lifetime_percentage=dict(type='int'),
            days_before_expiry=dict(type='int')
        )
    ),
)


class AzureRMKeyVaultCertificate(AzureRMModuleBase):
    def __init__(self):
        self.module_arg_spec = dict(name=dict(type='str'),
                                    vault_uri=dict(type='str', required=True),
                                    policy=dict(type='dict', options=policy_spec),
                                    enabled=dict(type='bool'),
                                    password=dict(type='str', no_log=True),
                                    cert=dict(type='str'),
                                    x509_certificates=dict(type='list', elements='str'),
                                    backup=dict(type='str'),
                                    state=dict(
                                        type='str',
                                        required=True,
                                        choices=['generate', 'import', 'delete', 'purge', 'backup', 'restore', 'recover', 'merge']),
                                   )
        self.vault_uri = None
        self.name = None
        self.policy = None
        self.enabled = None
        self.cert = None
        self.password = None
        self.backup = None
        self.x509_certificates = None

        self.results = dict(changed=False)
        self._client = None

        super(AzureRMKeyVaultCertificate,
              self).__init__(derived_arg_spec=self.module_arg_spec,
                             supports_check_mode=True,
                             supports_tags=True,
                             facts_module=False)

    def exec_module(self, **kwargs):
        """Main module execution method"""

        for certificate in list(self.module_arg_spec.keys()) + ['tags']:
            if hasattr(self, certificate):
                setattr(self, certificate, kwargs[certificate])

        self._client = self.get_keyvault_client()
        changed = False
        reponse = None

        del_response = self.get_deleted_certificate()
        response = self.get_certificate()

        if self.state == 'delete':
            if del_response is not None:
                changed = True
                if not self.check_mode:
                    response = self.del_certificate()
        elif self.state == 'purge':
            if del_response is not None:
                changed = True
                if not self.check_mode:
                    response = self.purge_certificate()
        elif self.state == 'backup':
            if response is not None:
                changed = True
                if not self.check_mode:
                    response = self.backup_certificate()
        elif self.state == 'restore':
            if response is not None:
                changed = True
                if not self.check_mode:
                    response = self.restore_certificate()
        elif self.state == 'merge':
            if response is not None:
                changed = True
                if not self.check_mode:
                    response = self.merge_certificate()
            else:
                self.fail("The certificate not exist {0}".format(self.name))
        elif self.state == 'recover':
            if del_response is not None:
                changed = True
                if not self.check_mode:
                    response = self.recover_certificate()
        else:
            if response is not None:
                if self.policy is not None and response['policy'] != self.policy:
                    changed = True
                    if not self.check_mode:
                        response['policy'] = self.update_certificate_policy()
                update_tags, self.tags = self.update_tags(response['properties']['tags'])
                if update_tags or (self.enabled is not None and bool(self.enabled) != bool(response['properties']['enabled'])):
                    changed = True
                    if not self.check_mode:
                        response = self.update_certificate_properties()
            else:
                changed = True
                if self.state == 'import':
                    if not self.check_mode:
                        response = self.import_certificate()
                else:
                    if not self.check_mode:
                        response = self.create_certificate()

        self.results['changed'] = changed
        self.results['certificate'] = response

        return self.results

    def get_keyvault_client(self):

        return CertificateClient(vault_url=self.vault_uri, credential=self.azure_auth.azure_credential_track2)

    def get_certificate(self):
        '''
        Gets the certificate fact of the specified in key vault.

        :return: deserialized certificate state dictionary
        '''
        self.log("Get the certificate {0}".format(self.name))

        results = []
        try:
            response = self._client.get_certificate(certificate_name=self.name)

            if response:
                response = certificatebundle_to_dict(response)
                if self.has_tags(response['properties']['tags'], self.tags):
                    self.log("Response : {0}".format(response))
                    results.append(response)

        except ResourceNotFoundError as ec:
            self.log("Did not find the key vault certificate {0}: {1}".format(self.name, str(ec)))
        except Exception as ec2:
            self.fail("Find the key vault certificate got exception, exception as {0}".format(str(ec2)))
        return results

    def create_certificate(self):
        '''
        Create the certificate in key vault.

        :return: deserialized certificate state dictionary
        '''
        self.log("Create the certificate {0}".format(self.name))

        try:
            response = self._client.begin_create_certificate(certificate_name=self.name,
                                                             policy=self.policy,
                                                             enabled=self.enabled,
                                                             tags=self.tags)

            if response:
                response = certificatebundle_to_dict(response)
                return response

        except Exception as ec:
            self.log("Did not create the key vault certificate {0}: {1}".format(self.name, str(ec)))

    def import_certificate(self):
        '''
        Import the certificate in key vault.

        :return: deserialized certificate state dictionary
        '''
        self.log("Import the certificate {0}".format(self.name))

        try:
            response = self._client.import_certificate(certificate_name=self.name,
                                                       certificate_bytes=self.cert,
                                                       policy=self.policy,
                                                       enabled=self.enabled,
                                                       password=self.password,
                                                       tags=self.tags)

            if response:
                response = certificatebundle_to_dict(response)
                return response

        except Exception as ec:
            self.log("Did not import the key vault certificate {0}: {1}".format(self.name, str(ec)))

    def delete_certificate(self):
        '''
        Delete the certificate in key vault.

        :return: deserialized certificate state dictionary
        '''
        self.log("Delete the certificate {0}".format(self.name))

        try:
            response = self._client.begin_delete_certificate(certificate_name=self.name)
            if response is not None:
                return deleted_certificatebundle_to_dict(response)

        except Exception as ec:
            self.log("Did not delete the key vault certificate {0}: {1}".format(self.name, str(ec)))

    def get_deleted_certificate(self):
        '''
        Gets the deleted certificate facts in key vault.

        :return: deserialized certificate state dictionary
        '''
        self.log("Get the certificate {0}".format(self.name))

        results = []
        try:
            response = self._client.get_deleted_certificate(certificate_name=self.name)

            if response:
                response = deleted_certificatebundle_to_dict(response)
                if self.has_tags(response['properties'].get('tags'), self.tags):
                    self.log("Response : {0}".format(response))
                    results.append(response)

        except ResourceNotFoundError as ec:
            self.log("Did not find the key vault certificate {0}: {1}".format(
                self.name, str(ec)))
        except Exception as ec2:
            self.fail("Find the key vault certificate got exception, exception as {0}".format(str(ec2)))
        return results

    def recover_certificate(self):
        '''
        Recover the certificate in key vault.

        :return: deserialized certificate state dictionary
        '''
        self.log("Recover the certificate {0}".format(self.name))

        try:
            response = self._client.begin_recover_deleted_certificate(certificate_name=self.name)
            if response is not None:
                return certificatebundle_to_dict(response)

        except Exception as ec:
            self.log("Did not recover the key vault certificate {0}: {1}".format(self.name, str(ec)))

    def backup_certificate(self):
        '''
        Backup the certificate in key vault.
        '''
        self.log("Backup the certificate {0}".format(self.name))

        try:
            return self._client.backup_certificate(certificate_name=self.name)

        except Exception as ec:
            self.log("Did not backup the key vault certificate {0}: {1}".format(self.name, str(ec)))

    def restore_certificate(self):
        '''
        Restore the certificate in key vault.

        :return: deserialized certificate state dictionary
        '''
        self.log("Restore the certificate {0}".format(self.name))

        try:
            response = self._client.restore_certificate_backup(backup=self.backup)
            if response is not None:
                return certificatebundle_to_dict(response)

        except Exception as ec:
            self.log("Did not restore the key vault certificate {0}: {1}".format(self.name, str(ec)))

    def merge_certificate(self):
        '''
        Merge the certificate in key vault.

        :return: deserialized certificate state dictionary
        '''
        self.log("Merge the certificate {0}".format(self.name))

        try:
            response = self._client.merge_certificate(certificate_name=self.name,
                                                      enabled=self.enabled,
                                                      tags=self.tags,
                                                      x509_certificates=self.x509_certificates)
                                                      
            if response is not None:
                return certificatebundle_to_dict(response)

    def update_certificate_properties(self):
        '''
        Update the certificate properties in key vault.

        :return: deserialized certificate state dictionary
        '''
        self.log("Merge the certificate {0}".format(self.name))

        try:
            response = self._client.update_certificate_properties(certificate_name=self.name,
                                                                  version=None,
                                                                  enabled=self.enabled,
                                                                  tags=self.tags)
                                                      
            if response is not None:
                return certificatebundle_to_dict(response)

    def update_certificate_policy(self):
        '''
        Update the certificate policy in key vault.

        :return: deserialized certificate state dictionary
        '''
        self.log("Update the certificate policy {0}".format(self.name))

        try:
            response = self._client.update_certificate_policy(certificate_name=self.name,
                                                              policy=self.policy)
                                                      
            if response is not None:
                return policy_bundle_to_dict(response)

        except Exception as ec:
            self.log("Did not update policy in the key vault certificate {0}: {1}".format(self.name, str(ec)))

    def purge_certificate(self):
        '''
        Permanently deletes a deleted certificate.
        '''
        self.log("Permanently deletes the certificate {0}".format(self.name))

        try:
            self._client.purge_deleted_certificate(certificate_name=self.name)

        except Exception as ec:
            self.log("Did not permanently delete the key vault certificate {0}: {1}".format(self.name, str(ec)))


def main():
    """Main execution"""
    AzureRMKeyVaultCertificate()


if __name__ == '__main__':
    main()
