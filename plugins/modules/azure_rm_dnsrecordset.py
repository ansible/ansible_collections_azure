#!/usr/bin/python
#
# Copyright (c) 2017 Obezimnaka Boms, <t-ozboms@microsoft.com>
# Copyright (c) 2017 Ansible Project
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: azure_rm_dnsrecordset

version_added: "0.1.0"

short_description: Create, delete and update DNS record sets and records

description:
    - Creates, deletes, and updates DNS records sets and records within an existing Azure DNS Zone.

options:
    resource_group:
        description:
            - Name of resource group.
        required: true
        type: str
    zone_name:
        description:
            - Name of the existing DNS zone in which to manage the record set.
        required: true
        type: str
    relative_name:
        description:
            - Relative name of the record set.
        required: true
        type: str
    record_type:
        description:
            - The type of record set to create or delete.
        choices:
            - A
            - AAAA
            - CNAME
            - MX
            - NS
            - SRV
            - TXT
            - PTR
            - CAA
            - SOA
            - DS
            - TLSA
            - NAPTR
        required: true
        type: str
    record_mode:
        description:
            - Whether existing record values not sent to the module should be purged.
        default: purge
        type: str
        choices:
            - append
            - purge
    state:
        description:
            - Assert the state of the record set. Use C(present) to create or update and C(absent) to delete.
        default: present
        type: str
        choices:
            - absent
            - present
    metadata:
        description:
            - The metadata tags for the record sets.
        type: dict
    append_metadata:
        description: Whether metadata should be appended or not
        type: bool
        default: True
    time_to_live:
        description:
            - Time to live of the record set in seconds.
        default: 3600
        type: int
    target_resource:
        description:
            - A reference to an azure resource from where the dns resource value is taken.
            - This parameter can only be applied to I(record_type=A), I(record_type=AAAA) and I(record_type=CNAME).
            - It cannot configure both I(target_resource) and I(records).
        type: dict
        suboptions:
            id:
                description:
                    - A reference to a another resource ID.
                    - Sample as C("/subscriptions/xxx-xxx/resourceGroups/rg_name/providers/Microsoft.Network/publicIPAddresses/pip01")
                type: str
    records:
        description:
            - List of records to be created depending on the type of record (set).
            - It cannot configure both I(target_resource) and I(records).
            - This parameter must be set when I(record_type=A), I(record_type=AAAA) or I(record_type=CNAME).
        type: list
        elements: dict
        suboptions:
            preference:
                description:
                    - Used for creating an C(MX) record set/records.
            priority:
                description:
                   - Used for creating an C(SRV) record set/records.
            weight:
                description:
                    - Used for creating an C(SRV) record set/records.
            port:
                description:
                    - Used for creating an C(SRV) record set/records.
            entry:
                description:
                    - Primary data value for all record types.
            email:
                description:
                    - Used for creating an C(SOA) record set/records.
                    - The email contact for this SOA record.
            serial_number:
                description:
                    - Used for creating an C(SOA) record set/records.
                    - The serial number for this SOA record.
            refresh_time:
                description:
                    - Used for creating an C(SOA) record set/records.
                    - The refresh value for this SOA record.
            retry_time:
                description:
                    - Used for creating an C(SOA) record set/records.
                    - The retry time for this SOA record.
            expire_time:
                description:
                    - Used for creating an C(SOA) record set/records.
                    - The expire time for this SOA record.
            minimum_ttl:
                description:
                    - Used for creating an C(SOA) record set/records.
                    - The minimum value for this SOA record. By convention this is used to determine the negative caching duration.
            key_tag:
                description:
                    - Used for creating an C(DS) record set/records.
                    - The key tag value is used to determine which DNSKEY Resource Record is used for signature verification.
            algorithm:
                description:
                    - Used for creating an C(DS) record set/records.
                    - The security algorithm type represents the standard security algorithm number of the DNSKEY Resource Record.
            digest:
                description:
                    - Used for creating an C(DS) record set/records.
                    - The digest entity.
                suboptions:
                    algorithm_type:
                        description:
                            - The digest algorithm type represents the standard digest algorithm number used to construct the digest
                    value:
                        description:
                            - The digest value is a cryptographic hash value of the referenced DNSKEY Resource Record.
            usage:
                description:
                    - Used for creating an C(TLSA) record set/records.
                    - The usage specifies the provided association that will be used to match the certificate presented in the TLS handshake.
            selector:
                description:
                    - Used for creating an C(TLSA) record set/records.
                    - The selector specifies which part of the TLS certificate presented by the server will be matched against the association data.
            matching_type:
                description:
                    - Used for creating an C(TLSA) record set/records.
                    - The matching type specifies how the certificate association is presented.
            cert_association_data:
                description:
                    - Used for creating an C(TLSA) record set/records.
                    - This specifies the certificate association data to be matched.
            order:
                description:
                    - Used for creating an C(NAPTR) record set/records.
                    - The order in which the NAPTR records MUST be processed in order to accurately represent the ordered list of rules.
                    - The ordering is from lowest to highest. Valid values 0-65535.
            flags:
                description:
                    - Used for creating an C(NAPTR) record set/records.
                    - The flags specific to DDDS applications.
                    - Values currently defined in RFC 3404 are uppercase and lowercase letters "A", "P", "S", and "U", and the empty string.
            services:
                description:
                    - Used for creating an C(NAPTR) record set/records.
                    - The services specific to DDDS applications. Enclose Services in quotation marks.
            regexp:
                description:
                    - Used for creating an C(NAPTR) record set/records.
                    - The regular expression that the DDDS application uses to convert an input value into an output value.
                    - Specify either a value for 'regexp' or a value for 'replacement'.
            replacement:
                description:
                    - Used for creating an C(NAPTR) record set/records.
                    - The replacement is a fully qualified domain name (FQDN) of the next domain name that you want the DDDS application to submit a DNS query for.
                    - The DDDS application replaces the input value with the value specified for replacement.
                    - Specify either a value for 'regexp' or a value for 'replacement'.
                    - If you specify a value for 'regexp', specify a dot (.) for 'replacement'.

extends_documentation_fragment:
    - azure.azcollection.azure
    - azure.azcollection.azure_tags

author:
    - Obezimnaka Boms (@ozboms)
    - Matt Davis (@nitzmahone)
'''

EXAMPLES = '''

- name: ensure an "A" record set with multiple records
  azure_rm_dnsrecordset:
    resource_group: myResourceGroup
    relative_name: www
    zone_name: testing.com
    record_type: A
    records:
      - entry: 192.168.100.101
      - entry: 192.168.100.102
      - entry: 192.168.100.103

- name: delete a record set
  azure_rm_dnsrecordset:
    resource_group: myResourceGroup
    record_type: A
    relative_name: www
    zone_name: testing.com
    state: absent

- name: create A record set with metadata information
  azure_rm_dnsrecordset:
    resource_group: myResourceGroup
    relative_name: www
    zone_name: zone1.com
    record_type: A
    records:
      - entry: 192.168.100.104
    metadata:
      key1: "value1"

- name: Create A dns record set  with target_resource
  azure_rm_dnsrecordset:
    resource_group: myResourceGroup
    relative_name: www
    zone_name: zone1.com
    record_type: A
    target_resource:
      id: "/subscriptions/xxx-xxx/resourceGroups/v-xisuRG02/providers/Microsoft.Network/publicIPAddresses/pip01"

- name: create multiple "A" record sets with multiple records
  azure_rm_dnsrecordset:
    resource_group: myResourceGroup
    zone_name: testing.com
    relative_name: "{{ item.name }}"
    record_type: "{{ item.type }}"
    records: "{{ item.records }}"
  with_items:
    - {name: 'servera', type: 'A', records: [{entry: '10.10.10.20'}, {entry: '10.10.10.21'}]}
    - {name: 'serverb', type: 'A', records: [{entry: '10.10.10.30'}, {entry: '10.10.10.41'}]}
    - {name: 'serverc', type: 'A', records: [{entry: '10.10.10.40'}, {entry: '10.10.10.41'}]}

- name: create SRV records in a new record set
  azure_rm_dnsrecordset:
    resource_group: myResourceGroup
    relative_name: _sip._tcp.testing.com
    zone_name: testing.com
    time_to_live: 7200
    record_type: SRV
    records:
      - entry: sip.testing.com
        preference: 10
        priority: 20
        weight: 10
        port: 5060

- name: create PTR record in a new record set
  azure_rm_dnsrecordset:
    resource_group: myResourceGroup
    relative_name: 192.168.100.101.in-addr.arpa
    zone_name: testing.com
    record_type: PTR
    records:
      - entry: servera.testing.com

- name: create TXT record in a new record set
  azure_rm_dnsrecordset:
    resource_group: myResourceGroup
    relative_name: mail.testing.com
    zone_name: testing.com
    record_type: TXT
    records:
      - entry: 'v=spf1 a -all'

- name: Update SOA record
  azure_rm_dnsrecordset:
    resource_group: myResourceGroup
    relative_name: "@"
    zone_name: testing.com
    record_type: SOA
    records:
      - host: ns1-99.example.com.
        email: azuredns-hostmaster99.example.com
        serial_number: 99
        refresh_time: 3699
        retry_time: 399
        expire_time: 2419299
        minimum_ttl: 399
'''

RETURN = '''
state:
    description:
        - Current state of the DNS record set.
    returned: always
    type: complex
    contains:
        id:
            description:
                - The DNS record set ID.
            returned: always
            type: str
            sample: "/subscriptions/xxxx......xxx/resourceGroups/v-xisuRG/providers/Microsoft.Network/dnszones/b57dc95985712e4523282.com/A/www"
        name:
            description:
                - Relate name of the record set.
            returned: always
            type: str
            sample: 'www'
        fqdn:
            description:
                - Fully qualified domain name of the record set.
            returned: always
            type: str
            sample: www.b57dc95985712e4523282.com
        etag:
            description:
                - The etag of the record set.
            returned: always
            type: str
            sample: 692c3e92-a618-46fc-aecd-8f888807cd6c
        provisioning_state:
            description:
                - The DNS record set state.
            returned: always
            type: str
            sample: Succeeded
        target_resource:
            description:
                - The target resource of the record set.
            returned: always
            type: dict
            sample: {}
        ttl:
            description:
                - The TTL(time-to-live) of the records in the records set.
            returned: always
            type: int
            sample: 3600
        type:
            description:
                - The type of DNS record in this record set.
            returned: always
            type: str
            sample: A
        arecords:
            description:
                - A list of records in the record set.
            returned: always
            type: list
            sample: [
            {
                "ipv4_address": "192.0.2.2"
            },
            {
                "ipv4_address": "192.0.2.4"
            },
            {
                "ipv4_address": "192.0.2.8"
            }
        ]
'''

import copy

from ansible.module_utils.basic import _load_params
from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase, HAS_AZURE

try:
    from azure.core.exceptions import ResourceNotFoundError
except ImportError:
    # This is handled in azure_rm_common
    pass


RECORD_ARGSPECS = dict(
    A=dict(
        ipv4_address=dict(type='str', required=True, aliases=['entry'])
    ),
    AAAA=dict(
        ipv6_address=dict(type='str', required=True, aliases=['entry'])
    ),
    CNAME=dict(
        cname=dict(type='str', required=True, aliases=['entry'])
    ),
    MX=dict(
        preference=dict(type='int', required=True),
        exchange=dict(type='str', required=True, aliases=['entry'])
    ),
    NS=dict(
        nsdname=dict(type='str', required=True, aliases=['entry'])
    ),
    PTR=dict(
        ptrdname=dict(type='str', required=True, aliases=['entry'])
    ),
    SRV=dict(
        priority=dict(type='int', required=True),
        port=dict(type='int', required=True),
        weight=dict(type='int', required=True),
        target=dict(type='str', required=True, aliases=['entry'])
    ),
    TXT=dict(
        value=dict(type='list', required=True, aliases=['entry'])
    ),
    SOA=dict(
        host=dict(type='str', aliases=['entry']),
        email=dict(type='str'),
        serial_number=dict(type='int'),
        refresh_time=dict(type='int'),
        retry_time=dict(type='int'),
        expire_time=dict(type='int'),
        minimum_ttl=dict(type='int')
    ),
    CAA=dict(
        value=dict(type='str', aliases=['entry']),
        flags=dict(type='int'),
        tag=dict(type='str')
    ),
    DS=dict(
        key_tag=dict(type='int'),
        algorithm=dict(type='int'),
        digest=dict(
            algorithm_type=dict(type='str'),
            value=dict(type='str')
        )
    ),
    TLSA=dict(
        usage=dict(type='int'),
        selector=dict(type='int'),
        cert_association_data=dict(type='str')
    ),
    NAPTR=dict(
        order=dict(type='int'),
        preference=dict(type='int'),
        flags=dict(type='str'),
        services=dict(type='str'),
        regexp=dict(type='str'),
        replacement=dict(type='str')
    )
    # FUTURE: ensure all record types are supported (see https://github.com/Azure/azure-sdk-for-python/tree/master/azure-mgmt-dns/azure/mgmt/dns/models)
)

RECORDSET_VALUE_MAP = dict(
    A=dict(attrname='a_records', classobj='ARecord', is_list=True),
    AAAA=dict(attrname='aaaa_records', classobj='AaaaRecord', is_list=True),
    CNAME=dict(attrname='cname_record', classobj='CnameRecord', is_list=False),
    MX=dict(attrname='mx_records', classobj='MxRecord', is_list=True),
    NS=dict(attrname='ns_records', classobj='NsRecord', is_list=True),
    PTR=dict(attrname='ptr_records', classobj='PtrRecord', is_list=True),
    SRV=dict(attrname='srv_records', classobj='SrvRecord', is_list=True),
    TXT=dict(attrname='txt_records', classobj='TxtRecord', is_list=True),
    SOA=dict(attrname='soa_record', classobj='SoaRecord', is_list=False),
    CAA=dict(attrname='caa_records', classobj='CaaRecord', is_list=True),
    DS=dict(attrname='ds_records', classobj='DsRecord', is_list=True),
    TLSA=dict(attrname='tlsa_records', classobj='TlsaRecord', is_list=True),
    NAPTR=dict(attrname='naptr_records', classobj='NaptrRecord', is_list=True)
    # FUTURE: add missing record types from https://github.com/Azure/azure-sdk-for-python/blob/master/azure-mgmt-dns/azure/mgmt/dns/models/record_set.py
) if HAS_AZURE else {}


class AzureRMRecordSet(AzureRMModuleBase):

    def __init__(self):

        # we're doing two-pass arg validation, sample and store the args internally to allow this
        _load_params()

        self.module_arg_spec = dict(
            resource_group=dict(type='str', required=True),
            relative_name=dict(type='str', required=True),
            zone_name=dict(type='str', required=True),
            record_type=dict(choices=['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SRV', 'TXT', 'SOA', 'CAA', 'DS', 'TLSA', 'NAPTR'],
                             required=True,
                             type='str'),
            record_mode=dict(type='str', choices=['append', 'purge'], default='purge'),
            state=dict(choices=['present', 'absent'], default='present', type='str'),
            time_to_live=dict(type='int', default=3600),
            records=dict(type='list', elements='dict'),
            metadata=dict(type='dict'),
            append_metadata=dict(type='bool', default=True),
            target_resource=dict(
                type='dict',
                options=dict(
                    id=dict(type='str')
                )
            ),
        )


        self.results = dict(
            changed=False
        )

        mutually_exclusive = [['target_resource', 'records']]
        # first-pass arg validation so we can get the record type- skip exec_module
        super(AzureRMRecordSet, self).__init__(self.module_arg_spec, mutually_exclusive=mutually_exclusive, supports_check_mode=True, skip_exec=True)

        # look up the right subspec and metadata
        record_subspec = RECORD_ARGSPECS.get(self.module.params['record_type'])

        # patch the right record shape onto the argspec
        self.module_arg_spec['records']['options'] = record_subspec

        self.resource_group = None
        self.relative_name = None
        self.zone_name = None
        self.record_type = None
        self.record_mode = None
        self.state = None
        self.time_to_live = None
        self.records = None
        self.metadata = None
        self.target_resource = None

        # rerun validation and actually run the module this time
        super(AzureRMRecordSet, self).__init__(self.module_arg_spec, mutually_exclusive=mutually_exclusive, supports_check_mode=True)

    def exec_module(self, **kwargs):
        for key in self.module_arg_spec.keys():
            setattr(self, key, kwargs[key])

        zone = self.dns_client.zones.get(self.resource_group, self.zone_name)
        if not zone:
            self.fail('The zone {0} does not exist in the resource group {1}'.format(self.zone_name, self.resource_group))

        try:
            self.log('Fetching Record Set {0}'.format(self.relative_name))
            record_set = self.dns_client.record_sets.get(self.resource_group, self.zone_name, self.relative_name, self.record_type)
            self.results['state'] = self.recordset_to_dict(record_set)
        except ResourceNotFoundError:
            record_set = None
            # FUTURE: fail on anything other than ResourceNotFound

        record_type_metadata = RECORDSET_VALUE_MAP.get(self.record_type)

        # FUTURE: implement diff mode

        if self.state == 'present':
            # convert the input records to SDK objects
            self.input_sdk_records = self.create_sdk_records(self.records, self.record_type)

            if not record_set:
                changed = True
            else:
                # and use it to get the type-specific records
                server_records = getattr(record_set, record_type_metadata.get('attrname'))

                # compare the input records to the server records
                self.input_sdk_records, changed = self.records_changed(self.input_sdk_records, server_records)

                # also check top-level recordset properties
                changed |= record_set.ttl != self.time_to_live

                old_metadata = self.results['state']['metadata'] if 'metadata' in self.results['state'] else dict()
                update_metadata, self.results['state']['metadata'] = self.update_metadata(old_metadata)
                if update_metadata:
                    changed = True
                self.metadata = self.results['state']['metadata']

                if self.target_resource is not None:
                    if not self.results['state'].get('target_resource'):
                        changed = True
                    else:
                        if self.target_resource['id'].lower() != self.results['state']['target_resource']['id'].lower():
                            changed = True

            self.results['changed'] |= changed

        elif self.state == 'absent':
            if record_set:
                self.results['changed'] = True

        if self.check_mode:
            return self.results

        if self.results['changed']:
            if self.state == 'present':
                record_set_args = dict(
                    ttl=self.time_to_live,
                    #target_resource=self.target_resource
                )

                record_set_args[record_type_metadata['attrname']] = self.input_sdk_records if record_type_metadata['is_list'] else self.input_sdk_records[0]

                record_set = self.dns_models.RecordSet(**record_set_args)
                if self.metadata:
                    record_set.metadata = self.metadata
                if self.target_resource:
                    record_set.target_resource = self.dns_models.SubResource(id=self.target_resource['id'])

                self.results['state'] = self.create_or_update(record_set)

            elif self.state == 'absent':
                # delete record set
                self.delete_record_set()

        return self.results

    def create_or_update(self, record_set):
        try:
            record_set = self.dns_client.record_sets.create_or_update(resource_group_name=self.resource_group,
                                                                      zone_name=self.zone_name,
                                                                      relative_record_set_name=self.relative_name,
                                                                      record_type=self.record_type,
                                                                      parameters=record_set)
            return self.recordset_to_dict(record_set)
        except Exception as exc:
            self.fail("Error creating or updating dns record {0} - {1}".format(self.relative_name, exc.message or str(exc)))

    def delete_record_set(self):
        try:
            # delete the record set
            self.dns_client.record_sets.delete(resource_group_name=self.resource_group,
                                               zone_name=self.zone_name,
                                               relative_record_set_name=self.relative_name,
                                               record_type=self.record_type)
        except Exception as exc:
            self.fail("Error deleting record set {0} - {1}".format(self.relative_name, exc.message or str(exc)))
        return None

    def create_sdk_records(self, input_records, record_type):
        record = RECORDSET_VALUE_MAP.get(record_type)
        if not record:
            self.fail('record type {0} is not supported now'.format(record_type))
        record_sdk_class = getattr(self.dns_models, record.get('classobj'))
        record_sdk = []
        if input_records is not None:
            for x in input_records:
                record_sdk.append(record_sdk_class(**x))
        return record_sdk

    def records_changed(self, input_records, server_records):
        # ensure we're always comparing a list, even for the single-valued types
        if not isinstance(server_records, list):
            server_records = [server_records]

        input_set = set([self.module.jsonify(x.as_dict()) for x in input_records])
        server = []
        for x in server_records:
            if x is not None:
                server.append(self.module.jsonify(x.as_dict()))
        server_set = set(server)

        if self.record_mode == 'append':  # only a difference if the server set is missing something from the input set
            input_set = server_set.union(input_set)

        # non-append mode; any difference in the sets is a change
        changed = input_set != server_set

        records = [self.module.from_json(x) for x in input_set]
        return self.create_sdk_records(records, self.record_type), changed

    def recordset_to_dict(self, recordset):
        result = recordset.as_dict()
        result['type'] = result['type'].strip('Microsoft.Network/dnszones/')
        return result

    def update_metadata(self, metadata):
        metadata = metadata or dict()
        new_metadata = copy.copy(metadata) if isinstance(metadata, dict) else dict()
        param_metadata = self.metadata if isinstance(self.metadata, dict) else dict()
        append_metadata = self.append_metadata if self.metadata is not None else True
        changed = False
        # check add or update metadata
        for key, value in param_metadata.items():
            if not new_metadata.get(key) or new_metadata[key] != value:
                changed = True
                new_metadata[key] = value
        # check remove
        if not append_metadata:
            for key, value in metadata.items():
                if not param_metadata.get(key):
                    new_metadata.pop(key)
                    changed = True
        return changed, new_metadata


def main():
    AzureRMRecordSet()


if __name__ == '__main__':
    main()
