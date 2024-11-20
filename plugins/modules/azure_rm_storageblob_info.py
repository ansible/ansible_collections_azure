#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_storageblob_info
short_description: Get or list the containers blob facts
version_added: "3.0.0"
description:
    - Get or list the blobs under the specified container.
options:
    auth_mode:
        description:
            - The mode in which to run the command. C(login) mode will directly use your login credentials for the authentication.
            - The legacy C(key) mode will attempt to query for an account key if no authentication parameters for the account are provided.
            - Can also be set via the environment variable C(AZURE_STORAGE_AUTH_MODE).
        default: key
        type: str
        choices:
            - key
            - login
    storage_account_name:
        description:
            - Name of the storage account to use.
        required: true
        type: str
        aliases:
            - account_name
            - storage_account
    blob_name:
        description:
            - Name of a blob object within the container.
        aliases:
            - blob
        type: str
    container_name:
        description:
            - Name of a blob container within the storage account.
        required: true
        type: str
        aliases:
            - container
    resource_group:
        description:
            - Name of the resource group to use.
        required: true
        type: str
        aliases:
            - resource_group_name
    name_starts_with:
        description:
            - Filters the results to return only blobs whose names begin with the specified prefix.
        type: str
    include:
        description:
            - Specifies one or more additional datasets to include in the response.
        type: list
        elements: str
        choices:
            - snapshots
            - metadata
            - uncommittedblobs
            - copy
            - deleted
            - deletedwithversions
            - tags
            - versions
            - immutabilitypolicy
            - legalhold
extends_documentation_fragment:
    - azure.azcollection.azure

author:
    - xuzhang3 (@xuzhang3)
    - Fred-sun (@Fred-sun)

'''

EXAMPLES = '''
- name: Get the blob facts by name
  azure_rm_storageblob_info:
    resource_group: "{{ resource_group }}"
    account_name: "{{ storage_account }}"
    container_name: my-blobs
    blob_name: blobname01

- name: List the blob facts in specify container
  azure_rm_storageblob_info:
    resource_group: "{{ resource_group }}"
    account_name: "{{ storage_account }}"
    container_name: my-blobs
'''

RETURN = '''
blob:
    description:
        - Facts about the current state of the blob.
    returned: when a blob is operated on
    type: dict
    sample: {
        "content_length": 136532,
        "content_settings": {
            "cache_control": null,
            "content_disposition": null,
            "content_encoding": null,
            "content_language": null,
            "content_md5": null,
            "content_type": "application/image"
        },
        "last_modified": "20-11-2024 22:08:25 +0000",
        "name": "graylog.png",
        'metadata': {'key1': 'value1'},
        "standard_blob_tier": "Hot",
        "tags": {},
        "type": "BlockBlob"
    }
'''


try:
    from azure.core.exceptions import ResourceNotFoundError
except ImportError:
    # This is handled in azure_rm_common
    pass

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase
from ansible.module_utils.basic import env_fallback


class AzureRMStorageBlobInfo(AzureRMModuleBase):

    def __init__(self):

        self.module_arg_spec = dict(
            auth_mode=dict(
                type='str',
                choices=['key', 'login'],
                fallback=(env_fallback, ['AZURE_STORAGE_AUTH_MODE']),
                default="key"
            ),
            storage_account_name=dict(required=True, type='str', aliases=['account_name', 'storage_account']),
            blob_name=dict(type='str', aliases=['blob']),
            container_name=dict(required=True, type='str', aliases=['container']),
            resource_group=dict(required=True, type='str', aliases=['resource_group_name']),
            name_starts_with=dict(type='str'),
            include=dict(
                type='list',
                elements='str',
                choices=['snapshots', 'metadata', 'uncommittedblobs', 'copy', 'deleted',
                         'deletedwithversions', 'tags', 'versions', 'immutabilitypolicy', 'legalhold']
            ),
        )

        self.blob_service_client = None
        self.storage_account_name = None
        self.blob_name = None
        self.container_name = None
        self.resource_group = None
        self.name_starts_with = None
        self.include = None
        self.results = dict(
            changed=False,
            blob=dict()
        )

        super(AzureRMStorageBlobInfo, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                     supports_check_mode=True,
                                                     supports_tags=False)

    def exec_module(self, **kwargs):

        for key in list(self.module_arg_spec.keys()):
            setattr(self, key, kwargs[key])

        self.blob_service_client = self.get_blob_service_client(self.resource_group, self.storage_account_name, self.auth_mode)
        if self.blob_name:
            response = self.get_blob()
        else:
            response = self.list_blob()
        self.results['blob'] = response
        return self.results

    def get_blob(self):
        response = None
        if self.blob_name:
            try:
                response = self.blob_service_client.get_blob_client(container=self.container_name, blob=self.blob_name).get_blob_properties()
            except ResourceNotFoundError:
                pass
        return self.format_blob(response) if response else None

    def list_blob(self):
        response = []
        try:
            client = self.blob_service_client.get_container_client(container=self.container_name)
            blobs = client.list_blobs(name_starts_with=self.name_starts_with, include=self.include)
            for blob in blobs:
                response.append(self.format_blob(blob))
        except Exception as exc:
            self.fail("Error list container blob {0} - {1}".format(self.container_name, str(exc)))
        return response

    def format_blob(self, blob):
        result = dict(
            name=blob["name"],
            tags=blob["metadata"],
            last_modified=blob["last_modified"].strftime('%d-%b-%Y %H:%M:%S %z'),
            type=blob["blob_type"],
            standard_blob_tier=blob.get('blob_tier'),
            metadata=blob.get('metadata'),
            content_length=blob["size"],
            content_settings=dict(
                content_type=blob["content_settings"]["content_type"],
                content_encoding=blob["content_settings"]["content_encoding"],
                content_language=blob["content_settings"]["content_language"],
                content_disposition=blob["content_settings"]["content_disposition"],
                cache_control=blob["content_settings"]["cache_control"],
                content_md5=blob["content_settings"]["content_md5"].hex() if blob["content_settings"]["content_md5"] else None,
            )
        )
        return result


def main():
    AzureRMStorageBlobInfo()


if __name__ == '__main__':
    main()
