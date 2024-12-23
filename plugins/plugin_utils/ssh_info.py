# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------


import os
from ansible_collections.azure.azcollection.plugins.plugin_utils import file_utils
from ansible_collections.azure.azcollection.plugins.plugin_utils import connectivity_utils


class ConfigSession():
    # pylint: disable=too-many-instance-attributes
    def __init__(self, ssh_config_file, ssh_relay_file, resource_group_name, hostname, ansible_host,
                 private_key_file, local_user, port, resource_type, ssh_proxy_folder):
        self.resource_group_name = resource_group_name
        self.hostname = hostname
        self.ansible_host = ansible_host
        self.local_user = local_user
        self.port = port
        self.resource_type = resource_type
        self.proxy_path = None
        self.relay_info = None
        self.relay_info_path = None
        self.ssh_config_file = os.path.abspath(os.path.expanduser(ssh_config_file))
        self.ssh_relay_file = os.path.abspath(os.path.expanduser(ssh_relay_file))
        self.private_key_file = os.path.abspath(os.path.expanduser(private_key_file)) if private_key_file else None
        self.ssh_proxy_folder = os.path.abspath(os.path.expanduser(ssh_proxy_folder)) if ssh_proxy_folder else None

    def get_config_text(self):
        lines = [""]
        self.relay_info_path = self._create_relay_info_file()
        lines = lines + self._get_arc_entry()
        return lines

    def _get_arc_entry(self):
        lines = []
        lines.append("Host " + self.ansible_host)
        lines.append("\tHostName " + self.hostname)
        lines.append("\tUser " + self.local_user)
        if self.private_key_file:
            lines.append("\tIdentityFile \"" + self.private_key_file + "\"")
        if self.port:
            lines.append("\tProxyCommand \"" + self.proxy_path + "\" " + "-r \"" + self.relay_info_path + "\" "
                         + "-p " + str(self.port))
        else:
            lines.append("\tProxyCommand \"" + self.proxy_path + "\" " + "-r \"" + self.relay_info_path + "\"")
        return lines

    def _create_relay_info_file(self):
        relay_info_path = self.ssh_relay_file
        relay_info_dir = os.path.dirname(relay_info_path)
        if not os.path.isdir(relay_info_dir):
            os.makedirs(relay_info_dir)

        # Overwrite relay_info if it already exists in that folder.
        file_utils.delete_file(relay_info_path, f"{relay_info_path} already exists, and couldn't be overwritten.")
        file_utils.write_to_file(relay_info_path, 'w', connectivity_utils.format_relay_info_string(self.relay_info),
                                 f"Couldn't write relay information to file {relay_info_path}.", 'utf-8')
        os.chmod(relay_info_path, 0o644)

        return relay_info_path
