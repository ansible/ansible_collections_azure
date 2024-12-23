# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import time
import os
import json
import base64
import tarfile
from glob import glob
import traceback

HAS_ORAS = False
HAS_ORAS_EXC = None

try:
    import oras.client
    HAS_ORAS = True
except ImportError:
    oras = None
    HAS_ORAS_EXC = traceback.format_exc()

try:
    from azure.core.exceptions import ResourceNotFoundError, HttpResponseError
    from azure.mgmt.core.tools import resource_id, parse_resource_id
except ImportError:
    pass

from ansible_collections.azure.azcollection.plugins.plugin_utils import file_utils
from ansible_collections.azure.azcollection.plugins.plugin_utils import constants as consts

from ansible.errors import AnsibleError


# Get the Access Details to connect to Arc Connectivity platform from the HybridConnectivity RP
def get_relay_information(rest_client, subscription_id, resource_group, hostname, resource_type,
                          certificate_validity_in_seconds, port):
    if not certificate_validity_in_seconds or \
       certificate_validity_in_seconds > consts.RELAY_INFO_MAXIMUM_DURATION_IN_SECONDS:
        certificate_validity_in_seconds = consts.RELAY_INFO_MAXIMUM_DURATION_IN_SECONDS

    namespace = resource_type.split('/', 1)[0]
    arc_type = resource_type.split('/', 1)[1]
    resource_uri = resource_id(subscription=subscription_id, resource_group=resource_group,
                               namespace=namespace, type=arc_type, name=hostname)

    cred = None
    new_service_config = False
    try:
        cred = _list_credentials(rest_client, resource_uri, certificate_validity_in_seconds)
    except ResourceNotFoundError:
        _create_default_endpoint(rest_client, resource_uri)
    except HttpResponseError as e:
        if e.reason != "Precondition Failed":
            raise AnsibleError(f"Unable to retrieve relay information. Failed with error: {str(e)}")
    except Exception as e:
        raise AnsibleError(f"Unable to retrieve relay information. Failed with error: {str(e)}")

    if not cred:
        _create_service_configuration(rest_client, resource_uri, port)
        new_service_config = True
        try:
            cred = _list_credentials(rest_client, resource_uri, certificate_validity_in_seconds)
        except Exception as e:
            raise AnsibleError(f"Unable to get relay information. Failed with error: {str(e)}")
        _handle_relay_connection_delay(rest_client, "Setting up service configuration")
    else:
        if not _check_service_configuration(rest_client, resource_uri, port):
            _create_service_configuration(rest_client, resource_uri, port)
            new_service_config = True
            try:
                cred = _list_credentials(rest_client, resource_uri, certificate_validity_in_seconds)
            except Exception as e:
                raise AnsibleError(f"Unable to get relay information. Failed with error: {str(e)}")
            _handle_relay_connection_delay(rest_client, "Setting up service configuration")
    return (cred, new_service_config)


def _check_service_configuration(rest_client, resource_uri, port):
    url = f"/{resource_uri}/providers/Microsoft.HybridConnectivity/endpoints/default/serviceConfigurations/SSH"

    serviceConfig = None
    # pylint: disable=broad-except
    try:
        serviceConfig = resource(rest_client, url, "GET")
    except Exception:
        # If for some reason the request for Service Configuration fails,
        # we will still attempt to get relay information and connect. If the service configuration
        # is not setup correctly, the connection will fail.
        # The more likely scenario is that the request failed with a "Authorization Error",
        # in case the user isn't an owner/contributor.
        return True
    serviceConfigPort = serviceConfig and serviceConfig.get('properties', {}).get('port')
    if port:
        return int(serviceConfigPort) == int(port)

    return True


def _create_default_endpoint(rest_client, resource_uri):
    url = f"/{resource_uri}/providers/Microsoft.HybridConnectivity/endpoints/default"
    body = {'properties': {'type': 'default'}}

    hostname = parse_resource_id(resource_uri)["name"]
    resource_group = parse_resource_id(resource_uri)["resource_group"]
    try:
        endpoint = resource(rest_client, url, "PUT", body=body)
    except HttpResponseError as e:
        if e.reason == "Forbidden":
            raise AnsibleError(f"Client is not authorized to create a default connectivity "
                               f"endpoint for \'{hostname}\' in Resource Group \'{resource_group}\'. "
                               f"This is a one-time operation that must be performed by "
                               f"an account with Owner or Contributor role to allow "
                               f"connections to the target resource.")
        raise AnsibleError(f"Failed to create default endpoint for the target Arc Server. "
                           f"\nError: {str(e)}")
    except Exception as e:
        raise AnsibleError(f"Failed to create default endpoint for the target Arc Server. "
                           f"\nError: {str(e)}")

    return endpoint


def _create_service_configuration(rest_client, resource_uri, port):
    if not port:
        port = '22'

    url = f"/{resource_uri}/providers/Microsoft.HybridConnectivity/endpoints/default/serviceConfigurations/SSH"
    body = {'properties': {'port': int(port), 'serviceName': 'SSH'}}

    hostname = parse_resource_id(resource_uri)["name"]
    resource_group = parse_resource_id(resource_uri)["resource_group"]

    try:
        serviceConfig = resource(rest_client, url, "PUT", body=body)
    except HttpResponseError as e:
        if e.reason == "Forbidden":
            raise AnsibleError(f"Client is not authorized to create or update the Service "
                               f"Configuration endpoint for \'{hostname}\' in the Resource "
                               f"Group \'{resource_group}\'. This is an operation that "
                               f"must be performed by an account with Owner or Contributor "
                               f"role to allow SSH connections to the specified port {port}.")
        raise AnsibleError(f"Failed to create service configuration to allow SSH "
                           f"connections to port {port} on the endpoint for {hostname} "
                           f"in the Resource Group {resource_group}\nError: {str(e)}")
    except Exception as e:
        raise AnsibleError(f"Failed to create service configuration to allow SSH connections "
                           f"to port {port} on the endpoint for {hostname} in the Resource "
                           f"Group {resource_group}\nError: {str(e)}")
    return serviceConfig


def _list_credentials(rest_client, resource_uri, certificate_validity_in_seconds):
    url = f"/{resource_uri}/providers/Microsoft.HybridConnectivity/endpoints/default/listCredentials"
    query_parameters = {'expiresin': int(certificate_validity_in_seconds)}
    body = {'serviceName': 'SSH'}

    response = resource(rest_client, url, "POST", body=body, custom_query=query_parameters)
    return response and response.get('relay')


def format_relay_info_string(relay_info):
    relay_info_string = json.dumps(
        {
            "relay": {
                "namespaceName": relay_info['namespaceName'],
                "namespaceNameSuffix": relay_info['namespaceNameSuffix'],
                "hybridConnectionName": relay_info['hybridConnectionName'],
                "accessKey": relay_info['accessKey'],
                "expiresOn": relay_info['expiresOn'],
                "serviceConfigurationToken": relay_info['serviceConfigurationToken']
            }
        })
    result_bytes = relay_info_string.encode("ascii")
    enc = base64.b64encode(result_bytes)
    base64_result_string = enc.decode("ascii")
    return base64_result_string


def _handle_relay_connection_delay(rest_client, message):
    # relay has retry delay after relay connection is lost
    # must sleep for at least as long as the delay
    # otherwise the ssh connection will fail
    for x in range(0, consts.SERVICE_CONNECTION_DELAY_IN_SECONDS + 1):
        time.sleep(1)


# Downloads client side proxy to connect to Arc Connectivity Platform
def install_client_side_proxy(arc_proxy_folder):

    client_operating_system = _get_client_operating_system()
    client_architecture = _get_client_architeture()
    install_dir = _get_proxy_install_dir(arc_proxy_folder)
    proxy_name = _get_proxy_filename(client_operating_system, client_architecture)
    install_location = os.path.join(install_dir, proxy_name)

    # Only download new proxy if it doesn't exist already
    if not os.path.isfile(install_location):
        if not os.path.isdir(install_dir):
            file_utils.create_directory(install_dir, f"Failed to create client proxy directory '{install_dir}'.")
        # if directory exists, delete any older versions of the proxy
        else:
            older_version_location = _get_older_version_proxy_path(
                install_dir,
                client_operating_system,
                client_architecture)
            older_version_files = glob(older_version_location)
            for f in older_version_files:
                file_utils.delete_file(f, f"failed to delete older version file {f}", warning=True)

        _download_proxy_from_MCR(install_dir, proxy_name, client_operating_system, client_architecture)
        _check_proxy_installation(install_dir, proxy_name)

    return install_location


def _download_proxy_from_MCR(dest_dir, proxy_name, operating_system, architecture):
    mar_target = f"{consts.CLIENT_PROXY_MCR_TARGET}/{operating_system.lower()}/{architecture}/ssh-proxy"

    client = oras.client.OrasClient()

    try:
        response = client.pull(target=f"{mar_target}:{consts.CLIENT_PROXY_VERSION}", outdir=dest_dir)
    except Exception as e:
        raise AnsibleError(
            f"Failed to download Arc Connectivity proxy with error {str(e)}. Please try again.")

    proxy_package_path = _get_proxy_package_path_from_oras_response(response)
    _extract_proxy_tar_files(proxy_package_path, dest_dir, proxy_name)
    file_utils.delete_file(proxy_package_path, f"Failed to delete {proxy_package_path}. Please delete manually.", True)


def _get_proxy_package_path_from_oras_response(pull_response):
    if not isinstance(pull_response, list):
        raise AnsibleError(
            "Attempt to download Arc Connectivity Proxy returned unnexpected result. Please try again.")

    if len(pull_response) != 1:
        for r in pull_response:
            file_utils.delete_file(r, f"Failed to delete {r}. Please delete it manually.", True)
        raise AnsibleError(
            "Attempt to download Arc Connectivity Proxy returned unnexpected result. Please try again.")

    proxy_package_path = pull_response[0]

    if not os.path.isfile(proxy_package_path):
        raise AnsibleError("Unable to download Arc Connectivity Proxy. Please try again.")

    return proxy_package_path


def _extract_proxy_tar_files(proxy_package_path, install_dir, proxy_name):
    with tarfile.open(proxy_package_path, 'r:gz') as tar:
        members = []
        for member in tar.getmembers():
            if member.isfile():
                filenames = member.name.split('/')

                if len(filenames) != 2:
                    tar.close()
                    file_utils.delete_file(
                        proxy_package_path,
                        f"Failed to delete {proxy_package_path}. Please delete it manually.",
                        True)
                    raise AnsibleError(
                        "Attempt to download Arc Connectivity Proxy returned unnexpected result. Please try again.")

                member.name = filenames[1]

                if member.name.startswith('sshproxy'):
                    member.name = proxy_name
                elif member.name.lower() not in ['license.txt', 'thirdpartynotice.txt']:
                    tar.close()
                    file_utils.delete_file(
                        proxy_package_path,
                        f"Failed to delete {proxy_package_path}. Please delete it manually.",
                        True)
                    raise AnsibleError(
                        "Attempt to download Arc Connectivity Proxy returned unnexpected result. Please try again.")

                members.append(member)

        tar.extractall(members=members, path=install_dir)


def _check_proxy_installation(install_dir, proxy_name):
    proxy_filepath = os.path.join(install_dir, proxy_name)
    if not os.path.isfile(proxy_filepath):
        raise AnsibleError(
            "Failed to install required SSH Arc Connectivity Proxy. "
            f"Couldn't find expected file {proxy_filepath}. Please try again.")


def _get_proxy_filename(operating_system, architecture):
    if operating_system.lower() == 'darwin' and architecture == '386':
        raise AnsibleError("Unsupported Darwin OS with 386 architecture.")
    proxy_filename = \
        f"sshProxy_{operating_system.lower()}_{architecture}_{consts.CLIENT_PROXY_VERSION.replace('.', '_')}"
    if operating_system.lower() == 'windows':
        proxy_filename += '.exe'
    return proxy_filename


def _get_older_version_proxy_path(install_dir, operating_system, architecture):
    proxy_name = f"sshProxy_{operating_system.lower()}_{architecture}_*"
    return os.path.join(install_dir, proxy_name)


def _get_proxy_install_dir(arc_proxy_folder):
    if not arc_proxy_folder:
        return os.path.expanduser(os.path.join('~', ".clientsshproxy"))
    return arc_proxy_folder


def _get_client_architeture():
    import platform
    machine = platform.machine()
    architecture = None

    if "arm64" in machine.lower() or "aarch64" in machine.lower():
        architecture = 'arm64'
    elif machine.endswith('64'):
        architecture = 'amd64'
    elif machine.endswith('86'):
        architecture = '386'
    elif machine == '':
        raise AnsibleError("Couldn't identify the platform architecture.")
    else:
        raise AnsibleError(f"Unsuported architecture: {machine} is not currently supported")

    return architecture


def _get_client_operating_system():
    import platform
    operating_system = platform.system()

    if operating_system.lower() not in ('linux', 'darwin', 'windows'):
        raise AnsibleError(f"Unsuported OS: {operating_system} platform is not currently supported")
    return operating_system


def resource(client,
             url,
             method,
             body=None,
             custom_query=None,
             custom_header=None,
             status_code=None):

    # Construct status_code
    if status_code is None:
        status_code = [200, 201, 202]

    # Construct parameters
    query_parameters = {}
    query_parameters['api-version'] = '2023-03-15'
    if custom_query:
        query_parameters.update(custom_query)

    # Construct headers
    header_parameters = {}
    header_parameters['Content-Type'] = 'application/json; charset=utf-8'
    if custom_header:
        header_parameters.update(custom_header)

    response = client.query(url,
                            method,
                            query_parameters,
                            header_parameters,
                            body,
                            status_code,
                            600,
                            30)

    if hasattr(response, 'body'):
        try:
            response = json.loads(response.body())
        except Exception:
            response = response.body()
    elif hasattr(response, 'context'):
        response = response.context['deserialized_data']
    else:
        response = None

    return response
