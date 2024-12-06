#!/usr/bin/python
#
# Copyright (c) 2024 xuzhang3 (@xuzhang3), Fred-sun (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: azure_rm_batchaccountpool
version_added: "3.0.0"
short_description: Manages a Batch Account Pool on Azure
description:
    - Create, update and delete instance of Azure Batch Account Pool.

options:
    resource_group:
        description:
            - The name of the resource group in which to create the Batch Account Pool.
        required: true
        type: str
    batch_account_name:
        description:
            - The name of the Batch Account.
        required: true
        type: str
    name:
        description:
            - The name of the Batch Account Pool.
        required: true
        type: str
    display_name:
        description:
            - The display name for the pool.
        type: str
    identity:
        description:
            - The type of identity used for the Batch Pool.
            - If the pool identity is updated during update an existing pool.
            - Only the new vms which are created after the pool shrinks to 0 will have the updated identities.
        type: dict
        suboptions:
            type:
                description:
                    - The type of identity used for the Batch Pool.
                required: true
                type: str
                choices:
                    - None
                    - UserAssigned
            user_assigned_identities:
                description:
                    - The list of user identities associated with the Batch pool.
                    - The key is the identity's ID and value contains 'principal_id' and 'client_id'.
                type: dict
    vm_size:
        description:
            - For information about available sizes of virtual machines for Cloud Services Pools.
            - Batch supports all Cloud Services VM sizes except ExtraSmall, A1V2 and A2V2,
            - Batch supports all Azure VM sizes except STANDARD_A0 and those with premium storage (STANDARD_GS, STANDARD_DS, and STANDARD_DSV2 series).
        type: str
    deployment_configuration:
        description:
            - Using CloudServiceConfiguration specifies that the nodes should be creating using Azure Cloud Services (PaaS).
            - Using VirtualMachineConfiguration uses Azure Virtual Machines (IaaS).
        type: dict
        suboptions:
            cloud_service_configuration:
                description:
                    - This property and virtualMachineConfiguration are mutually exclusive and one of the properties must be specified.
                    - This property cannot be specified if the Batch account was created with its poolAllocationMode property set to 'UserSubscription'.
                type: dict
                suboptions:
                    os_family:
                        description:
                            - I(os_family=2) equivalent to Windows Server 2008 R2 SP1.
                            - I(os_family=3) equivalent to Windows Server 2012.
                            - I(os_family=4) equivalent to Windows Server 2012 R2.
                            - I(os_family=5) equivalent to Windows Server 2016.
                            - I(os_family=6) equivalent to Windows Server 2019.
                        type: str
                        default: '*'
                    os_version:
                        description:
                            - The default value is C(*) which specifies the latest operating system version for the specified OS family.
                        type: str
            virtual_machine_configuration:
                description:
                    - This property and cloudServiceConfiguration are mutually exclusive and one of the properties must be specified.
                type: dict
                suboptions:
                    image_reference:
                        description:
                            - A reference to an Azure Virtual Machines Marketplace image or the zure Image resource of a custom Virtual Machine.
                            - To get the list of all imageReferences verified by Azure Batch, see the 'List supported node agent SKUs' operation.
                        type: dict
                        required: true
                        suboptions:
                            publisher:
                                description:
                                    - For example, C(Canonical) or C(MicrosoftWindowsServer).
                                type: str
                            offer:
                                description:
                                    - For example, C(UbuntuServer) or C(WindowsServer).
                                type: str
                            sku:
                                description:
                                    - For example, C(18.04-LTS) or C(2022-datacenter).
                                type: str
                            version:
                                description:
                                    - A value of 'latest' can be specified to select the latest version of an image.
                                    - If omitted, the default is C(latest).
                                type: str
                            id:
                                description:
                                    - This property is mutually exclusive with other properties.
                                    - The Azure Compute Gallery Image must have replicas in the same region as the Azure Batch account.
                                    - Sample as C('/subscriptions/{sub_Id}/resourceGroups/{resourceGroup}/providers/Microsoft.Compute/images/{imageName}).
                                type: str
                    node_agent_sku_id:
                        description:
                            - The Batch node agent is a program that runs on each node in the pool.
                            - Provides the command-and-control interface between the node and the Batch service.
                            - There are different implementations of the node agent, known as SKUs, for different operating systems.
                            - You must specify a node agent SKU which matches the selected image reference.
                            - To get the list of supported node agent SKUs along with their list of verified image references.
                        type: str
                        required: true
                    windows_configuration:
                        description:
                            - This property must not be specified if the imageReference specifies a Linux OS image.
                        type: dict
                        suboptions:
                            enable_automatic_updates:
                                description:
                                    - If omitted, the default value is C(true).
                                type: bool
                                default: true
                    data_disks:
                        description:
                            - This property must be specified if the compute nodes in the pool need to have empty data disks attached to them.
                        type: list
                        elements: dict
                        suboptions:
                            lun:
                                description:
                                    - The lun is used to uniquely identify each data disk.
                                    - If attaching multiple disks, each should have a distinct lun.
                                    - The value must be between 0 and 63, inclusive.
                                required: true
                                type: int
                            caching:
                                description:
                                    - The caching mode for the disk
                                type: str
                                choices:
                                    - None
                                    - ReadOnly
                                    - ReadWrite
                            disk_size_gb:
                                description:
                                    - The initial disk size in GB when creating new data disk.
                                type: int
                                required: true
                            storage_account_type:
                                description:
                                    - The data disk type.
                                    - C(Standard_LRS) for the data disk should use standard locally redundant storage.
                                    - C(Premium_LRS) for the he data disk should use premium locally redundant storage.
                                type: str
                                default: Standard_LRS
                                choices:
                                    - Standard_LRS
                                    - Premium_LRS
                                    - StandardSSD_LRS
                    license_type:
                        description:
                            - This only applies to images that contain the Windows operating system.
                            - Should only be used when you hold valid on-premises licenses for the nodes which will be deployed.
                            - C(Windows_Server), The on-premises license is for Windows Server.
                            - C(Windows_Client), The on-premises license is for Windows Client.
                        type: str
                    container_configuration:
                        description:
                            - If specified, setup is performed on each node in the pool to allow tasks to run in containers.
                            - All regular tasks and job manager tasks run on this pool must specify the containerSettings property.
                            - All other tasks may specify it.
                        type: dict
                        suboptions:
                            type:
                                description:
                                    - The container technology to be used.
                                required: true
                                type: str
                                choices:
                                    - DockerCompatible
                                    - CriCompatible
                            container_image_names:
                                description:
                                    - This is the full image reference, as would be specified to "docker pull".
                                    - "An image will be sourced from the default Docker registry
                                      unless the image is fully qualified with an alternative registry."
                                type: list
                                elements: str
                            container_registries:
                                description:
                                    - "If any images must be downloaded from a private registry which requires credentials,
                                      then those credentials must be provided here."
                                type: list
                                elements: dict
                                suboptions:
                                    user_name:
                                        description:
                                            - The user name to log into the registry server.
                                        type: str
                                    password:
                                        description:
                                            - The password to log into the registry server.
                                        type: str
                                    registry_server:
                                        description:
                                            - If omitted, the default is C(docker.io).
                                        type: str
                                        default: 'docker.io'
                                    identity_reference:
                                        description:
                                            - The reference to a user assigned identity associated with the Batch pool which a compute node will use.
                                        type: dict
                                        suboptions:
                                            resource_id:
                                                description:
                                                    - The ARM resource id of the user assigned identity.
                                                type: str
                    disk_encryption_configuration:
                        description:
                            - If specified, encryption is performed on each node in the pool during node provisioning.
                        type: dict
                        suboptions:
                            targets:
                                description:
                                    - On Linux pool, only C(TemporaryDisk) is supported.
                                    - on Windows pool, C(OsDisk) and C(TemporaryDisk) must be specified.
                                type: list
                                elements: str
                                choices:
                                    - TemporaryDisk
                                    - OsDisk
                    node_placement_configuration:
                        description:
                            - This configuration will specify rules on how nodes in the pool during node provisioning.
                        type: dict
                        suboptions:
                            policy:
                                description:
                                    - Allocation policy used by Batch Service to provision the nodes.
                                    - If not specified, Batch will use the regional policy.
                                type: str
                                choices:
                                    - Regional
                                    - Zonal
                    extensions:
                        description:
                            - If specified, the extensions mentioned in this configuration will be installed on each node.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - The name of the virtual machine extension.
                                required: true
                                type: str
                            publisher:
                                description:
                                    - The name of the extension handler publisher.
                                required: true
                                type: str
                            type:
                                description:
                                    - The type of the extensions.
                                type: str
                                required: true
                            type_handler_version:
                                description:
                                    - The version of script handler.
                                type: str
                            auto_upgrade_minor_version:
                                description:
                                    - Indicates whether the extension should use a newer minor version if one is available at deployment time.
                                    - Once deployed, the extension will not upgrade minor versions unless redeployed, even with this property set to true.
                                type: bool
                            enable_automatic_upgrade:
                                description:
                                    - "Indicates whether the extension should be automatically upgraded by the platform
                                      if there is a newer version of the extension available."
                                type: bool
                            settings:
                                description:
                                    - JSON formatted public settings for the extension.
                                type: json
                            protected_settings:
                                description:
                                    - The extension can contain either protectedSettings or protectedSettingsFromKeyVault or no protected settings at all.
                                type: json
                            provision_after_extensions:
                                description:
                                    - Collection of extension names after which this extension needs to be provisioned.
                                type: list
                                elements: str
                    os_disk:
                        description:
                            - Contains configuration for ephemeral OSDisk settings.
                        type: dict
                        suboptions:
                            ephemeral_os_disk_settings:
                                description:
                                    - Specifies the ephemeral Disk Settings for the operating system disk used by the virtual machine.
                                type: dict
                                suboptions:
                                    placement:
                                        description:
                                            - This property can be used by user in the request to choose which location the operating system should be in.
                                        type: str
                            caching:
                                description:
                                    - The type of caching to enable for the disk.
                                type: str
                                choices:
                                    - None
                                    - ReadOnly
                                    - ReadWrite
                            managed_disk:
                                description:
                                    - The data disk config.
                                type: dict
                                suboptions:
                                    storage_account_type:
                                        description:
                                            - The storage account type for use in creating data disks or OSdisk.
                                        type: str
                                        choices:
                                            - Standard_LRS
                                            - Premium_LRS
                                            - StandardSSD_LRS
                            disk_size_gb:
                                description:
                                    - The initial disk size in GB when creating new OS disk.
                                type: int
                            write_accelerator_enabled:
                                description:
                                    -  Specifies whether writeAccelerator should be enabled or disabled on the disk.
                                type: bool
                    security_profile:
                        description:
                            - Specifies the security profile settings for the virtual machine or virtual machine scale set.
                        type: dict
                        suboptions:
                            security_type:
                                description:
                                    - Specifies the SecurityType of the virtual machine.
                                    - It has to be set to any specified value to enable UefiSettings.
                                type: str
                                default: trustedLaunch
                            encryption_at_host:
                                description:
                                    - "This property can be used by user in the request to enable or disable the Host Encryption
                                      for the virtual machine or virtual machine scale set."
                                    - This willenable the encryption for all the disks including Resource/Temp disk at host itself.
                                type: bool
                            uefi_settings:
                                description:
                                    - Specifies the security settings like secure boot and vTPM used while creating the virtual machine.
                                type: dict
                                suboptions:
                                    secure_boot_enabled:
                                        description:
                                            - Specifies whether secure boot should be enabled on the virtual machine.
                                        type: bool
                                    v_tpm_enabled:
                                        description:
                                            - Specifies whether vTPM should be enabled on the virtual machine.
                                        type: bool
                    service_artifact_reference:
                        description:
                            - The service artifact reference ID.
                            - "Such as C(/subscriptions/{subId}/resourceGroups/{testRG}/providers/Microsoft.Compute/galleries
                              /{gName}/serviceArtifacts/{ArtName}/vmArtifactsProfiles/{ProfilesName})."
                        type: dict
                        suboptions:
                            id:
                                description:
                                    - The service artifact reference ID of the vmArtifactsProfiles.
                                type: str
    scale_settings:
        description:
            - Defines the desired size of the pool.
            - "This can either be 'fixedScale' where the requested targetDedicatedNodes is specified,
              or 'autoScale' which defines a formula which is periodically reevaluated."
            - If this property is not specified, the pool will have a fixed scale with 0 targetDedicatedNodes.
        type: dict
        suboptions:
            fixed_scale:
                description:
                    - This property and autoScale are mutually exclusive and one of the properties must be specified.
                type: dict
                suboptions:
                    resize_timeout:
                        description:
                            - The default value is 15 minutes C(P15M).
                            - Timeout values use ISO 8601 format. For example, use PT10M for 10 minutes.
                            - The minimum value is 5 minutes.
                            - If you specify a value less than 5 minutes, the Batch service rejects the request with an error.
                        type: str
                        default: P15M
                    target_dedicated_nodes:
                        description:
                            -  At least one of targetDedicatedNodes, targetLowPriorityNodes must be set.
                        type: int
                    target_low_priority_nodes:
                        description:
                            - At least one of targetDedicatedNodes, targetLowPriorityNodes must be set.
                        type: int
                    node_deallocation_option:
                        description:
                            -  If omitted, the default value is C(Requeue).
                        type: str
                        choices:
                            - Requeue
                            - Terminate
                            - TaskCompletion
                            - RetainedData
            auto_scale:
                description:
                    - This property and fixedScale are mutually exclusive and one of the properties must be specified. must be specified.
                type: dict
                suboptions:
                    formula:
                        description:
                            - A formula for the desired number of compute nodes in the pool.
                        type: str
                        required: true
                    evaluation_interval:
                        description:
                            - If omitted, the default value is 15 minutes (PT15M).
                        type: str
                        default: P15M
    inter_node_communication:
        description:
            - This imposes restrictions on which nodes can be assigned to the pool.
            - Enabling this value can reduce the chance of the requested number of nodes to be allocated in the pool.
            - If not specified, this value defaults to C(Disabled).
        type: str
        choices:
            - Enabled
            - Disabled
    network_configuration:
        description:
            - The network configuration for a pool.
        type: dict
        suboptions:
            subnet_id:
                description:
                    - The virtual network must be in the same region and subscription as the Azure Batch account.
                    - The specified subnet should have enough free IP addresses to accommodate the number of nodes in the pool.
                    - If the subnet doesn't have enough free IP addresses, the pool will partially allocate compute nodes and a resize error will occur.
                type: str
            dynamic_vnet_assignment_scope:
                description:
                    - The scope of dynamic vnet assignment.
                type: str
                choices:
                    - none
                    - job
            endpoint_configuration:
                description:
                    - Pool endpoint configuration is only supported on pools with the virtualMachineConfiguration property.
                type: dict
                suboptions:
                    inbound_nat_pools:
                        description:
                            - The maximum number of inbound NAT pools per Batch pool is 5.
                            - If the maximum number of inbound NAT pools is exceeded the request fails with HTTP status code 400.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - The name must be unique within a Batch pool.
                                    - The name contain letters, numbers, underscores, periods, and hyphens.
                                type: str
                                required: true
                            protocol:
                                description:
                                    - The protocol of the endpoint.
                                type: str
                                required: true
                                choices:
                                    - UDP
                                    - TCP
                            backend_port:
                                description:
                                    - This must be unique within a Batch pool.
                                    - Acceptable values are between 1 amd 65535 except for 22.
                                type: int
                                required: true
                            frontend_port_range_start:
                                description:
                                    - Acceptable values range between 1 and 65534 except ports overlap
                                    - If any reserved or overlapping values are provided the request fails with HTTP status code 400.
                                type: int
                                required: true
                            frontend_port_range_end:
                                description:
                                    - Acceptable values range between 1 and 65534 except ports from 50000 to 55000 which are reserved by the Batch service.
                                    - All ranges within a pool must be distinct and cannot overlap.
                                type: int
                                required: true
                            network_security_group_rules:
                                description:
                                    - The maximum number of rules that can be specified across all the endpoints on a Batch pool is 25.
                                    - If no network security group rules are specified.
                                    - default rule will be created to allow inbound access to the specified backendPort.
                                type: list
                                elements: dict
                                suboptions:
                                    priority:
                                        description:
                                            - Priorities within a pool must be unique and are evaluated in order of priority
                                        type: int
                                        required: true
                                    access:
                                        description:
                                            - The action that should be taken for a specified IP address, subnet range or tags.
                                        type: str
                                        choices:
                                            - Allow
                                            - Deny
                                        required: true
                                    source_address_prefix:
                                        description:
                                            - Valid values are a single IP address (i.e. 10.10.10.10).
                                            - Valid values are a single IP address.
                                        type: str
                                    source_port_ranges:
                                        description:
                                            - Valid values are '*' (for all ports 0 - 65535) or arrays of orts or port ranges (i.e. 100-200).
                                        type: list
                                        elements: str
            public_ip_address_configuration:
                description:
                    - This property is only supported on Pools with the virtualMachineConfiguration property.
                type: dict
                suboptions:
                    provision:
                        description:
                            - The public IP Address configuration's provision.
                        type: str
                        default: BatchManaged
                        choices:
                            - BatchManaged
                            - UserManaged
                            - NoPublicIPAddresses
                    ip_address_ids:
                        description:
                            - "The number of IPs specified here limits the maximum size of the Pool
                              100 dedicated nodes or 100 Spot/low-priority nodes can be allocated for each public IP."
                        type: list
                        elements: str
            enable_accelerated_networking:
                description:
                    - Accelerated networking enables single root I/O virtualization (SR-IOV) to a VM.
                    - Which may lead to improved networking performance.
                type: bool
    task_slots_per_node:
        description:
            - The default value is C(1).
            - The maximum value is the smaller of 4 times the number of cores of the vmSize of the pool or 256.
        type: int
        default: 1
    task_scheduling_policy:
        description:
            - Specifies how tasks should be distributed across compute nodes.
        type: dict
        suboptions:
            node_fill_type:
                description:
                    - How tasks should be distributed across compute nodes.
                type: str
                choices:
                    - Spread
                    - Pack
    user_accounts:
        description:
            - The list of user accounts to be created on each node in the pool.
        type: list
        elements: dict
        suboptions:
            name:
                description:
                    - The name of the user account. Names can contain any Unicode characters up to a maximum length of 20.
                type: str
                required: true
            password:
                description:
                    - The password for the user account.
                type: str
                required: true
            elevation_level:
                description:
                    - C(NonAdmin) - the auto user is a standard user without elevated access.
                    - C(Admin) - The auto user is a user with elevated access and operates with full Administrator permissions.
                type: str
                default: NonAdmin
                choices:
                    - NonAdmin
                    - Admin
            linux_user_configuration:
                description:
                    - Properties used to create a user account on a Linux node.
                type: dict
                suboptions:
                    uid:
                        description:
                            - The uid and gid properties must be specified together or not at all.
                            - If not specified the underlying operating system picks the uid.
                        type: int
                    gid:
                        description:
                            - The uid and gid properties must be specified together or not at all.
                            - If not specified the underlying operating system picks the gid.
                        type: int
                    ssh_private_key:
                        description:
                            - The private key must not be password protected.
                            - "The private key is used to automatically configure asymmetric-key based authentication for SSH between nodes in a Linux pool
                               when the pool's enableInterNodeCommunication property is true."
                            - It does this by placing the key pair into the user's .ssh directory.
                            - If not specified, password-less SSH is not configured between nodes (no modification of the user's .ssh directory is done).
                        type: str
            windows_user_configuration:
                description:
                    - Properties used to create a user account on a Windows node.
                type: dict
                suboptions:
                    login_mode:
                        description:
                            - Specifies login mode for the user.
                            - The default value for VirtualMachineConfiguration pools is interactive mode and for CloudServiceConfiguration pools is batch mode.
                        type: str
                        choices:
                            - Batch
                            - Interactive
    metadata:
        description:
            - The Batch service does not assign any meaning to this metadata; it is solely for the use of user code.
        type: list
        elements: dict
        suboptions:
            name:
                description:
                    - The name of the metadata item.
                type: str
                required: true
            value:
                description:
                    - The value of the metadata item.
                type: str
                required: true
    start_task:
        description:
            - In an PATCH (update) operation, this property can be set to an empty object to remove the start task from the pool.
        type: dict
        suboptions:
            command_line:
                description:
                    - The command line does not run under a shell, and therefore cannot take advantage of shell features such as environment variable expansion.
                    - If you want to take advantage of such features, you should invoke the shell in the command line.
                    - Required if any other properties of the startTask are specified.
                type: str
            resource_files:
                description:
                    - A list of files that the Batch service will download to the compute node before running the command line.
                    - A single file or multiple files to be downloaded to a compute node.
                type: list
                elements: dict
                suboptions:
                    auto_storage_container_name:
                        description:
                            - The autoStorageContainerName, storageContainerUrl and httpUrl properties are mutually exclusive and one of them must be specified.
                        type: str
                    storage_container_url:
                        description:
                            - The autoStorageContainerName, storageContainerUrl and httpUrl properties are mutually exclusive and one of them must be specified.
                            - This URL must be readable and listable from compute nodes.
                            - There are three ways to get such a URL for a container in Azure storage.
                            - "Include a Shared Access Signature (SAS) granting read and list permissions on  the container,
                              use a managed identity with read and list permissions, or set the ACL for the container to allow public access."
                        type: str
                    http_url:
                        description:
                            - The autoStorageContainerName, storageContainerUrl and httpUrl properties are mutually exclusive and one of them must be specified.
                            - If the URL points to Azure Blob Storage, it must be readable from compute nodes.
                            - There are three ways to get such a URL for a blob in Azure storage.
                            - "Include a Shared Access Signature (SAS) granting read permissions on the blob, use a managed identity with read permission,
                              or set the ACL for the blob or its container to allow public access."
                        type: str
                    blob_prefix:
                        description:
                            - The property is valid only when autoStorageContainerName or storageContainerUrl is used.
                            - This prefix can be a partial filename or a subdirectory.
                            - If a prefix is not specified, all the files in the container will be downloaded.
                        type: str
                    file_path:
                        description:
                            - If the httpUrl property is specified, the filePath is required and
                              describes the path which the file will be downloaded to, including the filename.
                            - If the autoStorageContainerName or storageContainerUrl property is specified, filePath is optional and
                              is the directory to download the files to.
                            - "In the case where filePath is used as a directory, any directory structure already associated with the input data
                              will be retained in full and appended to the specified filePath directory."
                            - The specified relative path cannot break out of  the task's working directory.
                        type: str
                    file_mode:
                        description:
                            - This property applies only to files being downloaded to Linux compute nodes.
                            - It will be ignored if it is specified for a resourceFile which will be downloaded to a Windows node.
                            - If this property is not specified for a Linux node, then a default value of 0770 is applied to the file.
                        type: str
                    identity_reference:
                        description:
                            - The reference to a user assigned identity associated with the Batch pool which a compute node will use.
                        type: dict
                        suboptions:
                            resource_id:
                                description:
                                    - The ARM resource id of the user assigned identity.
                                type: str
            environment_settings:
                description:
                    - A list of environment variable settings for the start task.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - The name of the environment variable.
                        type: str
                        required: true
                    value:
                        description:
                            - The value of the environment variable.
                        type: str
            user_identity:
                description:
                    - If omitted, the task runs as a non-administrative user unique to the task.
                type: dict
                suboptions:
                    user_name:
                        description:
                            - The username of the task user identity.
                            - The userName and autoUser properties are mutually exclusive; you must specify one but not both.
                        type: str
                    auto_user:
                        description:
                            - The autouser config of the task user identity.
                            - The userName and autoUser properties are mutually exclusive; you must specify one but not both.
                        type: dict
                        suboptions:
                            scope:
                                description:
                                    - The scope of the auto user scope.
                                    - The default value is Pool.
                                    - If the pool is running Windows a value of Task should be specified if stricter isolation between tasks is required.
                                type: str
                                default: Pool
                                choices:
                                    - Task
                                    - Pool
                            elevation_level:
                                description:
                                    - The auto user elevation level.
                                type: str
                                default: NonAdmin
                                choices:
                                    - NonAdmin
                                    - Admin
            max_task_retry_count:
                description:
                    - The Batch service retries a task if its exit code is nonzero.
                    - Note that this value specifically controls the number of retries.
                    - The Batch service will try the task once, and may then retry up to this limit.
                type: int
                default: 0
            wait_for_success:
                description:
                    - If true and the start task fails on a compute node.
                    - The Batch service retries the start task up to its maximum retry count (maxTaskRetryCount).
                    - "If the task has still not completed successfully after all retries, then the Batch service marks the compute node unusable,
                      and will not schedule tasks to it."
                    - This condition can be detected via the node state and scheduling error detail.
                    - If false, the Batch service will not wait for the start task to complet.
                type: bool
            container_settings:
                description:
                    - "When this is specified, all directories recursively below the AZ_BATCH_NODE_ROOT_DIR are mapped into the container,
                      all task environment variables are mapped into the container, and the task command line is executed in the container."
                type: dict
                suboptions:
                    container_run_options:
                        description:
                            - "These additional options are supplied as arguments to the 'docker create' command,
                              in addition to those controlled by the Batch Service."
                        type: str
                    image_name:
                        description:
                            - This is the full image reference, as would be specified to "docker pull".
                            - If no tag is provided as part of the image name, the tag ":latest" is used as a default.
                        type: str
                    registry:
                        description:
                            - This setting can be omitted if was already provided at pool creation.
                        type: dict
                        suboptions:
                            user_name:
                                description:
                                    - he user name to log into the registry server.
                                type: str
                            password:
                                description:
                                    - The password to log into the registry server.
                                type: str
                            registry_server:
                                description:
                                    - If omitted, the default is "docker.io".
                                type: str
                                default: 'docker.io'
                            identity_reference:
                                description:
                                    - The reference to a user assigned identity associated with the Batch pool which a compute node will use.
                                type: dict
                                suboptions:
                                    resource_id:
                                        description:
                                            - The ARM resource id of the user assigned identity.
                                        type: str
                    working_directory:
                        description:
                            - A flag to indicate where the container task working directory is.
                        type: str
                        choices:
                            - TaskWorkingDirectory
                            - ContainerImageDefault
    application_packages:
        description:
            - Changes to application package references affect all new compute nodes joining the pool.
            - But do not affect compute nodes that are already in the pool until they are rebooted or reimaged.
            - There is a maximum of 10 application package references on any given pool.
        type: list
        elements: dict
        suboptions:
            id:
                description:
                    - The ID of the application package to install.
                    - This must be inside the same batch account as the pool.
                    - This can either be a reference to a specific version or the default version if one exists.
                type: str
                required: true
            version:
                description:
                    - "If this is omitted, and no default version is specified for this application,
                      the request fails with the error code InvalidApplicationPackageReferences."
                    - If you are calling the REST API directly, the HTTP status code is 409.
                type: str
    certificates:
        description:
            - For Windows compute nodes, the Batch service installs the certificates to the specified certificate store and location.
            - "For Linux compute nodes, the certificates are stored in a directory inside the task working directory and
              an environment variable AZ_BATCH_CERTIFICATES_DIR is supplied to the task to query for this location."
            - "For certificates with visibility of 'remoteUser', a 'certs' directory is created in the user's home directory and
              certificates are placed in that directory."
        type: list
        elements: dict
        suboptions:
            id:
                description:
                    - The fully qualified ID of the certificate to install on the pool.
                    - This must be inside the same batch account as the pool.
                type: str
                required: true
            store_location:
                description:
                    - The default value is C(CurrentUser).
                    - This property is applicable only for pools configured with Windows nodes.
                    - "For Linux compute nodes, the certificates are stored in a directory inside the task working directory and
                      an environment variable AZ_BATCH_CERTIFICATES_DIR is supplied to the task to query for this location."
                    - "For certificates with visibility of 'remoteUser', a 'certs' directory is created in the user's home directory
                      and certificates are placed in that directory."
                type: str
                default: CurrentUser
                choices:
                    - CurrentUser
                    - LocalMachine
            store_name:
                description:
                    - This property is applicable only for pools configured with Windows nodes.
                    - This created with cloudServiceConfiguration, or with virtualMachineConfiguration using a Windows image reference.
                type: str
                default: My
                choices:
                    - My
                    - Root
                    - CA
                    - Trust
                    - Disallowed
                    - TrustedPeople
                    - TrustedPublisher
                    - AuthRoot
                    - AddressBook
            visibility:
                description:
                    - Which user accounts on the compute node should have access to the private data of the certificate.
                type: list
                elements: str
                choices:
                    - StartTask
                    - Task
                    - RemoteUser
    application_licenses:
        description:
            - The list of application licenses must be a subset of available Batch service application licenses.
            - If a license is requested which is not supported, pool creation will fail.
        type: list
        elements: str
    mount_configuration:
        description:
            - This supports Azure Files, NFS, CIFS/SMB, and Blobfuse.
        type: list
        elements: dict
        suboptions:
            azure_blob_file_system_configuration:
                description:
                    - Configuration of the azure blob file system.
                    - This property is mutually exclusive with all other properties.
                type: dict
                suboptions:
                    account_name:
                        description:
                            - The Azure Storage Account name.
                        type: str
                        required: true
                    container_name:
                        description:
                            - The Azure Blob Storage Container name.
                        type: str
                        required: true
                    account_key:
                        description:
                            - This property is mutually exclusive with both sasKey and identity; exactly one must be specified.
                        type: str
                    sas_key:
                        description:
                            - This property is mutually exclusive with both accountKey and identity; exactly one must be specified.
                        type: str
                    blobfuse_options:
                        description:
                            - These are C(net use) options in Windows and C(mount) options in Linux.
                        type: str
                        choices:
                            - 'net use'
                            - mount
                    relative_mount_path:
                        description:
                            - "All file systems are mounted relative to the Batch mounts directory,
                              accessible via the AZ_BATCH_NODE_MOUNTS_DIR environment variable."
                        type: str
                        required: true
                    identity_reference:
                        description:
                            - This property is mutually exclusive with both accountKey and sasKey; exactly one must be specified.
                        type: dict
                        suboptions:
                            resource_id:
                                description:
                                    - The ARM resource id of the user assigned identity.
                                type: str
            nfs_mount_configuration:
                description:
                    - Configuration of the nfs mount.
                    - This property is mutually exclusive with all other properties.
                type: dict
                suboptions:
                    source:
                        description:
                            - The URI of the file system to mount.
                        type: str
                        required: true
                    relative_mount_path:
                        description:
                            - "All file systems are mounted relative to the Batch mounts directory,
                              accessible via the AZ_BATCH_NODE_MOUNTS_DIR environment variable."
                        type: str
                        required: true
                    mount_options:
                        description:
                            - These are C(net use) options in Windows and C(mount) options in Linux.
                        type: str
                        choices:
                            - 'net use'
                            - mount
            cifs_mount_configuration:
                description:
                    - Configuration of the cifs mount.
                    - This property is mutually exclusive with all other properties.
                type: dict
                suboptions:
                    user_name:
                        description:
                            - The user to use for authentication against the CIFS file system.
                        type: str
                        required: true
                    source:
                        description:
                            - The URI of the file system to mount.
                        type: str
                        required: true
                    relative_mount_path:
                        description:
                            - "All file systems are mounted relative to the Batch mounts directory,
                              accessible via the AZ_BATCH_NODE_MOUNTS_DIR environment variable."
                        type: str
                        required: true
                    mount_options:
                        description:
                            -  These are C(net use) options in Windows and C(mount) options in Linux.
                        type: str
                        choices:
                            - 'net use'
                            - mount
                    password:
                        description:
                            - The password to use for authentication against the CIFS file system.
                        type: str
                        required: true
            azure_file_share_configuration:
                description:
                    - Configuration of the azure file share.
                    - This property is mutually exclusive with all other properties.
                type: dict
                suboptions:
                    account_name:
                        description:
                            - The Azure Storage account name.
                        type: str
                        required: true
                    azure_file_url:
                        description:
                            -  This is of the form 'https://{account}.file.core.windows.net/'.
                        type: str
                        required: true
                    account_key:
                        description:
                            - The Azure Storage account key.
                        type: str
                        required: true
                    relative_mount_path:
                        description:
                            - "All file systems are mounted relative to the Batch mounts directory,
                              accessible via the AZ_BATCH_NODE_MOUNTS_DIR environment variable."
                        type: str
                        required: true
                    mount_options:
                        description:
                            - These are C(net use) options in Windows and C(mount) options in Linux.
                        type: str
                        choices:
                            - 'net use'
                            - mount
    target_node_communication_mode:
        description:
            - If omitted, the default value is C(Default).
        type: str
        default: Default
        choices:
            - Default
            - Classic
            - Simplified
    upgrade_policy:
        description:
            - Describes an upgrade policy.
        type: dict
        suboptions:
            mode:
                description:
                    - Specifies the mode of an upgrade to virtual machines in the scale set.
                type: str
                choices:
                    - automatic
                    - manual
                    - rolling
                required: true
            automatic_os_upgrade_policy:
                description:
                    -  The configuration parameters used for performing automatic OS upgrade.
                type: dict
                suboptions:
                    disable_automatic_rollback:
                        description:
                            - Whether OS image rollback feature should be disabled.
                        type: bool
                    enable_automatic_os_upgrade:
                        description:
                            - "Indicates whether OS upgrades should automatically be applied to scale set instances in a rolling fashion
                              when a newer version of the OS image becomes available."
                        type: bool
                    use_rolling_upgrade_policy:
                        description:
                            - Indicates whether rolling upgrade policy should be used during Auto OS Upgrade.
                            - Auto OS Upgrade will fallback to the default policy if no policy is defined on the VMSS.
                        type: bool
                    os_rolling_upgrade_deferral:
                        description:
                            - Defer OS upgrades on the TVMs if they are running tasks.
                        type: bool
            rolling_upgrade_policy:
                description:
                    - This property is only supported on Pools with the virtualMachineConfiguration property.
                type: dict
                suboptions:
                    enable_cross_zone_upgrade:
                        description:
                            - Allow VMSS to ignore AZ boundaries when constructing upgrade batches.
                            - Take into consideration the Update Domain and maxBatchInstancePercent to determine the batch size.
                            - If this field is not set, Azure Azure Batch will not set its default value.
                            - "The value of enableCrossZoneUpgrade on the created VirtualMachineScaleSet
                              will be decided by the default configurations on VirtualMachineScaleSet."
                            - This field is able to be set to true or false only when using NodePlacementConfiguration as Zonal.
                        type: bool
                    max_batch_instance_percent:
                        description:
                            - The maximum percent of total virtual machine instances that will be upgraded simultaneously by the rolling upgrade in one batch.
                            - "As this is a maximum, unhealthy instances in previous or future batches can cause the percentage of instances
                              in a batch to decrease to ensure higher reliability."
                            - The value of this field should be between 5 and 100, inclusive.
                            - "If both maxBatchInstancePercent and maxUnhealthyInstancePercent are assigned with value,
                              the value of maxBatchInstancePercent should not be more than maxUnhealthyInstancePercent."
                        type: int
                    max_unhealthy_instance_percent:
                        description:
                            - "The maximum percentage of the total virtual machine instances in the scale set that can be simultaneously unhealthy,
                              either as a result of being upgraded, or by being found in an unhealthy state by the virtual machine health checks
                              before the rolling upgrade aborts."
                            - This constraint will be checked prior to starting any batch.
                            - "If both maxBatchInstancePercent and maxUnhealthyInstancePercent are assigned with value,
                              the value of maxBatchInstancePercent should not be more than maxUnhealthyInstancePercent."
                        type: int
                    max_unhealthy_upgraded_instance_percent:
                        description:
                            - The maximum percentage of upgraded virtual machine instances that can be found to be in an unhealthy state.
                            - This check will happen after each batch is upgraded.
                            - If this percentage is ever exceeded, the rolling update aborts.
                            - The value of this field should be between 0 and 100, inclusive.
                        type: int
                    pause_time_between_batches:
                        description:
                            - The wait time between completing the update for all virtual machines in one batch and starting the next batch.
                            - The time duration should be specified in ISO 8601 format.
                        type: str
                    prioritize_unhealthy_instances:
                        description:
                            - Upgrade all unhealthy instances in a scale set before any healthy instances.
                        type: bool
                    rollback_failed_instances_on_policy_breach:
                        description:
                            - Rollback failed instances to previous model if the Rolling Upgrade policy is violated.
                        type: bool
    resource_tags:
        description:
            - The user-defined tags to be associated with the Azure Batch Pool.
            - When specified, these tags are propagated to the backing Azure resources associated with the pool.
            - This property can only be specified when the Batch account was created with the poolAllocationMode property set to 'UserSubscription'.
        type: dict
    is_disable_auto_scale:
        description:
            - Whether disables automatic scaling for a pool.
        type: bool
        default: false
    is_stop_resize:
        description:
            - Whether stops an ongoing resize operation on the pool.
        type: bool
        default: false
    state:
        description:
            - Assert the state of the Batch Account Pool.
            - Use C(present) to create or update a Batch Account Pool and C(absent) to delete it.
        default: present
        type: str
        choices:
            - present
            - absent

extends_documentation_fragment:
    - azure.azcollection.azure

author:
    - xuzhang3 (@xuzhang3)
    - Fred Sun (@Fred-sun)
'''

EXAMPLES = '''
- name: Create a new batch account pool
  azure_rm_batchaccountpool:
    resource_group: "{{ resource_group }}"
    batch_account_name: "{{ batch_account_name }}"
    name: "pool{{ batch_account_name }}--004"
    deployment_configuration:
      virtual_machine_configuration:
        image_reference:
          offer: ubuntu-hpc
          publisher: microsoft-dsvm
          sku: 2204
          version: latest
        node_agent_sku_id: batch.node.ubuntu 22.04
        node_placement_configuration:
          policy: Regional
        os_disk:
          caching: None
          managed_disk:
            storage_account_type: Premium_LRS
    display_name: "fredtest01"
    identity:
      type: UserAssigned
      user_assigned_identities:
        '/subscriptions/xxx-xxx/resourceGroups/testRG/providers/Microsoft.ManagedIdentity/userAssignedIdentities/AzSecPackAutoConfigUA-westus':
          client_id: xxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
          principal_id: yyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
        '/subscriptions/xxx-xxx/resourceGroups/yishitest/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ystestidentity':
          client_id: yyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
          principal_id: xxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    inter_node_communication: Disabled
    network_configuration:
      dynamic_vnet_assignment_scope: none
      subnet_id: "/subscriptions/xxx-xxx/resourceGroups/testRG/providers/Microsoft.Network/virtualNetworks/vnet02/subnets/default"
      endpoint_configuration:
        inbound_nat_pools:
          - backend_port: 33
            frontend_port_range_end: 49999
            frontend_port_range_start: 1
            name: nat02
            protocol: UDP
      public_ip_address_configuration:
        provision: BatchManaged
    scale_settings:
      fixed_scale:
        resize_timeout: PT15M
        target_dedicated_nodes: 0
        target_low_priority_nodes: 0
    target_node_communication_mode: Default
    task_scheduling_policy:
      node_fill_type: Pack
    task_slots_per_node: 1
    vm_size: STANDARD_D2S_V3
    upgrade_policy:
      mode: manual
      rolling_upgrade_policy:
        max_batch_instance_percent: 20
        max_unhealthy_instance_percent: 20
        max_unhealthy_upgraded_instance_percent: 20
        pause_time_between_batches: P0D
        rollback_failed_instances_on_policy_breach: false
      automatic_os_upgrade_policy:
        disable_automatic_rollback: false
        enable_automatic_os_upgrade: false
        os_rolling_upgrade_deferral: false
        use_rolling_upgrade_policy: false

- name: Delete the Batch Account Pool
  azure_rm_batchaccountpool:
    resource_group: MyResGroup
    name: pool01
    batch_account_name: mybatchaccount
    state: absent
'''

RETURN = '''
state:
    description:
        - Contains information about an pool in a Batch account.
    type: dict
    returned: always
    sample: {
                "allocation_state": "Steady",
                "allocation_state_transition_time": "2024-11-05T08:58:16.803138Z",
                "batch_account_name": "fredbatch02",
                "creation_time": "2024-11-05T08:58:15.399345Z",
                "current_dedicated_nodes": 0,
                "current_low_priority_nodes": 0,
                "deployment_configuration": {
                    "virtual_machine_configuration": {
                        "image_reference": {
                            "offer": "ubuntu-hpc",
                            "publisher": "microsoft-dsvm",
                            "sku": "2204",
                            "version": "latest"
                        },
                        "node_agent_sku_id": "batch.node.ubuntu 22.04",
                        "node_placement_configuration": {
                            "policy": "Regional"
                        },
                        "os_disk": {
                            "caching": "None",
                            "managed_disk": {
                                "storage_account_type": "Premium_LRS"
                            }
                        }
                    }
                },
                "etag": "0x8DCFD77FC345CFE",
                "id": "/subscriptions/xxx-xxx/resourceGroups/testRG/providers/Microsoft.Batch/batchAccounts/batch01/pools/pool01",
                "inter_node_communication": "Disabled",
                "last_modified": "2024-11-05T08:58:15.399347Z",
                "name": "poolfredbatch02--002",
                "network_configuration": {
                    "dynamic_vnet_assignment_scope": "None",
                    "enable_accelerated_networking": false,
                    "endpoint_configuration": {
                        "inbound_nat_pools": [
                            {
                                "backend_port": 33,
                                "frontend_port_range_end": 49999,
                                "frontend_port_range_start": 1,
                                "name": "nat02",
                                "protocol": "UDP"
                            }
                        ]
                    },
                    "public_ip_address_configuration": {
                        "provision": "BatchManaged"
                    },
                    "subnet_id": "/subscriptions/xxx-xxx/resourceGroups/testrg/providers/Microsoft.Network/virtualNetworks/vnet01/subnets/default"
                },
                "provisioning_state": "Succeeded",
                "provisioning_state_transition_time": "2024-11-05T08:58:15.399345Z",
                "resize_operation_status": {
                    "node_deallocation_option": "Requeue",
                    "resize_timeout": "PT15M",
                    "start_time": "2024-11-05T08:58:15.399317Z",
                    "target_dedicated_nodes": 0
                },
                "resource_group": "v-xisuRG06",
                "scale_settings": {
                    "fixed_scale": {
                        "resize_timeout": "PT15M",
                        "target_dedicated_nodes": 0,
                        "target_low_priority_nodes": 0
                    }
                },
                "target_node_communication_mode": "Default",
                "task_scheduling_policy": {
                    "node_fill_type": "Pack"
                },
                "task_slots_per_node": 1,
                "type": "Microsoft.Batch/batchAccounts/pools",
                "upgrade_policy": {
                    "automatic_os_upgrade_policy": {
                        "disable_automatic_rollback": false,
                        "enable_automatic_os_upgrade": false,
                        "os_rolling_upgrade_deferral": false,
                        "use_rolling_upgrade_policy": false
                    },
                    "mode": "Manual",
                    "rolling_upgrade_policy": {
                        "max_batch_instance_percent": 20,
                        "max_unhealthy_instance_percent": 20,
                        "max_unhealthy_upgraded_instance_percent": 20,
                        "pause_time_between_batches": "P0D",
                        "rollback_failed_instances_on_policy_breach": false
                    }
                },
                "vm_size": "STANDARD_D2S_V3"
            }
'''

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common_ext import AzureRMModuleBaseExt

try:
    from azure.core.polling import LROPoller
    from azure.core.exceptions import ResourceNotFoundError
except ImportError:
    # This is handled in azure_rm_common
    pass


class AzureRMBatchAccountPool(AzureRMModuleBaseExt):
    """Configuration class for an Azure RM Batch Account Pool resource"""

    def __init__(self):
        self.module_arg_spec = dict(
            resource_group=dict(
                required=True,
                type='str'
            ),
            batch_account_name=dict(
                type='str',
                required=True,
            ),
            name=dict(
                required=True,
                type='str'
            ),
            identity=dict(
                type='dict',
                options=dict(
                    type=dict(type='str', required=True, choices=['None', 'UserAssigned']),
                    user_assigned_identities=dict(
                        type='dict',
                    )
                )
            ),
            display_name=dict(
                type='str'
            ),
            vm_size=dict(
                type='str'
            ),
            deployment_configuration=dict(
                type='dict',
                options=dict(
                    cloud_service_configuration=dict(
                        type='dict',
                        options=dict(
                            os_family=dict(type='str', default='*'),
                            os_version=dict(type='str')
                        )
                    ),
                    virtual_machine_configuration=dict(
                        type='dict',
                        options=dict(
                            image_reference=dict(
                                type='dict',
                                required=True,
                                options=dict(
                                    publisher=dict(type='str'),
                                    offer=dict(type='str'),
                                    sku=dict(type='str'),
                                    version=dict(type='str'),
                                    id=dict(type='str'),
                                )
                            ),
                            node_agent_sku_id=dict(type='str', required=True),
                            windows_configuration=dict(
                                type='dict',
                                options=dict(
                                    enable_automatic_updates=dict(type='bool', default=True)
                                )
                            ),
                            data_disks=dict(
                                type='list',
                                elements='dict',
                                options=dict(
                                    lun=dict(type='int', required=True),
                                    caching=dict(type='str', choices=['None', 'ReadOnly', 'ReadWrite']),
                                    disk_size_gb=dict(type='int', required=True),
                                    storage_account_type=dict(
                                        type='str',
                                        default='Standard_LRS',
                                        choices=['Standard_LRS', 'Premium_LRS', 'StandardSSD_LRS']
                                    )
                                )
                            ),
                            license_type=dict(
                                type='str'
                            ),
                            container_configuration=dict(
                                type='dict',
                                options=dict(
                                    type=dict(type='str', choices=['DockerCompatible', 'CriCompatible'], required=True),
                                    container_image_names=dict(type='list', elements='str'),
                                    container_registries=dict(
                                        type='list',
                                        elements='dict',
                                        options=dict(
                                            user_name=dict(type='str'),
                                            password=dict(type='str', no_log=True),
                                            registry_server=dict(type='str', default='docker.io'),
                                            identity_reference=dict(
                                                type='dict',
                                                options=dict(
                                                    resource_id=dict(type='str')
                                                )
                                            )
                                        )
                                    )
                                )
                            ),
                            disk_encryption_configuration=dict(
                                type='dict',
                                options=dict(
                                    targets=dict(type='list', elements='str', choices=['TemporaryDisk', 'OsDisk'])
                                )
                            ),
                            node_placement_configuration=dict(
                                type='dict',
                                options=dict(
                                    policy=dict(
                                        type='str',
                                        choices=['Zonal', 'Regional']
                                    )
                                ),
                            ),
                            extensions=dict(
                                type='list',
                                elements='dict',
                                options=dict(
                                    name=dict(type='str', required=True),
                                    publisher=dict(type='str', required=True),
                                    type=dict(type='str', required=True),
                                    type_handler_version=dict(type='str'),
                                    auto_upgrade_minor_version=dict(type='bool'),
                                    enable_automatic_upgrade=dict(type='bool'),
                                    provision_after_extensions=dict(type='list', elements='str'),
                                    settings=dict(type='json'),
                                    protected_settings=dict(type='json')
                                )
                            ),
                            os_disk=dict(
                                type='dict',
                                options=dict(
                                    caching=dict(
                                        type='str',
                                        choices=['ReadOnly', 'ReadWrite', 'None']
                                    ),
                                    write_accelerator_enabled=dict(type='bool'),
                                    disk_size_gb=dict(type='int'),
                                    managed_disk=dict(
                                        type='dict',
                                        options=dict(
                                            storage_account_type=dict(type='str', choices=["Standard_LRS", "Premium_LRS", "StandardSSD_LRS"])
                                        )
                                    ),
                                    ephemeral_os_disk_settings=dict(
                                        type='dict',
                                        options=dict(
                                            placement=dict(type='str')
                                        )
                                    )
                                )
                            ),
                            security_profile=dict(
                                type='dict',
                                options=dict(
                                    security_type=dict(type='str', default='trustedLaunch'),
                                    encryption_at_host=dict(type='bool'),
                                    uefi_settings=dict(
                                        type='dict',
                                        options=dict(
                                            secure_boot_enabled=dict(type='bool'),
                                            v_tpm_enabled=dict(type='bool')
                                        )
                                    )
                                )
                            ),
                            service_artifact_reference=dict(
                                type='dict',
                                options=dict(
                                    id=dict(type='str')
                                )
                            )
                        )
                    )
                )
            ),
            scale_settings=dict(
                type='dict',
                options=dict(
                    fixed_scale=dict(
                        type='dict',
                        options=dict(
                            resize_timeout=dict(type='str', default='P15M'),
                            target_dedicated_nodes=dict(type='int'),
                            target_low_priority_nodes=dict(type='int'),
                            node_deallocation_option=dict(type='str', choices=["Requeue", "Terminate", "TaskCompletion", "RetainedData"])
                        )
                    ),
                    auto_scale=dict(
                        type='dict',
                        options=dict(
                            formula=dict(type='str', required=True),
                            evaluation_interval=dict(type='str', default='P15M'),
                        )
                    )
                )
            ),
            inter_node_communication=dict(
                type='str',
                choices=['Enabled', 'Disabled']
            ),
            network_configuration=dict(
                type='dict',
                options=dict(
                    subnet_id=dict(type='str'),
                    dynamic_vnet_assignment_scope=dict(type='str', choices=['none', 'job']),
                    endpoint_configuration=dict(
                        type='dict',
                        options=dict(
                            inbound_nat_pools=dict(
                                type='list',
                                elements='dict',
                                options=dict(
                                    name=dict(type='str', required=True),
                                    protocol=dict(type='str', choices=['UDP', 'TCP'], required=True),
                                    backend_port=dict(type='int', required=True),
                                    frontend_port_range_start=dict(type='int', required=True),
                                    frontend_port_range_end=dict(type='int', required=True),
                                    network_security_group_rules=dict(
                                        type='list',
                                        elements='dict',
                                        options=dict(
                                            priority=dict(type='int', required=True),
                                            access=dict(type='str', required=True, choices=['Allow', 'Deny']),
                                            source_address_prefix=dict(type='str'),
                                            source_port_ranges=dict(type='list', elements='str')
                                        )
                                    )
                                )
                            )
                        )
                    ),
                    public_ip_address_configuration=dict(
                        type='dict',
                        options=dict(
                            provision=dict(type='str', default='BatchManaged', choices=['BatchManaged', 'UserManaged', 'NoPublicIPAddresses']),
                            ip_address_ids=dict(
                                type='list',
                                elements='str'
                            )
                        )
                    ),
                    enable_accelerated_networking=dict(
                        type='bool'
                    )
                )
            ),
            task_slots_per_node=dict(
                type='int',
                default=1
            ),
            task_scheduling_policy=dict(
                type='dict',
                options=dict(
                    node_fill_type=dict(type='str', choices=['Spread', 'Pack'])
                )
            ),
            user_accounts=dict(
                type='list',
                elements='dict',
                options=dict(
                    name=dict(type='str', required=True),
                    password=dict(type='str', required=True, no_log=True),
                    elevation_level=dict(type='str', choices=['NonAdmin', 'Admin'], default='NonAdmin'),
                    linux_user_configuration=dict(
                        type='dict',
                        options=dict(
                            uid=dict(type='int',),
                            gid=dict(type='int'),
                            ssh_private_key=dict(type='str', no_log=True),
                        )
                    ),
                    windows_user_configuration=dict(
                        type='dict',
                        options=dict(
                            login_mode=dict(type='str', choices=['Batch', 'Interactive'])
                        )
                    )
                )
            ),
            metadata=dict(
                type='list',
                elements='dict',
                options=dict(
                    name=dict(type='str', required=True),
                    value=dict(type='str', required=True)
                )
            ),
            start_task=dict(
                type='dict',
                options=dict(
                    command_line=dict(type='str'),
                    resource_files=dict(
                        type='list',
                        elements='dict',
                        options=dict(
                            auto_storage_container_name=dict(type='str'),
                            storage_container_url=dict(type='str'),
                            http_url=dict(type='str'),
                            blob_prefix=dict(type='str'),
                            file_path=dict(type='str'),
                            file_mode=dict(type='str'),
                            identity_reference=dict(
                                type='dict',
                                options=dict(
                                    resource_id=dict(type='str')
                                )
                            )
                        )
                    ),
                    environment_settings=dict(
                        type='list',
                        elements='dict',
                        options=dict(
                            name=dict(type='str', required=True),
                            value=dict(type='str')
                        )
                    ),
                    user_identity=dict(
                        type='dict',
                        options=dict(
                            user_name=dict(type='str'),
                            auto_user=dict(
                                type='dict',
                                options=dict(
                                    scope=dict(type='str', default='Pool', choices=['Pool', 'Task']),
                                    elevation_level=dict(type='str', default='NonAdmin', choices=['NonAdmin', 'Admin'])
                                )
                            )
                        )
                    ),
                    max_task_retry_count=dict(
                        type='int',
                        default=0,
                    ),
                    wait_for_success=dict(type='bool'),
                    container_settings=dict(
                        type='dict',
                        options=dict(
                            container_run_options=dict(type='str'),
                            image_name=dict(type='str'),
                            working_directory=dict(type='str', choices=['TaskWorkingDirectory', 'ContainerImageDefault']),
                            registry=dict(
                                type='dict',
                                options=dict(
                                    user_name=dict(type='str'),
                                    password=dict(type='str', no_log=True),
                                    registry_server=dict(type='str', default='docker.io'),
                                    identity_reference=dict(
                                        type='dict',
                                        options=dict(
                                            resource_id=dict(type='str')
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            ),
            application_packages=dict(
                type='list',
                elements='dict',
                options=dict(
                    id=dict(type='str', required=True),
                    version=dict(type='str')
                )
            ),
            certificates=dict(
                type='list',
                elements='dict',
                options=dict(
                    id=dict(type='str', required=True),
                    store_location=dict(type='str', default='CurrentUser', choices=['CurrentUser', 'LocalMachine']),
                    store_name=dict(
                        type='str',
                        default='My',
                        choices=['My', 'Root', 'CA', 'Trust', 'Disallowed', 'TrustedPeople', 'TrustedPublisher', 'AuthRoot', 'AddressBook']
                    ),
                    visibility=dict(type='list', elements='str', choices=['StartTask', 'Task', 'RemoteUser'])
                )
            ),
            application_licenses=dict(
                type='list',
                elements='str'
            ),
            mount_configuration=dict(
                type='list',
                elements='dict',
                options=dict(
                    azure_blob_file_system_configuration=dict(
                        type='dict',
                        options=dict(
                            account_name=dict(type='str', required=True),
                            container_name=dict(type='str', required=True),
                            account_key=dict(type='str', no_log=True),
                            sas_key=dict(type='str', no_log=True),
                            blobfuse_options=dict(type='str', choices=['net use', 'mount']),
                            relative_mount_path=dict(type='str', required=True),
                            identity_reference=dict(
                                type='dict',
                                options=dict(
                                    resource_id=dict(type='str')
                                )
                            )
                        )
                    ),
                    nfs_mount_configuration=dict(
                        type='dict',
                        options=dict(
                            source=dict(type='str', required=True),
                            relative_mount_path=dict(type='str', required=True),
                            mount_options=dict(type='str', choices=['net use', 'mount'])
                        )
                    ),
                    cifs_mount_configuration=dict(
                        type='dict',
                        options=dict(
                            user_name=dict(type='str', required=True),
                            source=dict(type='str', required=True),
                            relative_mount_path=dict(type='str', required=True),
                            mount_options=dict(type='str', choices=['net use', 'mount']),
                            password=dict(type='str', no_log=True, required=True)
                        )
                    ),
                    azure_file_share_configuration=dict(
                        type='dict',
                        options=dict(
                            account_name=dict(type='str', required=True),
                            azure_file_url=dict(type='str', required=True),
                            account_key=dict(type='str', required=True, no_log=True),
                            relative_mount_path=dict(type='str', required=True),
                            mount_options=dict(type='str', choices=['net use', 'mount'])
                        )
                    )
                )
            ),
            target_node_communication_mode=dict(
                type='str',
                default='Default',
                choices=["Default", "Classic", "Simplified"]
            ),
            upgrade_policy=dict(
                type='dict',
                options=dict(
                    mode=dict(type='str', required=True, choices=['automatic', 'manual', 'rolling']),
                    automatic_os_upgrade_policy=dict(
                        type='dict',
                        options=dict(
                            disable_automatic_rollback=dict(type='bool'),
                            enable_automatic_os_upgrade=dict(type='bool'),
                            use_rolling_upgrade_policy=dict(type='bool'),
                            os_rolling_upgrade_deferral=dict(type='bool'),
                        )
                    ),
                    rolling_upgrade_policy=dict(
                        type='dict',
                        options=dict(
                            enable_cross_zone_upgrade=dict(type='bool'),
                            max_batch_instance_percent=dict(type='int'),
                            max_unhealthy_instance_percent=dict(type='int'),
                            max_unhealthy_upgraded_instance_percent=dict(type='int'),
                            pause_time_between_batches=dict(type='str'),
                            prioritize_unhealthy_instances=dict(type='bool'),
                            rollback_failed_instances_on_policy_breach=dict(type='bool')
                        )
                    )
                )
            ),
            resource_tags=dict(
                type='dict',
            ),
            is_disable_auto_scale=dict(
                type='bool',
                default=False
            ),
            is_stop_resize=dict(
                type='bool',
                default=False
            ),
            state=dict(
                type='str',
                default='present',
                choices=['present', 'absent']
            )
        )

        self.batch_account_name = None
        self.name = None
        self.resource_group = None
        self.is_disable_auto_scale = None
        self.is_stop_resize = None
        self.results = dict(changed=False)
        self.state = None
        self.body = dict()

        super(AzureRMBatchAccountPool, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                      supports_check_mode=True,
                                                      supports_tags=False)

    def exec_module(self, **kwargs):
        """Main module execution method"""

        for key in list(self.module_arg_spec.keys()):
            if hasattr(self, key):
                setattr(self, key, kwargs[key])
            elif kwargs[key] is not None:
                self.body[key] = kwargs[key]

        response = None
        changed = False

        old_response = self.get_batchaccount_pool()

        if not old_response:
            self.log("Batch Account Pool instance doesn't exist")
            if self.state == 'absent':
                self.log("Old instance didn't exist")
            else:
                changed = True
                if not self.check_mode:
                    response = self.create_batchaccount_pool()
        else:
            self.log("Batch Account Pool instance already exists")
            if self.state == 'absent':
                if not self.check_mode:
                    changed = True
                    response = self.delete_batchaccount_pool()
            else:
                if not self.default_compare({}, self.body, old_response, '', dict(compare=[])):
                    changed = True
                if not self.check_mode and changed:
                    response = self.update_batchaccount_pool()
                if self.is_stop_resize and not self.check_mode:
                    changed = True
                    self.stop_resize_pool()
                if self.is_disable_auto_scale and not self.check_mode:
                    changed = True
                    self.disable_auto_scale_pool()

        self.results = dict(
            changed=changed,
            state=self.get_batchaccount_pool(),
        )
        return self.results

    def create_batchaccount_pool(self):
        '''
        Creates Batch Account Pool with the specified configuration.
        '''
        self.log("Creating the Batch Account Pool instance {0}".format(self.name))

        try:
            response = self.batch_account_client.pool.create(resource_group_name=self.resource_group,
                                                             account_name=self.batch_account_name,
                                                             pool_name=self.name,
                                                             parameters=self.batch_account_model.Pool(**self.body))
            if isinstance(response, LROPoller):
                response = self.get_poller_result(response)
        except Exception as exc:
            self.log('Error attempting to create the Batch Account Pool instance.')
            self.fail("Error creating the Batch Account Pool instance: {0}".format(str(exc)))
        return response.as_dict()

    def update_batchaccount_pool(self):
        '''
        Update Batch Account Pool with the specified configuration.
        '''
        self.log("Updating the Batch Account Pool instance {0}".format(self.name))

        try:
            response = self.batch_account_client.pool.update(resource_group_name=self.resource_group,
                                                             account_name=self.batch_account_name,
                                                             pool_name=self.name,
                                                             parameters=self.batch_account_model.Pool(**self.body))
            if isinstance(response, LROPoller):
                response = self.get_poller_result(response)
        except Exception as exc:
            self.log('Error attempting to update the Batch Account Pool instance.')
            self.fail("Error updating the Batch Account Pool instance: {0}".format(str(exc)))
        return response.as_dict()

    def disable_auto_scale_pool(self):
        '''
        Disable_auto_scale Batch Account Pool instance in the specified subscription and resource group.
        :return: True
        '''
        self.log("Disable_auto_scale the Batch Account Pool instance {0}".format(self.name))
        try:
            response = self.batch_account_client.pool.disable_auto_scale(resource_group_name=self.resource_group,
                                                                         account_name=self.batch_account_name,
                                                                         pool_name=self.name)
        except Exception as e:
            self.log('Error attempting to disable the Batch Account Pool auto_scale.')
            self.fail("Error disable the Batch Account Pool auto_scale instance: {0}".format(str(e)))
        return True

    def stop_resize_pool(self):
        '''
        Stop resize Batch Account Pool instance in the specified subscription and resource group.
        :return: True
        '''
        self.log("Stop the Batch Account Pool resize {0}".format(self.name))
        try:
            response = self.batch_account_client.pool.stop_resize(resource_group_name=self.resource_group,
                                                                  account_name=self.batch_account_name,
                                                                  pool_name=self.name)
        except Exception as e:
            self.log('Error attempting to stop the Batch Account Pool resize.')
            self.fail("Error stop the Batch Account Pool resize: {0}".format(str(e)))
        return True

    def delete_batchaccount_pool(self):
        '''
        Deletes specified Batch Account Pool instance in the specified subscription and resource group.
        :return: True
        '''
        self.log("Deleting the Batch Account Pool instance {0}".format(self.name))
        try:
            response = self.batch_account_client.pool.begin_delete(resource_group_name=self.resource_group,
                                                                   account_name=self.batch_account_name,
                                                                   pool_name=self.name)
        except Exception as e:
            self.log('Error attempting to delete the Batch Account Pool instance.')
            self.fail("Error deleting the Batch Account Pool instance: {0}".format(str(e)))

        return True

    def get_batchaccount_pool(self):
        '''
        Gets the properties of the specified Batch Account Pool
        :return: deserialized Batch Account Pool instance state dictionary
        '''
        self.log("Checking if the Batch Account Pool instance {0} is present".format(self.name))
        found = False
        try:
            response = self.batch_account_client.pool.get(resource_group_name=self.resource_group,
                                                          account_name=self.batch_account_name,
                                                          pool_name=self.name)
            found = True
            self.log("Response : {0}".format(response))
            self.log("Batch Account Pool instance : {0} found".format(response.name))
        except ResourceNotFoundError as e:
            self.log('Did not find the Batch Account Pool instance. Exception as {0}'.format(e))
        if found is True:
            return self.format_item(response.as_dict())
        return False

    def format_item(self, item):
        if item is None:
            return
        result = item
        result['resource_group'] = self.resource_group
        result['batch_account_name'] = self.batch_account_name
        return result


def main():
    """Main execution"""
    AzureRMBatchAccountPool()


if __name__ == '__main__':
    main()
