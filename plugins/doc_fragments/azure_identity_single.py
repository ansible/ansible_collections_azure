# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Nir Argaman, <nargaman@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):

    # Azure doc fragment
    DOCUMENTATION = r"""
options:
    identity:
        description:
            - Identity for this resource.
        type: dict
        suboptions:
            type:
                description:
                    - Type of the managed identity
                choices:
                    - SystemAssigned
                    - UserAssigned
                    - 'None'
                default: 'None'
                type: str
            user_assigned_identity:
                description:
                    - User Assigned Managed Identity associated to this resource
                required: false
                type: str
"""
