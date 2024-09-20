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
            - Identity for the Object
        type: dict
        suboptions:
            type:
                description:
                    - Type of the managed identity
                choices:
                    - SystemAssigned
                    - UserAssigned
                    - SystemAssigned, UserAssigned
                    - None
                default: None
                type: str
            user_assigned_identities:
                description:
                    - User Assigned Managed Identities and its options
                required: false
                type: dict
                default: {}
                suboptions:
                    id:
                        description:
                            - List of the user assigned identities IDs associated to the Object
                        required: false
                        type: list
                        elements: str
                        default: []
                    append:
                        description:
                            - If the list of identities has to be appended to current identities (true) or if it has to replace current identities (false)
                        required: false
                        type: bool
                        default: True
"""
