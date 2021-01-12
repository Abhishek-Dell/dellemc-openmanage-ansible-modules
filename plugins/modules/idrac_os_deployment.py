#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Dell EMC OpenManage Ansible Modules
# Version 3.0.0
# Copyright (C) 2019-2021 Dell Inc.

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# All rights reserved. Dell, EMC, and other trademarks are trademarks of Dell Inc. or its subsidiaries.
# Other trademarks may be trademarks of their respective owners.
#

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: idrac_os_deployment
short_description: Boot to a network ISO image
version_added: "2.10.0"
description: Boot to a network ISO image.
extends_documentation_fragment:
  - dellemc.openmanage.idrac_auth_options
options:
    share_name:
        required: True
        description: CIFS or NFS Network share.
        type: str
    share_user:
        required: False
        description: Network share user in the format 'user@domain' or 'domain\\user' if user is
            part of a domain else 'user'. This option is mandatory for CIFS Network Share.
        type: str
    share_password:
        required: False
        description: Network share user password. This option is mandatory for CIFS Network Share.
        type: str
        aliases: ['share_pwd']
    iso_image:
        required: True
        description: Network ISO name.
        type: str
    expose_duration:
        required: False
        description: It is the time taken in minutes for the ISO image file to be exposed as a local CD-ROM device to
            the host server. When the time expires, the ISO image gets automatically detached.
        type: int
        default: 1080
requirements:
    - "omsdk"
    - "python >= 2.7.5"
author:
    - "Felix Stephen (@felixs88)"
    - "Jagadeesh N V (@jagadeeshnv)"
notes:
    - Run this module from a system that has direct access to DellEMC iDRAC.
    - This module does not support C(check_mode).
'''

EXAMPLES = r'''
---
- name: Boot to Network ISO
  dellemc.openmanage.idrac_os_deployment:
      idrac_ip: "192.168.0.1"
      idrac_user: "user_name"
      idrac_password: "user_password"
      share_name: "192.168.0.0:/nfsfileshare"
      iso_image:  "unattended_os_image.iso"
      expose_duration: 180
'''

RETURN = r'''
msg:
    description: details of the boot to network ISO image operation.
    returned: always
    type: dict
    sample: {
        "DeleteOnCompletion": "false",
        "InstanceID": "DCIM_OSDConcreteJob:1",
        "JobName": "BootToNetworkISO",
        "JobStatus": "Success",
        "Message": "The command was successful.",
        "MessageID": "OSD1",
        "Name": "BootToNetworkISO",
        "Status": "Success",
        "file": "192.168.0.0:/nfsfileshare/unattended_os_image.iso",
        "retval": true
    }
'''


import os
from ansible_collections.dellemc.openmanage.plugins.module_utils.dellemc_idrac import iDRACConnection
from ansible.module_utils.basic import AnsibleModule
try:
    from omsdk.sdkfile import FileOnShare
    from omsdk.sdkcreds import UserCredentials
except ImportError:
    pass


def minutes_to_cim_format(module, dur_minutes):
    try:
        if dur_minutes < 0:
            module.fail_json(msg="Invalid value for ExposeDuration.")
        MIN_PER_HOUR = 60
        MIN_PER_DAY = 1440
        days = dur_minutes // MIN_PER_DAY
        minutes = dur_minutes % MIN_PER_DAY
        hours = minutes // MIN_PER_HOUR
        minutes = minutes % MIN_PER_HOUR
        if days > 0:
            hours = 23
        cim_format = "{:08d}{:02d}{:02d}00.000000:000"
        cim_time = cim_format.format(days, hours, minutes)
    except Exception:
        module.fail_json(msg="Invalid value for ExposeDuration.")
    return cim_time


def run_boot_to_network_iso(idrac, module):
    """Boot to a network ISO image"""
    try:
        share_name = module.params['share_name']
        if share_name is None:
            share_name = ''
        share_obj = FileOnShare(remote="{0}{1}{2}".format(share_name, os.sep, module.params['iso_image']),
                                isFolder=False, creds=UserCredentials(module.params['share_user'],
                                                                      module.params['share_password'])
                                )
        cim_exp_duration = minutes_to_cim_format(module, module.params['expose_duration'])
        boot_status = idrac.config_mgr.boot_to_network_iso(share_obj, "", expose_duration=cim_exp_duration)
        if not boot_status.get("Status", False) == "Success":
            module.fail_json(msg=boot_status)
    except Exception as e:
        module.fail_json(msg=str(e))
    return boot_status


def main():
    module = AnsibleModule(
        argument_spec={
            "idrac_ip": {"required": True, "type": 'str'},
            "idrac_user": {"required": True, "type": 'str'},
            "idrac_password": {"required": True, "type": 'str', "aliases": ['idrac_pwd'], "no_log": True},
            "idrac_port": {"required": False, "default": 443, "type": 'int'},
            "share_name": {"required": True, "type": 'str'},
            "share_user": {"required": False, "type": 'str'},
            "share_password": {"required": False, "type": 'str', "aliases": ['share_pwd'], "no_log": True},
            "iso_image": {"required": True, "type": 'str'},
            "expose_duration": {"required": False, "type": 'int', "default": 1080}
        },
        supports_check_mode=False)

    try:
        with iDRACConnection(module.params) as idrac:
            boot_status = run_boot_to_network_iso(idrac, module)
            module.exit_json(changed=True, msg=boot_status)
    except (ImportError, ValueError, RuntimeError) as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()
