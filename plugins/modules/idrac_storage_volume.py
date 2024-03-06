#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Dell OpenManage Ansible Modules
# Version 9.1.0
# Copyright (C) 2024 Dell Inc. or its subsidiaries. All Rights Reserved.

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: idrac_storage_volume
short_description: Configures the RAID configuration attributes
version_added: "9.1.0"
description:
  - This module is responsible for configuring the RAID attributes.
extends_documentation_fragment:
  - dellemc.openmanage.idrac_auth_options
options:
  state:
    type: str
    description:
      - C(create), performs create volume operation.
      - C(delete), performs remove volume operation.
      - C(view), returns storage view.
    choices: ['create', 'delete', 'view']
    default: 'view'
  span_depth:
    type: int
    description:
      - Number of spans in the RAID configuration.
      - I(span_depth) is required for C(create) and its value depends on I(volume_type).
    default: 1
  span_length:
    type: int
    description:
      - Number of disks in a span.
      - I(span_length) is required for C(create) and its value depends on I(volume_type).
    default: 1
  number_dedicated_hot_spare:
    type: int
    description: Number of Dedicated Hot Spare.
    default: 0
  volume_type:
    type: str
    description: Provide the the required RAID level.
    choices: ['RAID 0', 'RAID 1', 'RAID 5', 'RAID 6', 'RAID 10', 'RAID 50', 'RAID 60']
    default: 'RAID 0'
  disk_cache_policy:
    type: str
    description: Disk Cache Policy.
    choices: ["Default", "Enabled", "Disabled"]
    default: "Default"
  write_cache_policy:
    type: str
    description: Write cache policy.
    choices: ["WriteThrough", "WriteBack", "WriteBackForce"]
    default: "WriteThrough"
  read_cache_policy:
    type: str
    description: Read cache policy.
    choices: ["NoReadAhead", "ReadAhead", "AdaptiveReadAhead"]
    default: "NoReadAhead"
  stripe_size:
    type: int
    description: Stripe size value to be provided in multiples of 64 * 1024.
    default: 65536
  controller_id:
    type: str
    description:
      - Fully Qualified Device Descriptor (FQDD) of the storage controller, for example 'RAID.Integrated.1-1'.
        Controller FQDD is required for C(create) RAID configuration.
  media_type:
    type: str
    description: Media type.
    choices: ['HDD', 'SSD']
  protocol:
    type: str
    description: Bus protocol.
    choices: ['SAS', 'SATA']
  volume_id:
    type: str
    description:
      - Fully Qualified Device Descriptor (FQDD) of the virtual disk, for example 'Disk.virtual.0:RAID.Slot.1-1'.
        This option is used to get the virtual disk information.
  volumes:
    type: list
    elements: dict
    description:
      - A list of virtual disk specific iDRAC attributes. This is applicable for C(create) and C(delete) operations.
      - For C(create) operation, name and drives are applicable options, other volume options can also be specified.
      - The drives is a required option for C(create) operation and accepts either location (list of drive slot)
        or id (list of drive fqdd).
      - For C(delete) operation, only name option is applicable.
      - See the examples for more details.
  capacity:
    type: float
    description: Virtual disk size in GB.
  raid_reset_config:
    type: str
    description:
      - This option represents whether a reset config operation needs to be performed on the RAID controller.
        Reset Config operation deletes all the virtual disks present on the RAID controller.
    choices: ['True', 'False']
    default: 'False'
  raid_init_operation:
    type: str
    description: This option represents initialization configuration operation to be performed on the virtual disk.
    choices: [None, Fast]
  job_wait:
    description:
      - This parameter provides the option to wait for the job completion.
      - This is applicable when I(state) is C(create) or C(delete).
    type: bool
    default: true
  job_wait_timeout:
    description:
      - This parameter is the maximum wait time of I(job_wait) in seconds.
      - This option is applicable when I(job_wait) is C(true).
    type: int
    default: 900

requirements:
  - "python >= 3.9.6"
author: 
  - "Felix Stephen (@felixs88)"
  - "Kritika Bhateja (@Kritika-Bhateja-03)"
  - "Abhishek Sinha(@ABHISHEK-SINHA10)"
notes:
    - Run this module from a system that has direct access to Dell iDRAC.
    - This module supports both IPv4 and IPv6 address for I(idrac_ip).
    - This module supports C(check_mode).
'''

EXAMPLES = r'''
---
- name: Create single volume
  dellemc.openmanage.idrac_storage_volume:
    idrac_ip: "192.168.0.1"
    idrac_user: "username"
    idrac_password: "password"
    ca_path: "/path/to/ca_cert.pem"
    state: "create"
    controller_id: "RAID.Slot.1-1"
    volumes:
      - drives:
        location: [5]

- name: Create multiple volume
  dellemc.openmanage.idrac_storage_volume:
    idrac_ip: "192.168.0.1"
    idrac_user: "username"
    idrac_password: "password"
    ca_path: "/path/to/ca_cert.pem"
    raid_reset_config: "True"
    state: "create"
    controller_id: "RAID.Slot.1-1"
    volume_type: "RAID 1"
    span_depth: 1
    span_length: 2
    number_dedicated_hot_spare: 1
    disk_cache_policy: "Enabled"
    write_cache_policy: "WriteBackForce"
    read_cache_policy: "ReadAhead"
    stripe_size: 65536
    capacity: 100
    raid_init_operation: "Fast"
    volumes:
      - name: "volume_1"
        drives:
          id: ["Disk.Bay.1:Enclosure.Internal.0-1:RAID.Slot.1-1", "Disk.Bay.2:Enclosure.Internal.0-1:RAID.Slot.1-1"]
      - name: "volume_2"
        volume_type: "RAID 5"
        span_length: 3
        span_depth: 1
        drives:
          location: [7, 3, 5]
        disk_cache_policy: "Disabled"
        write_cache_policy: "WriteBack"
        read_cache_policy: "NoReadAhead"
        stripe_size: 131072
        capacity: "200"
        raid_init_operation: "None"

- name: View all volume details
  dellemc.openmanage.idrac_storage_volume:
    idrac_ip: "192.168.0.1"
    idrac_user: "username"
    idrac_password: "password"
    ca_path: "/path/to/ca_cert.pem"
    state: "view"

- name: View specific volume details
  dellemc.openmanage.idrac_storage_volume:
    idrac_ip: "192.168.0.1"
    idrac_user: "username"
    idrac_password: "password"
    ca_path: "/path/to/ca_cert.pem"
    state: "view"
    controller_id: "RAID.Slot.1-1"
    volume_id: "Disk.Virtual.0:RAID.Slot.1-1"

- name: Delete single volume
  dellemc.openmanage.idrac_storage_volume:
    idrac_ip: "192.168.0.1"
    idrac_user: "username"
    idrac_password: "password"
    ca_path: "/path/to/ca_cert.pem"
    state: "delete"
    volumes:
      - name: "volume_1"

- name: Delete multiple volume
  dellemc.openmanage.idrac_storage_volume:
    idrac_ip: "192.168.0.1"
    idrac_user: "username"
    idrac_password: "password"
    ca_path: "/path/to/ca_cert.pem"
    state: "delete"
    volumes:
      - name: "volume_1"
      - name: "volume_2"
'''

RETURN = r'''
---
msg:
  type: str
  description: Overall status of the storage configuration operation.
  returned: always
  sample: "Successfully completed the view storage volume operation"
storage_status:
  type: dict
  description: Storage configuration job and progress details from the iDRAC.
  returned: success
  sample:
    {
      "Id": "JID_XXXXXXXXX",
      "JobState": "Completed",
      "JobType": "ImportConfiguration",
      "Message": "Successfully imported and applied Server Configuration Profile.",
      "MessageId": "XXX123",
      "Name": "Import Configuration",
      "PercentComplete": 100,
      "StartTime": "TIME_NOW",
      "Status": "Success",
      "TargetSettingsURI": null,
      "retval": true
    }
'''

import json
import time
from urllib.error import HTTPError, URLError
from ansible.module_utils.urls import ConnectionError, SSLValidationError
from ansible_collections.dellemc.openmanage.plugins.module_utils.idrac_redfish import iDRACRedfishAPI, idrac_auth_params
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.openmanage.plugins.module_utils.utils import (
    get_dynamic_uri, validate_and_get_first_resource_id_uri, xml_data_conversion, remove_key)
import operator


SYSTEMS_URI = "/redfish/v1/Systems"
CONTROLLER_NOT_EXIST_ERROR = "Specified Controller {controller_id} does not exist in the System."
CONTROLLER_NOT_DEFINED = "Controller ID is required."
SUCCESSFUL_OPERATION_MSG = "Successfully completed the {operation} storage volume operation"
DRIVES_NOT_EXIST_ERROR = "No Drive(s) are attached to the specified Controller Id: {controller_id}."
DRIVES_NOT_MATCHED = "Following Drive(s) {specified_drives} are not attached to the specified Controller Id: {controller_id}"
NEGATIVE_OR_ZERO_MSG = "The value for the `{parameter}` parameter cannot be negative or zero."
NEGATIVE_MSG = "The value for the `{parameter}` parameter cannot be negative."
INVALID_VALUE_MSG = " The value for the `{parameter}` parameter are invalid."
ID_AND_LOCATION_BOTH_DEFINED = "Either id or location is allowed."
ID_AND_LOCATION_BOTH_NOT_DEFINED = "Either id or location should be specified."
DRIVES_NOT_DEFINED = "Drives must be defined for volume creation."
ODATA_ID = '@odata.id'

class StorageBase:
    def __init__(self, idrac, module):
      self.module = self.module_extend_input(module)
      self.idrac = idrac

    def module_extend_input(self, module):
        """
        Extends the input module with additional volume-related parameters.

        Args:
            module (object): The module object.

        Returns:
            object: The updated module object.
        """
        volume_related_input = [
            'volume_type', 'span_length', 'span_depth',
            'number_dedicated_hot_spare', 'disk_cache_policy',
            'write_cache_policy', 'read_cache_policy', 'stripe_size',
            'capacity', 'raid_init_operation'
        ]
        
        volumes = module.params.get('volumes', [])
        if volumes:
            for each_member in volumes:
                for key in volume_related_input:
                    if key not in each_member:
                        each_member[key] = module.params.get(key)
        
        return module


    def construct_volume_payload(self, number_of_existing_vd, volume_dict, ) -> dict:
        
        """
        Constructs a payload dictionary for the given key mappings.

        Returns:
            dict: The constructed payload dictionary.
        """
        key_mapping: dict = {
            'raid_reset_config': 'RAIDresetConfig',
            'raid_init_operation': 'RAIDinitOperation',
            'state': "RAIDaction",
            'disk_cache_policy': "DiskCachePolicy",
            'write_cache_policy': "RAIDdefaultWritePolicy",
            'read_cache_policy': "RAIDdefaultReadPolicy",
            'stripe_size': "StripeSize",
            'span_depth': "SpanDepth",
            'span_length': "SpanLength",
            'volume_type': "RAIDTypes",
            'name': 'Name',
            'capacity': 'Size',
            'dedicated_hot_spare': "DedicatedSpare",
        }

        vdfqdd = "Disk.Virtual.{0}:{1}".format(int(number_of_existing_vd)+1, self.module.params.get("controller_id"))
        

        payload = {}

        return payload


class StorageData: 
    def __init__(self, idrac, module):
        self.idrac = idrac
        self.module = module

    def fetch_data_from_idrac(self, remove_odata=True):
        storage_info = {}
        uri, err_msg = validate_and_get_first_resource_id_uri(
            self.module, self.idrac, SYSTEMS_URI)
        if err_msg:
            self.module.exit_json(msg=err_msg, failed=True)
        storage_controllers = get_dynamic_uri(self.idrac, uri, 'Storage')
        controllers_expand_uri = f"{storage_controllers[ODATA_ID]}?$expand=*($levels=1)"
        storage_expand_response = get_dynamic_uri(self.idrac, controllers_expand_uri, 'Members')
        for each_controller in storage_expand_response:
            controller_id = each_controller.get("Id")
            storage_info[controller_id] = each_controller
            #  For Drives
            drives_uri_list = [drive[ODATA_ID] for drive in each_controller['Drives']]
            drives_dict = {}
            for each_drive_uri in drives_uri_list:
                drive = get_dynamic_uri(self.idrac, each_drive_uri)
                if drive:
                    drives_dict[drive.get('Id')] = drive
            storage_info[controller_id]['Drives'] = drives_dict
            #  For Volumes
            volume_uri = each_controller['Volumes'][ODATA_ID]
            volume_uri_list = [volume[ODATA_ID] for volume in get_dynamic_uri(self.idrac, volume_uri, 'Members')]
            volume_dict = {}
            for each_volume_uri in volume_uri_list:
                volume = get_dynamic_uri(self.idrac, each_volume_uri)
                if volume:
                    volume_dict[volume.get('Id')] = volume
            storage_info[controller_id]['Volumes'] = volume_dict
        if remove_odata:
            storage_info = remove_key(storage_info, regex_pattern="(.*?)@odata")
        return storage_info


class StorageValidation(StorageBase):
    def __init__(self, idrac, module):
        super().__init__(idrac,module)
        self.idrac_data = StorageData(idrac, module).fetch_data_from_idrac()
        self.controller_id = module.params.get("controller_id")

    def validate_controller_exists(self):
        if not self.controller_id:
            self.module.exit_json(msg=CONTROLLER_NOT_DEFINED, failed=True)
        controllers = self.idrac_data
        if self.controller_id not in controllers.keys():
            self.module.exit_json(msg=CONTROLLER_NOT_EXIST_ERROR.format(controller_id=self.controller_id), failed=True)
        return True

    def validate_negative_values(self):
        if self.module.params.get("job_wait") and self.module.params.get("job_wait_timeout") <= 0:
            self.module.exit_json(msg=NEGATIVE_OR_ZERO_MSG.format(parameter = "job_wait_timeout"), failed=True)

        params = ["span_depth", "span_length"]
        for param in params:
            if self.module.params.get(param) <= 0:
                self.module.exit_json(msg=NEGATIVE_OR_ZERO_MSG.format(parameter=param), failed=True)

        if self.module.params.get("number_dedicated_hot_spare") < 0:
            self.module.exit_json(msg=NEGATIVE_MSG.format(parameter="number_dedicated_hot_spare"), failed=True)
        return True

    def validate_volume_drives(self, specified_drives):
        if not specified_drives:
            self.module.exit_json(msg=DRIVES_NOT_DEFINED, failed=True)
        if specified_drives.get("id") and specified_drives.get("location"):
            self.module.exit_json(msg=ID_AND_LOCATION_BOTH_DEFINED, failed=True)
        elif not specified_drives.get("id") and not specified_drives.get("location"):
            self.module.exit_json(msg=ID_AND_LOCATION_BOTH_NOT_DEFINED, failed=True)
        drives_count = len(specified_drives.id) or len(specified_drives.location)
        return self.raid_std_validation(specified_drives.span_length, specified_drives.span_depth, specified_drives.volume_type, drives_count)


    def raid_std_validation(self, span_length, span_depth, volume_type, pd_count):
        raid_std = {
            "RAID 0": {'pd_slots': range(1, 2), 'span_length': 1, 'checks': operator.ge, 'span_depth': 1},
            "RAID 1": {'pd_slots': range(1, 3), 'span_length': 2, 'checks': operator.eq, 'span_depth': 1},
            "RAID 5": {'pd_slots': range(1, 4), 'span_length': 3, 'checks': operator.ge, 'span_depth': 1},
            "RAID 6": {'pd_slots': range(1, 5), 'span_length': 4, 'checks': operator.ge, 'span_depth': 1},
            "RAID 10": {'pd_slots': range(1, 5), 'span_length': 2, 'checks': operator.ge, 'span_depth': 2},
            "RAID 50": {'pd_slots': range(1, 7), 'span_length': 3, 'checks': operator.ge, 'span_depth': 2},
            "RAID 60": {'pd_slots': range(1, 9), 'span_length': 4, 'checks': operator.ge, 'span_depth': 2}
        }
        raid_info = raid_std.get(volume_type)
        if not raid_std.get('checks')(span_length, raid_info.get('span_length')):
            self.module.exit_json(msg=INVALID_VALUE_MSG.format(parameter=span_length))
        if volume_type in ["RAID 0", "RAID 1", "RAID 5", "RAID 6"] and operator.ne(span_depth, raid_info('span_depth')):
            self.module.exit_json(msg=INVALID_VALUE_MSG.format(parameter=span_length))
        if volume_type in ["RAID 10", "RAID 50", "RAID 60"] and operator.ge(span_depth, raid_info('span_depth')):
            self.module.exit_json(msg=INVALID_VALUE_MSG.format(parameter=span_length))
        if not operator.eq(pd_count, span_depth*span_length):
            self.module.exit_json(msg=INVALID_VALUE_MSG.format(parameter="drives"))
        return True

    def validate(self):
        pass
    
    def execute(self):
        self.validate_controller_exists()
        self.validate_negative_values()
        for volume in self.module.params.get("volumes"):
            self.validate_volume_drives(volume.get("drives"))


class StorageCreate(StorageValidation):
    def validate(self):
        super().execute()
    
    def execute(self):
        self.validate()


class StorageUpdate(StorageValidation):
    def validate(self):
        pass
    
    def execute(self):
        pass


class StorageDelete(StorageValidation):
    def validate(self):
        pass
    
    def execute(self):
        pass


class StorageView(StorageValidation):
    def __init__(self, idrac, module):
        super().__init__(idrac, module)
    
    def validate(self):
        pass

    def execute(self):
        return self.idrac_data


def main():
    specs = {
        "state": {"choices": ['create', 'delete', 'view'], "default": 'view'},
        "volume_id": {"type": 'str'},
        "volumes": {"type": 'list', "elements": 'dict'},
        "span_depth": {"type": 'int', "default": 1},
        "span_length": {"type": 'int', "default": 1},
        "number_dedicated_hot_spare": {"type": 'int', "default": 0},
        "volume_type": {"choices": ['RAID 0', 'RAID 1', 'RAID 5', 'RAID 6', 'RAID 10', 'RAID 50', 'RAID 60'],
                        "default": 'RAID 0'},
        "disk_cache_policy": {"choices": ["Default", "Enabled", "Disabled"],
                              "default": "Default"},
        "write_cache_policy": {"choices": ["WriteThrough", "WriteBack", "WriteBackForce"],
                               "default": "WriteThrough"},
        "read_cache_policy": {"choices": ["NoReadAhead", "ReadAhead", "AdaptiveReadAhead"],
                              "default": "NoReadAhead"},
        "stripe_size": {"type": 'int', "default": 64 * 1024},
        "capacity": {"type": 'float'},
        "controller_id": {"type": 'str'},
        "media_type": {"choices": ['HDD', 'SSD']},
        "protocol": {"choices": ['SAS', 'SATA']},
        "raid_reset_config": {"choices": ['True', 'False'], "default": 'False'},
        "raid_init_operation": {"choices": ['None', 'Fast']},
        "job_wait": {"type": "bool", "default": True},
        "job_wait_timeout": {"type": "int", "default": 900}
    }
    specs.update(idrac_auth_params)
    module = AnsibleModule(
        argument_spec=specs,
        supports_check_mode=True)
    
    try:
        with iDRACRedfishAPI(module.params) as idrac:
            changed = False
            state_class_mapping = {
              'create': StorageCreate,
              'view': StorageView,
              'update': StorageUpdate,
              'delete': StorageDelete,
            }
            state_type = state_class_mapping.get(module.params['state'])
            obj = state_type(idrac, module)
            output = obj.execute()
    except (ImportError, ValueError, RuntimeError, TypeError) as e:
        module.fail_json(msg=str(e), failed=True)
    msg = SUCCESSFUL_OPERATION_MSG.format(operation = module.params['state'])
    module.exit_json(msg=msg, changed=changed, storage_status=output)


if __name__ == '__main__':
    main()
