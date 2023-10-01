#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Dell OpenManage Ansible Modules
# Version 8.4.0
# Copyright (C) 2023 Dell Inc. or its subsidiaries. All Rights Reserved.

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
---
module: idrac_network_attributes
short_description: Configures the iDRAC network attributes
version_added: "8.4.0"
description:
    - This module allows to configure iDRAC network settings.
extends_documentation_fragment:
  - dellemc.openmanage.idrac_auth_options
options:
    share_name:
        type: str
        description:
          - (deprecated)Network share or a local path.
          - This option is deprecated and will be removed in the later version.
    share_user:
        type: str
        description:
          - (deprecated)Network share user name. Use the format 'user@domain' or 'domain\\user' if user is part of a domain.
            This option is mandatory for CIFS share.
          - This option is deprecated and will be removed in the later version.
    share_password:
        type: str
        description:
          - (deprecated)Network share user password. This option is mandatory for CIFS share.
          - This option is deprecated and will be removed in the later version.
        aliases: ['share_pwd']
    share_mnt:
        type: str
        description:
          - (deprecated)Local mount path of the network share with read-write permission for ansible user.
            This option is mandatory for network shares.
          - This option is deprecated and will be removed in the later version.
    setup_idrac_nic_vlan:
        type: str
        description: Allows to configure VLAN on iDRAC.
        choices: [Enabled, Disabled]
    register_idrac_on_dns:
        type: str
        description: Registers iDRAC on a Domain Name System (DNS).
        choices: [Enabled, Disabled]
    dns_idrac_name:
        type: str
        description: Name of the DNS to register iDRAC.
    auto_config:
        type: str
        description: Allows to enable or disable auto-provisioning to automatically acquire domain name from DHCP.
        choices: [Enabled, Disabled]
    static_dns:
        type: str
        description: Enter the static DNS domain name.
    vlan_id:
        type: int
        description: Enter the VLAN ID.  The VLAN ID must be a number from 1 through 4094.
    vlan_priority:
        type: int
        description: Enter the priority for the VLAN ID. The priority value must be a number from 0 through 7.
    enable_nic:
        type: str
        description: Allows to enable or disable the Network Interface Controller (NIC) used by iDRAC.
        choices: [Enabled, Disabled]
    nic_selection:
        type: str
        description: Select one of the available NICs.
        choices: [Dedicated, LOM1, LOM2, LOM3, LOM4]
    failover_network:
        type: str
        description: "Select one of the remaining LOMs. If a network fails, the traffic is routed through the failover
        network."
        choices: [ALL, LOM1, LOM2, LOM3, LOM4, T_None]
    auto_detect:
        type: str
        description: Allows to auto detect the available NIC types used by iDRAC.
        choices: [Enabled, Disabled]
    auto_negotiation:
        type: str
        description: Allows iDRAC to automatically set the duplex mode and network speed.
        choices: [Enabled, Disabled]
    network_speed:
        type: str
        description: Select the network speed for the selected NIC.
        choices: [T_10, T_100, T_1000]
    duplex_mode:
        type: str
        description: Select the type of data transmission for the NIC.
        choices: [Full, Half]
    nic_mtu:
        type: int
        description: Maximum Transmission Unit of the NIC.
    ip_address:
        type: str
        description: Enter a valid iDRAC static IPv4 address.
    enable_dhcp:
        type: str
        description: Allows to enable or disable Dynamic Host Configuration Protocol (DHCP) in iDRAC.
        choices: [Enabled, Disabled]
    enable_ipv4:
        type: str
        description: Allows to enable or disable IPv4 configuration.
        choices: [Enabled, Disabled]
    dns_from_dhcp:
        type: str
        description: Allows to enable DHCP to obtain DNS server address.
        choices: [Enabled, Disabled]
    static_dns_1:
        type: str
        description: Enter the preferred static DNS server IPv4 address.
    static_dns_2:
        type: str
        description: Enter the preferred static DNS server IPv4 address.
    static_gateway:
        type: str
        description: Enter the static IPv4 gateway address to iDRAC.
    static_net_mask:
        type: str
        description: Enter the static IP subnet mask to iDRAC.
requirements:
    - "omsdk >= 1.2.488"
    - "python >= 3.9.6"
author:
    - "Felix Stephen (@felixs88)"
    - "Anooja Vardhineni (@anooja-vardhineni)"
notes:
    - This module requires 'Administrator' privilege for I(idrac_user).
    - Run this module from a system that has direct access to Dell iDRAC.
    - This module supports both IPv4 and IPv6 address for I(idrac_ip).
    - This module supports C(check_mode).
"""

EXAMPLES = """
---
- name: Configure iDRAC network settings
  dellemc.openmanage.idrac_network:
       idrac_ip:   "192.168.0.1"
       idrac_user: "user_name"
       idrac_password:  "user_password"
       ca_path: "/path/to/ca_cert.pem"
       register_idrac_on_dns: Enabled
       dns_idrac_name: None
       auto_config: None
       static_dns: None
       setup_idrac_nic_vlan: Enabled
       vlan_id: 0
       vlan_priority: 1
       enable_nic: Enabled
       nic_selection: Dedicated
       failover_network: T_None
       auto_detect: Disabled
       auto_negotiation: Enabled
       network_speed: T_1000
       duplex_mode: Full
       nic_mtu: 1500
       ip_address: "192.168.0.1"
       enable_dhcp: Enabled
       enable_ipv4: Enabled
       static_dns_1: "192.168.0.1"
       static_dns_2: "192.168.0.1"
       dns_from_dhcp: Enabled
       static_gateway: None
       static_net_mask: None
"""

RETURN = r'''
---
msg:
  description: Successfully configured the idrac network settings.
  returned: always
  type: str
  sample: "Successfully configured the idrac network settings."
network_status:
  description: Status of the Network settings operation job.
  returned: success
  type: dict
  sample: {
    "@odata.context": "/redfish/v1/$metadata#DellJob.DellJob",
    "@odata.id": "/redfish/v1/Managers/iDRAC.Embedded.1/Jobs/JID_856418531008",
    "@odata.type": "#DellJob.v1_0_2.DellJob",
    "CompletionTime": "2020-03-31T03:04:15",
    "Description": "Job Instance",
    "EndTime": null,
    "Id": "JID_856418531008",
    "JobState": "Completed",
    "JobType": "ImportConfiguration",
    "Message": "Successfully imported and applied Server Configuration Profile.",
    "MessageArgs": [],
    "MessageArgs@odata.count": 0,
    "MessageId": "SYS053",
    "Name": "Import Configuration",
    "PercentComplete": 100,
    "StartTime": "TIME_NOW",
    "Status": "Success",
    "TargetSettingsURI": null,
    "retval": true
}
error_info:
  description: Details of the HTTP Error.
  returned: on HTTP error
  type: dict
  sample: {
    "error": {
      "code": "Base.1.0.GeneralError",
      "message": "A general error has occurred. See ExtendedInfo for more information.",
      "@Message.ExtendedInfo": [
        {
          "MessageId": "GEN1234",
          "RelatedProperties": [],
          "Message": "Unable to process the request because an error occurred.",
          "MessageArgs": [],
          "Severity": "Critical",
          "Resolution": "Retry the operation. If the issue persists, contact your system administrator."
        }
      ]
    }
  }
'''

import json
from abc import ABC
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.openmanage.plugins.module_utils.idrac_redfish import iDRACRedfishAPI, idrac_auth_params
from ansible_collections.dellemc.openmanage.plugins.module_utils.utils import remove_key
from ansible.module_utils.six.moves.urllib.error import URLError, HTTPError
from ansible.module_utils.urls import ConnectionError, SSLValidationError
from ansible.module_utils.compat.version import LooseVersion


SYSTEMS_URI = "/redfish/v1/Systems"
CHASSIS_URI = "/redfish/v1/Chassis"
GET_NETWORK_ADAPTER_URI = "/redfish/v1/Systems/{resource_id}/NetworkAdapters"
GET_NETWORK_DEVICE_FUNC_URI = "/redfish/v1/Systems/{resource_id}/NetworkAdapters/{network_adapter_id}/NetworkDeviceFunctions"
DMTF_GET_PATCH_NETWORK_ATTR_URI = "/redfish/v1/Systems/{resource_id}/NetworkAdapters/{network_adapter_id}/NetworkDeviceFunctions/{network_device_function_id}/Settings"
OEM_GET_NETWORK_ATTR_URI = "/redfish/v1/Chassis/{resource_id}/NetworkAdapters/{network_adapter_id}/NetworkDeviceFunctions/{network_device_function_id}/Oem/Dell/DellNetworkAttributes/{network_device_function_id}"
OEM_PATCH_NETWORK_SETTINGS_URI = "/redfish/v1/Chassis/{resource_id}/NetworkAdapters/{network_adapter_id}/NetworkDeviceFunctions/{network_device_function_id}/Oem/Dell/DellNetworkAttributes/{network_device_function_id}/Settings"
OEM_SCHEMA_NETWORK_SETTINGS_FOR_IDRAC_FW_VER_GREATER_AND_EQ_TO_6000000_URI = "/redfish/v1/Registries/NetworkAttributesRegistry_{network_device_function_id}/NetworkAttributesRegistry_{network_device_function_id}.json"
OEM_SCHEMA_NETWORK_SETTINGS_FOR_IDRAC_FW_VER_LESSER_TO_6000000_URI = "/redfish/v1/Registries/NetworkAttributesRegistry/NetworkAttributesRegistry.json"
GET_IDRAC_FIRMWARE_VER_URI = "/redfish/v1/Managers/iDRAC.Embedded.1?$select=FirmwareVersion"

SUCCESS_MSG = "Successfully updated the network attributes."
PENDING_MSG = "Successfully cleared the pending network attributes."
SCHEDULE_MSG = "Successfully scheduled the job for network attributes update."
TIMEOUT_NEGATIVE_OR_ZERO_MSG = "Successfully scheduled the job for network attributes update."
MAINTENACE_OFFSET_DIFF_MSG = "The maintenance time must be post-fixed with local offset to <idrac_time_offset>."
MAINTENACE_OFFSET_BEHIND_MSG = "The specified maintenance time window occurs in the past, provide a future time to schedule the maintenance window."
APPLY_TIME_NOT_SUPPORTED_MSG = "Apply time <apply_time> is not supported."
INVALID_ATTR_MSG = "Unable to update the network attributes because invalid values are entered. Enter the valid values for the network attributes and retry the operation."
VALID_AND_INVALID_ATTR_MSG = "Successfully updated the network attributes for valid values. Unable to update other attributes because invalid values are entered. Enter the valid values and retry the operation."
NO_CHANGES_FOUND_MSG = "No changes found to be applied."
CHANGES_FOUND_MSG = "Changes found to be applied."
NETWORK_INVALID_MSG = "{0} is not valid."

class IDRACNetworkAttributes:

    def __init__(self, idrac, module) -> None:
        self.module = module
        self.idrac = idrac
        self.resource_id = "System.Embedded.1"

    def __get_oem_first_resource_id(self):
        if self.module.params.get('oem_network_attributes'):
            fetch_all_chassis = self.idrac.invoke_request(method='GET', uri=CHASSIS_URI)
            self.resource_id = fetch_all_chassis.json_data.get('Members')[0]["@odata.id"].split('/')[-1]

    def __validate_id(self, id, uri):
        self.__get_oem_first_resource_id()
        fetch_all_id = self.idrac.invoke_request(method='GET', uri=uri)
        id_list = [each_member["@odata.id"].split('/')[-1] for each_member in fetch_all_id.json_data.get('Members')]
        if id not in id_list:
            return False, NETWORK_INVALID_MSG.format(id)
        return True, id

    def perform_validation_for_ids(self) -> tuple[bool, str]:
        data, id_or_msg = self.__validate_id(self.module.params.get('network_adapter_id'),
                                                              GET_NETWORK_ADAPTER_URI.format(resource_id=self.resource_id))
        if data:
            data, id_or_msg = self.__validate_id(self.module.params.get('network_device_function_id'),
                                           GET_NETWORK_DEVICE_FUNC_URI.format(resource_id=self.resource_id,
                                                                              network_adapter_id=id_or_msg))
        else:
            self.module.exit_json(msg=id_or_msg)

    def get_attributes(self, uri):
        attributes = self.idrac.invoke_request(method='GET', uri=uri)
        return attributes.json_data

class OEMNetworkAttributes(IDRACNetworkAttributes):
    def __init__(self, idrac, module) -> None:
        super().__init__(idrac, module)
        self.perform_validation_for_ids()

    def __get_idrac_firmware_version(self) -> str:
        firm_version = self.idrac.invoke_request(method='GET', uri=GET_IDRAC_FIRMWARE_VER_URI)
        return firm_version.json_data.get('FirmwareVersion', '')

    def __validate_enumeration_registry(self, searching_value, value_dict) -> bool:
        found = False
        for val in value_dict.get("Value", []):
            if searching_value == val.get("ValueDisplayName"):
                found = True
                break
        return found

    def __validate_integer_registry(self, check_attr, value_dict, module_input) -> tuple[bool, str]:
        try:
            i = int(module_input.get(check_attr))
        except ValueError:
            return False, "Not a valid integer."
        if not (value_dict.get("LowerBound") <= i <= value_dict.get("UpperBound")):
            return False, "Integer out of valid range."
        return True, ''

    def __validate_with_registry(self, check_attr, reg, module_input) -> dict:
        invalid = {}
        registry_value = reg[check_attr]
        if registry_value.get("ReadOnly"):
            invalid.update({check_attr: "Read only Attribute cannot be modified."})
        else:
            data_type = registry_value.get("Type")
            if data_type == "Enumeration" and not self.__validate_enumeration_registry(check_attr, registry_value):
                invalid.update({check_attr: "Invalid value for Enumeration."})
            if data_type == "Integer":
                valid, msg = self.__validate_integer_registry(check_attr, registry_value, module_input)
                if not valid:
                    invalid.update({check_attr: msg})
        return invalid

    def __get_diff_between_current_and_module_input(self, valid_attr, uri) -> int:
        diff = 0
        attributes = self.get_attributes(uri).get('Attributes')
        for each_attr in valid_attr:
            if valid_attr[each_attr] != attributes[each_attr]:
                diff += 1
        return diff

    def get_valid_invalid_diff(self) -> tuple[dict, dict, int]:
        network_adapter_id = self.module.params.get('network_adapter_id')
        network_device_function_id = self.module.params.get('network_device_function_id')
        oem_network_attributes = self.module.params.get('oem_network_attributes')
        firm_version = self.__get_idrac_firmware_version()
        if LooseVersion(firm_version) >= "6.0":
            uri = OEM_SCHEMA_NETWORK_SETTINGS_FOR_IDRAC_FW_VER_GREATER_AND_EQ_TO_6000000_URI
        else:
            uri = OEM_SCHEMA_NETWORK_SETTINGS_FOR_IDRAC_FW_VER_LESSER_TO_6000000_URI
        uri = uri.format(resource_id=self.resource_id,
                         network_adapter_id=network_adapter_id,
                         network_device_function_id=network_device_function_id)
        get_detailed_attributes = self.get_attributes(uri=uri).get('RegistryEntries',[]).get('Attributes',[])
        filtered_detailed_attributes = {x["AttributeName"]: x for x in get_detailed_attributes}
        invalid_attr = {}
        for each_attr_key in oem_network_attributes:
            if each_attr_key not in filtered_detailed_attributes:
                invalid_attr.update({each_attr_key: "Attribute does not exist."})
            else:
                invalid_attr.update(self.__validate_with_registry(each_attr_key,
                                                                  filtered_detailed_attributes,
                                                                  oem_network_attributes))
        valid_attr = {key:value for key, value in oem_network_attributes.items() if key not in invalid_attr}
        uri = OEM_GET_NETWORK_ATTR_URI.format(resource_id=self.resource_id,
                                              network_adapter_id=network_adapter_id,
                                              network_device_function_id=network_device_function_id)
        diff = self.__get_diff_between_current_and_module_input(valid_attr, uri)
        return valid_attr, invalid_attr, diff

    def perform_operation(self):
        


class NetworkAttributes(IDRACNetworkAttributes):
    def __init__(self, idrac, module) -> None:
        super().__init__(idrac, module)
        self.perform_validation_for_ids()
        self.uri = DMTF_GET_PATCH_NETWORK_ATTR_URI.format(resource_id=self.resource_id,
                                                     network_adapter_id=self.module.params.get('network_adapter_id'),
                                                     network_device_function_id=self.module.params.get('network_device_function_id'))
        
    def perform_operation(self):
        result = self.get_attributes(uri=self.uri)
        return result
        
def get_module_parameters() -> AnsibleModule:
    specs = {
        "network_adapter_id": {"type": 'str', "required": True},
        "network_device_function_id": {"type": 'str', "required": True},
        "network_attributes": {"type": 'dict'},
        "oem_network_attributes": {"type": 'dict'},
        "resource_id": {"type": 'str'},
        "clear_pending": {"type": 'bool', "default": False},
        "apply_time": {"type": 'str', "default": 'Immediate',
                       "choices": ['Immediate', 'OnReset', 'AtMaintenanceWindowStart', 'InMaintenanceWindowOnReset']},
        "maintenance_window": {"type": 'dict',
                               "options": {"start_time": {"type": 'str', "required": True},
                                           "duration": {"type": 'int', "required": True}}},
        "job_wait": {"type": "bool", "default": False},
        "job_wait_timeout": {"type": "int", "default": 1200}
    }
    specs.update(idrac_auth_params)
    module = AnsibleModule(argument_spec=specs,
                           mutually_exclusive=[('network_attributes', 'oem_network_attributes')],
                           required_one_of=[('network_attributes', 'oem_network_attributes')],
                           supports_check_mode=True)
    return module

def main():
    try:
        module = get_module_parameters()
        with iDRACRedfishAPI(module.params, req_session=True) as idrac:
            if module.params.get('oem_network_attributes'):
                network_attr_obj = OEMNetworkAttributes(idrac, module)
            else:
                network_attr_obj = NetworkAttributes(idrac, module)
            valid_attr, invalid_attr, diff = network_attr_obj.get_valid_invalid_diff()
            if not diff:
                module.exit_json(msg=NO_CHANGES_FOUND_MSG)
            elif diff and module.check_mode:
                module.exit_json(msg=CHANGES_FOUND_MSG, changed=True)
            msg = network_attr_obj.perform_operation()
            module.exit_json(msg=msg)
    except HTTPError as err:
        module.exit_json(msg=str(err), error_info=json.load(err), failed=True)
    except URLError as err:
        module.exit_json(msg=str(err), unreachable=True)
    except (SSLValidationError, ConnectionError, TypeError, ValueError, OSError) as err:
        module.fail_json(msg=str(err), failed=True)


if __name__ == '__main__':
    main()
