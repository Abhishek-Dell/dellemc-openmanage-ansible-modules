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

import re
import json
from abc import ABC
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.openmanage.plugins.module_utils.idrac_redfish import iDRACRedfishAPI, idrac_auth_params
from ansible_collections.dellemc.openmanage.plugins.module_utils.utils import remove_key, wait_for_idrac_job_completion, \
    get_dynamic_uri, get_scheduled_job_resp, delete_job, get_current_time
from ansible.module_utils.six.moves.urllib.error import URLError, HTTPError
from ansible.module_utils.urls import ConnectionError, SSLValidationError
from ansible.module_utils.compat.version import LooseVersion


SYSTEMS_URI = "/redfish/v1/Systems"
CHASSIS_URI = "/redfish/v1/Chassis"
REGISTRY_URI = '/redfish/v1/Registries'
MANAGERS_URI = '/redfish/v1/Managers'
GET_ALL_JOBS = "/redfish/v1/JobService/Jobs?$expand=*($levels=1)"
SINGLE_JOB = "/redfish/v1/JobService/Jobs/{job_id}"

GET_NETWORK_ADAPTER_URI = "/redfish/v1/Systems/{resource_id}/NetworkAdapters"
GET_NETWORK_DEVICE_FUNC_URI = "/redfish/v1/Systems/{resource_id}/NetworkAdapters/{network_adapter_id}/NetworkDeviceFunctions"
DMTF_GET_PATCH_NETWORK_ATTR_URI = "/redfish/v1/Systems/{resource_id}/NetworkAdapters/{network_adapter_id}/NetworkDeviceFunctions/{network_device_function_id}/Settings"
OEM_GET_NETWORK_ATTR_URI = "/redfish/v1/Chassis/{resource_id}/NetworkAdapters/{network_adapter_id}/NetworkDeviceFunctions/{network_device_function_id}/Oem/Dell/DellNetworkAttributes/{network_device_function_id}"
OEM_PATCH_PENDING_NETWORK_SETTINGS_URI = "/redfish/v1/Chassis/{resource_id}/NetworkAdapters/{network_adapter_id}/NetworkDeviceFunctions/{network_device_function_id}/Oem/Dell/DellNetworkAttributes/{network_device_function_id}/Settings"
OEM_SCHEMA_NETWORK_SETTINGS_FOR_IDRAC_FW_VER_GREATER_AND_EQ_TO_6000000_URI = "/redfish/v1/Registries/NetworkAttributesRegistry_{network_device_function_id}/NetworkAttributesRegistry_{network_device_function_id}.json"
OEM_SCHEMA_NETWORK_SETTINGS_FOR_IDRAC_FW_VER_LESSER_TO_6000000_URI = "/redfish/v1/Registries/NetworkAttributesRegistry/NetworkAttributesRegistry.json"
GET_IDRAC_FIRMWARE_VER_URI = "/redfish/v1/Managers/iDRAC.Embedded.1?$select=FirmwareVersion"
CLEAR_PENDING_URI = "/redfish/v1/Chassis/{resource_id}/NetworkAdapters/{network_adapter_id}/NetworkDeviceFunctions/{network_device_function_id}/Oem/Dell/DellNetworkAttributes/{network_device_function_id}/Settings/Actions/DellManager.ClearPending"

SUCCESS_MSG = "Successfully updated the network attributes."
SUCCESS_CLEAR_PENDING_ATTR_MSG = "Successfully cleared the pending network attributes."
SCHEDULE_MSG = "Successfully scheduled the job for network attributes update."
TIMEOUT_NEGATIVE_OR_ZERO_MSG = "The value for the `job_wait_timeout` parameter cannot be negative or zero."
MAINTENACE_OFFSET_DIFF_MSG = "The maintenance time must be post-fixed with local offset to <idrac_time_offset>."
MAINTENACE_OFFSET_BEHIND_MSG = "The specified maintenance time window occurs in the past, provide a future time to schedule the maintenance window."
APPLY_TIME_NOT_SUPPORTED_MSG = "Apply time <apply_time> is not supported."
INVALID_ATTR_MSG = "Unable to update the network attributes because invalid values are entered. Enter the valid values for the network attributes and retry the operation."
VALID_AND_INVALID_ATTR_MSG = "Successfully updated the network attributes for valid values. Unable to update other attributes because invalid values are entered. Enter the valid values and retry the operation."
NO_CHANGES_FOUND_MSG = "No changes found to be applied."
CHANGES_FOUND_MSG = "Changes found to be applied."
NETWORK_INVALID_MSG = "{0} is not valid."
INVALID_RES_ID = "{0} is not valid resource_id."
JOB_RUNNING_CLEAR_PENDING_ATTR = "{0} Config job is running. Wait for the job to complete. Currently can not clear pending attributes."

class IDRACNetworkAttributes:

    def __init__(self, idrac, module, base_uri) -> None:
        self.module = module
        self.idrac = idrac
        self.base_uri = base_uri
        self.network_adapter_id_uri = None
        self.network_device_function_id = None
        self.manager_uri = None
    
    def __get_resource_id(self):
        odata = '@odata.id'
        found = False
        res_id_uri = None
        res_id_input = self.module.params.get('resource_id')
        res_id_members = get_dynamic_uri(self.idrac, self.base_uri, 'Members')
        for each in res_id_members:
            if res_id_input and res_id_input in each[odata]:
                res_id_uri =  each[odata]
                found = True
                break
        if not found and res_id_input:
            self.module.exit_json(msg=INVALID_RES_ID.format(res_id_input), failed=True)
        else:
            res_id_uri = res_id_members[0][odata]
        return res_id_uri
    
    def _extract_error_msg(self, resp):
        error_info = {}
        error = resp.json_data.get('error')
        for each_dict_err in error.get("@Message.ExtendedInfo"):
            key = each_dict_err.get('MessageArgs')[0]
            msg = each_dict_err.get('Message')
            if key not in error_info:
                error_info.update({key: msg})
        return error_info

    def __validate_time(self, mtime):
        curr_time, date_offset = get_current_time(self.idrac)
        if not mtime.endswith(date_offset):
            self.module.exit_json(failed=True, msg=MAINTENACE_OFFSET_DIFF_MSG.format(date_offset))
        if mtime < curr_time:
            self.module.exit_json(failed=True, msg=MAINTENACE_OFFSET_BEHIND_MSG)
    

    def __get_redfish_apply_time(self, aplytm, rf_settings):
        rf_set = {}
        reboot_req = False
        if rf_settings:
            if 'Maintenance' in aplytm:
                if aplytm not in rf_settings:
                    self.module.exit_json(failed=True, status_msg=APPLY_TIME_NOT_SUPPORTED_MSG.format(aplytm))
                else:
                    rf_set['ApplyTime'] = aplytm
                    m_win = self.module.params.get('maintenance_window')
                    self.__validate_time(m_win.get('start_time'))
                    rf_set['MaintenanceWindowStartTime'] = m_win.get('start_time')
                    rf_set['MaintenanceWindowDurationInSeconds'] = m_win.get('duration')
            else:  # assuming OnReset is always
                if aplytm == "Immediate":
                    if aplytm not in rf_settings:
                        reboot_req = True
                        aplytm = 'OnReset'
                rf_set['ApplyTime'] = aplytm
        return rf_set, reboot_req


    def get_diff_between_current_and_module_input(self, attr, uri) -> tuple[int, dict]:
        diff = 0
        invalid = {}
        attributes = get_dynamic_uri(self.idrac, uri).get('Attributes', {})
        for each_attr in attr:
            if each_attr in attributes:
                if attr[each_attr] != attributes[each_attr]:
                    diff += 1
            else:
                invalid.update({each_attr: 'Attribute does not exist.'})
        return diff, invalid

    def perform_validation_for_ids(self) -> tuple[bool, str]:
        odata = '@odata.id'
        network_adapter_id = self.module.params.get('network_adapter_id')
        network_device_function_id = self.module.params.get('network_device_function_id')
        found_adapter, found_device = False, False
        first_resource_id_uri = self.__get_resource_id()
        network_adapters = get_dynamic_uri(self.idrac, first_resource_id_uri, 'NetworkAdapters')[odata]
        network_adapter_list = get_dynamic_uri(self.idrac, network_adapters, 'Members')
        for each_adapter in network_adapter_list:
            if network_adapter_id in each_adapter.get(odata, ''):
                found_adapter = True
                self.network_adapter_id_uri = each_adapter.get(odata, '')
                break
        if found_adapter:
            network_devices = get_dynamic_uri(self.idrac, self.network_adapter_id_uri, 'NetworkDeviceFunctions')[odata]
            network_device_list = get_dynamic_uri(self.idrac, network_devices, 'Members')
            for each_device in network_device_list:
                if network_device_function_id in each_device.get(odata, ''):
                    found_device = True
                    self.network_device_function_id = each_device.get(odata, '')
                    break
            if not found_device:
                self.module.exit_json(msg=NETWORK_INVALID_MSG.format(network_device_function_id))
        else:
            self.module.exit_json(msg=NETWORK_INVALID_MSG.format(network_adapter_id))

    def validate_job_timeout(self):
        if self.module.params.get("job_wait") and self.module.params.get("job_wait_timeout") <= 0:
            self.module.exit_json(msg=TIMEOUT_NEGATIVE_OR_ZERO_MSG, failed=True)


    def apply_time(self, setting_uri):
        resp = get_dynamic_uri(self.idrac, setting_uri, "@Redfish.Settings")
        rf_settings = resp.get("SupportedApplyTimes", [])
        apply_time = self.module.params.get('apply_time', {})
        rf_set, reboot_required = self.__get_redfish_apply_time(apply_time, rf_settings)
        return rf_set


class OEMNetworkAttributes(IDRACNetworkAttributes):
    def __init__(self, idrac, module, base_uri) -> None:
        super().__init__(idrac, module, base_uri)
        self.perform_validation_for_ids()
        self.validate_job_timeout()
        oem_links = get_dynamic_uri(self.idrac, self.network_device_function_id, 'Links')
        self.oem_uri = oem_links.get('Oem').get('Dell').get('DellNetworkAttributes').get('@odata.id')

    def __get_idrac_firmware_version(self) -> str:
        firm_version = self.idrac.invoke_request(method='GET', uri=GET_IDRAC_FIRMWARE_VER_URI)
        return firm_version.json_data.get('FirmwareVersion', '')


    def clear_pending(self):
        resp = get_dynamic_uri(self.idrac, self.oem_uri, '@Redfish.Settings')
        settings_uri = resp.get('SettingsObject').get('@odata.id')
        settings_uri_resp = get_dynamic_uri(self.idrac, settings_uri)
        pending_attributes = settings_uri_resp.get('Attributes')
        clear_pending_uri = settings_uri_resp.get('Actions').get('#DellManager.ClearPending').get('target')
        if not pending_attributes:
            self.module.exit_json(msg=NO_CHANGES_FOUND_MSG)
        job_resp = get_scheduled_job_resp(self.idrac, 'NICConfiguration')
        job_id, job_state = job_resp.get('Id'), job_resp.get('JobState')
        if job_id:
            if job_state in ["Running"]:
                job_resp = remove_key(job_resp, regex_pattern='(.*?)@odata') 
                self.module.exit_json(failed=True, msg=JOB_RUNNING_CLEAR_PENDING_ATTR,
                                      job_status=job_resp)
            elif job_state in ["Starting", "Scheduled", "Scheduling"]:
                if self.module.check_mode:
                    self.module.exit_json(msg=CHANGES_FOUND_MSG, changed=True)
                delete_job(self.idrac, job_id)
                self.module.exit_json(msg=SUCCESS_CLEAR_PENDING_ATTR_MSG, changed=True)
        if self.module.check_mode:
            self.module.exit_json(msg=CHANGES_FOUND_MSG, changed=True)
        self.idrac.invoke_request(clear_pending_uri, "POST", data="{}", dump=False)
        self.module.exit_json(msg=SUCCESS_CLEAR_PENDING_ATTR_MSG, changed=True)


    def perform_operation(self):
        oem_network_attributes = self.module.params.get('oem_network_attributes')
        job_wait = self.module.params.get('job_wait')
        job_wait_timeout = self.module.params.get('job_wait_timeout')
        payload = {'Attributes': oem_network_attributes}
        apply_time_setting = self.apply_time(self.oem_uri)
        if apply_time_setting:
            payload.update({"@Redfish.SettingsApplyTime": apply_time_setting})

        patch_uri = get_dynamic_uri(self.idrac, self.oem_uri).get('@Redfish.Settings', {}).get('SettingsObject', {}).get('@odata.id')
        response = self.idrac.invoke_request(method='PATCH', uri=patch_uri, data=payload)
        invalid_attr = self._extract_error_msg(response)
        job_tracking_uri = response.headers["Location"]
        job_resp, error_msg = wait_for_idrac_job_completion(self.idrac, job_tracking_uri,
                                                            job_wait=job_wait,
                                                            wait_timeout=job_wait_timeout)

        if error_msg:
            self.module.exit_json(msg=error_msg, failed=True)
        job_resp = remove_key(job_resp.json_data, regex_pattern='(.*?)@odata')
        return job_resp, invalid_attr


class NetworkAttributes(IDRACNetworkAttributes):
    def __init__(self, idrac, module, base_uri) -> None:
        super().__init__(idrac, module, base_uri)
        self.perform_validation_for_ids()
        self.validate_job_timeout()


def get_module_parameters() -> AnsibleModule:
    specs = {
        "network_adapter_id": {"type": 'str', "required": True},
        "network_device_function_id": {"type": 'str', "required": True},
        "network_attributes": {"type": 'dict'},
        "oem_network_attributes": {"type": 'dict'},
        "resource_id": {"type": 'str'},
        "clear_pending": {"type": 'bool', "default": False},
        "apply_time": {"type": 'str', "required": True,
                       "choices": ['Immediate', 'OnReset', 'AtMaintenanceWindowStart', 'InMaintenanceWindowOnReset']},
        "maintenance_window": {"type": 'dict',
                               "options": {"start_time": {"type": 'str', "required": True},
                                           "duration": {"type": 'int', "required": True}}},
        "job_wait": {"type": "bool", "default": True},
        "job_wait_timeout": {"type": "int", "default": 1200}
    }
    specs.update(idrac_auth_params)
    module = AnsibleModule(argument_spec=specs,
                           mutually_exclusive=[('network_attributes', 'oem_network_attributes')],
                           supports_check_mode=True)
    return module

def perform_operation_for_main(module, obj, diff, invalid_attr):
    if diff:
        if module.check_mode:
            module.exit_json(msg=CHANGES_FOUND_MSG, changed=True)
        else:
            job_resp, invalid_attr = obj.perform_operation()
            if job_resp.get('JobState') == "Completed":
                msg = SUCCESS_MSG if not invalid_attr else VALID_AND_INVALID_ATTR_MSG
            else:
                msg = SCHEDULE_MSG
            module.exit_json(msg=msg, invalid_attributes=invalid_attr,
                                job_status=job_resp, changed=True)
    else:
        module.exit_json(msg=NO_CHANGES_FOUND_MSG, invalid_attributes=invalid_attr) 


def main():
    try:
        module = get_module_parameters()
        with iDRACRedfishAPI(module.params, req_session=True) as idrac:
            if oem_attribute:= module.params.get('oem_network_attributes') or module.params.get('clear_pending'):
                base_uri = CHASSIS_URI
                network_attr_obj = OEMNetworkAttributes(idrac, module, base_uri)
                if module.params.get('clear_pending'):
                    network_attr_obj.clear_pending()
                diff, invalid_attr = network_attr_obj.get_diff_between_current_and_module_input(oem_attribute, network_attr_obj.oem_uri)
            else:
                base_uri = SYSTEMS_URI
                network_attr_obj = NetworkAttributes(idrac, module, base_uri) 
            perform_operation_for_main(module, network_attr_obj, diff, invalid_attr)
    except HTTPError as err:
        module.exit_json(msg=str(err), error_info=json.load(err), failed=True)
    except URLError as err:
        module.exit_json(msg=str(err), unreachable=True)
    except (SSLValidationError, ConnectionError, TypeError, ValueError, OSError) as err:
        module.fail_json(msg=str(err), failed=True)


if __name__ == '__main__':
    main()
