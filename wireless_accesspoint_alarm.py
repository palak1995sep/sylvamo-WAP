#!/usr/bin/env python
# Copyright 2021 Encore Technologies
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# https://www.w3schools.com/python/trypython.asp?filename=demo_ref_string_split3
from st2reactor.sensor.base import PollingSensor
from st2client.models.keyvalue import KeyValuePair  # pylint: disable=no-name-in-module
import requests
import ast
import socket
import os
from st2client.client import Client
import sys
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/../actions/lib')
import base_action
from datetime import datetime, timedelta

__all__ = [
    'ServiceNowIncidentSensor'
]


class ServiceNowIncidentSensor(PollingSensor):
    def __init__(self, sensor_service, config=None, poll_interval=None):
        super(ServiceNowIncidentSensor, self).__init__(sensor_service=sensor_service,
                                                       config=config,
                                                       poll_interval=poll_interval)
        self._logger = self._sensor_service.get_logger(__name__)
        self.base_action = base_action.BaseAction(config)

    def add_utc_time(self):
        try:
            edt_time = datetime.now().replace(microsecond=0)
            utc_time = edt_time + timedelta(hours=4)
        except Exception:
            utc_time = "EXCEPTION_TIME"
        return " at "+ str(utc_time) + " UTC"

    def setup(self):
        self.sn_username = self._config['servicenow']['username']
        self.sn_password = self._config['servicenow']['password']
        self.sn_url = self._config['servicenow']['url']
        self.som_company_sys_id =  self.config['servicenow']['company_sys_id']
        self.servicenow_headers = {'Content-type': 'application/json',
                                   'Accept': 'application/json'}
        self.st2_fqdn = socket.getfqdn()
        st2_url = "https://{}/".format(self.st2_fqdn)
        self.st2_client = Client(base_url=st2_url)

    def poll(self):
        # Query for all active and open incidents
        self._logger.info('STARTED_INCIDENT_SENSOR_AT: {}'.format(datetime.now()))
        sn_inc_endpoint = '/api/now/table/incident?sysparm_query=active=true^incident_state=2'
        sn_inc_endpoint = sn_inc_endpoint + '^company.sys_id='+self.som_company_sys_id
        sn_inc_endpoint = sn_inc_endpoint + '^priority=3^ORpriority=4'
        sn_inc_endpoint = sn_inc_endpoint + '^sys_created_on>=javascript:gs.beginningOfYesterday()'
        #sn_inc_endpoint = sn_inc_endpoint + "^sys_created_onBETWEENjavascript:gs.dateGenerate('2022-06-20','00:00:00')@javascript:gs.dateGenerate('2022-06-28','23:59:59')"
        # Host down
        sn_inc_endpoint = sn_inc_endpoint + '^descriptionLIKEnot%20responding%20to%20Ping'
        # Windows CPU Utilization
        sn_inc_endpoint = sn_inc_endpoint + '^ORdescriptionLIKEtotal%20cpu%20utilization'
        # Memory Utilization
        sn_inc_endpoint = sn_inc_endpoint + '^ORdescriptionLIKEmemory%20usage%20on'
        #sn_inc_endpoint = sn_inc_endpoint + '^ORdescriptionLIKEmemory%20used%20on'
        # Windows Disk usage
        sn_inc_endpoint = sn_inc_endpoint + '^ORdescriptionLIKElogical%20disk%20free%20space%20on'
        #sn_inc_endpoint = sn_inc_endpoint + '^ORdescriptionLIKE%20MONITORING%20%20Disk'
        # Windows CPU Performance Queue length
        #sn_inc_endpoint = sn_inc_endpoint + '^ORdescriptionLIKESystem%20Performance%20Processor%20Queue%20Length'
        # Linux Process
        sn_inc_endpoint = sn_inc_endpoint + '^ORdescriptionLIKELinux%20process'
        # Windows Hearbeat
        #sn_inc_endpoint = sn_inc_endpoint + '^ORdescriptionLIKEOpsRamp%20Agent%20service%20is%20offline'
        # Windows Service alert
        sn_inc_endpoint = sn_inc_endpoint + '^ORshort_descriptionLIKEPATROL%20Agent'
        sn_inc_endpoint = sn_inc_endpoint + '^ORshort_descriptionLIKEWindows%20Service'
        #sn_inc_endpoint = sn_inc_endpoint + '^ORshort_descriptionLIKEService%20Alert:'
        # Network Unreachable to ping
        sn_inc_endpoint = sn_inc_endpoint + '^ORdescriptionLIKENetwork%20Outage'
        sn_inc_endpoint = sn_inc_endpoint + '^ORdescriptionLIKEDevice%20Reboot%20Detected'
        # SNMP Agent Not Responding
        #sn_inc_endpoint = sn_inc_endpoint + '^ORdescriptionLIKESNMP%20Agent%20Not%20Responding'
        # Network Port down
        sn_inc_endpoint= sn_inc_endpoint + '^ORdescriptionLIKEPort%20Down'
        #BGP Peer check
        #sn_inc_endpoint= sn_inc_endpoint + '^ORdescriptionLIKEBGP'
        #Wireless accesspoint alarm
        sn_inc_endpoint = sn_inc_endpoint + '^ORdescriptionLIKEAP%20Not%20Associated%20With%20Controller'
        sn_inc_endpoint = sn_inc_endpoint + '^ORdescriptionLIKEAP%20Unreachable'
        #Wireless accesspoint antenna offline status
        sn_inc_endpoint = sn_inc_endpoint + '^ORdescriptionLIKEAP%20Antenna%20Offline'
        #Port utilization
        sn_inc_endpoint = sn_inc_endpoint + '^ORdescriptionLIKEPort%20Utilization%20High'
        #OSPF Peer route has disappeared
        #sn_inc_endpoint= sn_inc_endpoint + '^ORdescriptionLIKEOSPF'
        #EIGRP Peer check
        #sn_inc_endpoint= sn_inc_endpoint + '^ORdescriptionLIKEEIGRP'
        sn_inc_endpoint = sn_inc_endpoint + '^ORdescriptionLIKE%20eigrp'
        #Temperature Alarm
        sn_inc_endpoint = sn_inc_endpoint + '^ORshort_descriptionLIKETemperature%20Alarm'
        #Power supply Alarm
        sn_inc_endpoint = sn_inc_endpoint + '^ORshort_descriptionLIKEPower%20Supply'
        # define the which fiels needs to return from SOM API
        sn_inc_endpoint = sn_inc_endpoint + '&sysparm_fields=number,assignment_group,company,cmdb_ci,description,short_description,sys_id,priority,incident_state,opened_at'

        sn_inc_url = "https://{0}{1}".format(self.sn_url,
                                             sn_inc_endpoint)
        print(sn_inc_url)

        sn_result = requests.request('GET',
                                     sn_inc_url,
                                     auth=(self.sn_username, self.sn_password),
                                     headers=self.servicenow_headers)

        sn_result.raise_for_status()
        sn_incidents = sn_result.json()['result']
        self.check_incidents(sn_incidents)
        self._logger.info('COMPLETED_INCIDENT_SENSOR_AT: {}'.format(datetime.now()))

    def check_incidents(self, sn_incidents):
        ''' Create a trigger to run cleanup on any open incidents that are not being processed
        '''
        inc_st2_key = 'servicenow.incidents_processing'
        processing_incs = self.st2_client.keys.get_by_name(inc_st2_key)

        processing_incs = [] if processing_incs is None else ast.literal_eval(processing_incs.value)

        for inc in sn_incidents:
            # skip any incidents that are currently being processed
            if inc['number'] in processing_incs:
                self._logger.info('Already processing INC: ' + inc['number'])
                continue
            else:
                self._logger.info('Processing INC: ' + inc['number'])
                processing_incs.append(inc['number'])
                incs_str = str(processing_incs)
                kvp = KeyValuePair(name=inc_st2_key, value=incs_str)
                self.st2_client.keys.update(kvp)
                self.check_description(inc)

    def get_company_and_ag_and_ciname(self, inc):
        configuration_item_env = ''
        if inc['assignment_group'] and inc['assignment_group']['link']:
            response = self.base_action.sn_api_call(method='GET',
                                                    url=inc['assignment_group']['link'])
            assign_group = response['name']
        else:
            self._logger.info('Assignment Group not found for INC: ' + inc['number'])
            assign_group = ''

        if inc['company'] and inc['company']['link']:
            response = self.base_action.sn_api_call(method='GET',
                                                   url=inc['company']['link'])
            company = response['name']
        else:
            self._logger.info('Company not found for INC: ' + inc['number'])
            company = ''

        if inc['cmdb_ci'] and inc['cmdb_ci']['link']:
            response = self.base_action.sn_api_call(method='GET',
                                                   url=inc['cmdb_ci']['link'])
            configuration_item_name = response['name']
            configuration_item_env = response['u_environment'].lower()
        else:
            self._logger.info('Company not found for INC: ' + inc['number'])
            configuration_item_name = ''

        return assign_group, company,configuration_item_name,configuration_item_env



    def betweenString(self,value, a, b):
        # Find and validate before-part.
        pos_a = value.find(a)
        if pos_a == -1: return ""
        # Find and validate after part.
        pos_b = value.rfind(b)
        if pos_b == -1: return ""
        # Return middle part.
        adjusted_pos_a = pos_a + len(a)
        if adjusted_pos_a >= pos_b: return ""
        return value[adjusted_pos_a:pos_b]

    def afterString(self,value, a):
        # Find and validate first part.
        pos_a = value.rfind(a)
        if pos_a == -1: return ""
        # Returns chars after the found string.
        adjusted_pos_a = pos_a + len(a)
        if adjusted_pos_a >= len(value): return ""
        return value[adjusted_pos_a:]

    def beforeString(self,value, a):
        # Find first part and return slice before it.
        pos_a = value.find(a)
        if pos_a == -1: return ""
        return value[0:pos_a]

    def check_description(self, inc):
        desc_rec = inc['description']
        desc = inc['description'].lower()
        short_desc = inc['short_description']
        short_desc_lower = inc['short_description'].lower()
        triggers_list = ['is not responding to ping', 'cpu utilization on', 'memory usage on - memory used on - linux - unix', 'logical disk free space on', \
                    'memory usage on - memory used on - intel - wintel', 'Windows Service - is not running - Service Alert: - has changed to Stopped state', \
                    'cpu utilization on', 'disk - is critical', 'system performance processor queue length', 'is not running on host', \
                    'opsramp agent service is offline', 'network outage - device reboot detected', 'snmp agent not responding', 'port down - ifindex - oper down',\
                    'bgp peer', 'ap not associated with controller', 'ap antenna offline', 'port utilization high', 'ospf', 'power supply alarm']
        assign_group, company, configuration_item_name,configuration_item_env = self.get_company_and_ag_and_ciname(inc)

#        if 'is not responding to ping' in desc:
#           self._logger.info("Inside is not responding to ping trigger condition")
            #assign_group, company = self.get_company_and_ag_and_ciname(inc)

#            if assign_group == '':
#                check_uptime = 'False'
#                os_type = ''
#            else:
#                check_uptime = 'True'
#                os_type = 'windows' if 'intel' in assign_group.lower() else 'linux'

#            ci_address_end = desc.split(' is not responding to ping')[0]
#            ci_address = ci_address_end.split(' ')[-1]
#            payload = {
#                'assignment_group': assign_group,
#                'check_uptime': check_uptime,
#                'ci_address': ci_address,
#                'customer_name': company,
#                'detailed_desc': inc['description'],
#                'inc_number': inc['number'],
#                'inc_sys_id': inc['sys_id'],
#                'os_type': os_type,
#                'short_desc': inc['short_description'],
#                'rec_short_desc': 'is not responding to ping',
#                'rec_detailed_desc': 'is not responding to ping',
#                'configuration_item_name': configuration_item_name
#            }
#            self._logger.info(inc['number'] + ": DISPATCHING ntt_itsm.unreachable_ping WORKFLOW" + self.add_utc_time())
#            self._sensor_service.dispatch(trigger='ntt_itsm.unreachable_ping', payload=payload)
        if (('total cpu utilization' in desc) and ('intel' in assign_group.lower() or 'wintel' in assign_group.lower())):
            self._logger.info("Inside cpu utilization on trigger condition")
            #assign_group, company = self.get_company_and_ag(inc)

            ci_address_begin = desc.split('cpu utilization on ')[-1]
            ci_address = ci_address_begin.split(' ')[0]
            recurrence = ci_address + " " + 'Total CPU Utilization on'
            if ', th is' in desc:
                threshold_begin = desc.split(', th is ')[-1]
                threshold = threshold_begin.split('%')[0]
            else:
                threshold = None

            payload = {
                'assignment_group': assign_group,
                'ci_address': ci_address,
                'cpu_name': '_total',
                'cpu_type': 'ProcessorTotalProcessorTime',
                'customer_name': company,
                'detailed_desc': inc['description'],
                'inc_number': inc['number'],
                'inc_sys_id': inc['sys_id'],
                'incident_state': inc['incident_state'],
                'os_type': 'windows',
                'short_desc': inc['short_description'],
                'threshold_percent': threshold,
                'rec_short_desc': recurrence,
                'rec_detailed_desc': 'total cpu utilization on',
                'configuration_item_name': configuration_item_name
            }
            self._logger.info(inc['number'] + ": DISPATCHING ntt_itsm.high_cpu WORKFLOW" + self.add_utc_time())
            self._sensor_service.dispatch(trigger='ntt_itsm.high_cpu', payload=payload)

        #elif 'memory usage on' in desc or 'memory used on' in desc:
        elif (('memory usage on' in desc or 'memory used on' in desc) and ('linux' in assign_group.lower() or 'unix' in assign_group.lower())):
            self._logger.info("Inside memory usage on trigger condition")
            #assign_group, company = self.get_company_and_ag(inc)

            if 'memory usage on' in desc:
                ci_address_begin = desc.split('memory usage on ')[-1]
            else:
                ci_address_begin = desc.split('memory used on ')[-1]
            ci_address = ci_address_begin.split(' ')[0]
            if ', th is' in desc:
                threshold_begin = desc.split(', th is ')[-1]
                threshold = threshold_begin.split('%')[0]
            else:
                threshold = None
            payload = {
                'assignment_group': assign_group,
                'ci_address': ci_address,
                'customer_name': company,
                'detailed_desc': inc['description'],
                'inc_number': inc['number'],
                'inc_sys_id': inc['sys_id'],
                'memory_threshold': threshold,
                'os_type': 'linux',
                'short_desc': inc['short_description']
            }
            self._logger.info(inc['number'] + ": DISPATCHING ntt_itsm.high_memory WORKFLOW" + self.add_utc_time())
            #self._sensor_service.dispatch(trigger='ntt_itsm.high_memory', payload=payload)
        elif ('logical disk free space on' in desc) and ('c:' in desc):
            #assign_group, company = self.get_company_and_ag(inc)
            self._logger.info("Inside logical disk free space on trigger condition")
            ci_address_begin = desc.split('logical disk free space on ')[-1]
            ci_address = ci_address_begin.split(' ')[0]
            #disk_name_end = inc['description'].split(':')[0]
            #disk_name = disk_name_end.split(' ')[-1]
            disk_name = 'C'

            Find_Before_Short = self.beforeString(short_desc,'is at')
            Find_Before_Short = Find_Before_Short.strip()
            rec_short_desc = Find_Before_Short
            self._logger.info(rec_short_desc)
            Find_Before_long = self.beforeString(desc_rec,'is at')
            Find_Before_long = Find_Before_long.strip()
            rec_detailed_desc = Find_Before_long
            self._logger.info(rec_detailed_desc)

            if ', th is' in desc:
                threshold_begin = desc.split(', th is ')[-1]
                threshold = int(float(threshold_begin.split('%')[0].strip()))
            else:
                threshold = 0
            payload = {
                'assignment_group': assign_group,
                'ci_address': ci_address,
                'customer_name': company,
                'detailed_desc': inc['description'].replace(':', ''),
                'disk_name': disk_name,
                'inc_number': inc['number'],
                'inc_sys_id': inc['sys_id'],
                'os_type': 'windows',
                'short_desc': inc['short_description'].replace(':', ''),
                'threshold_percent': threshold,
                'threshold_mb': 100,
                'threshold_type': "percent",
                'rec_short_desc': rec_short_desc,
                'rec_detailed_desc': rec_detailed_desc,
                'configuration_item_name': configuration_item_name
            }
            self._logger.info(inc['number'] + ": DISPATCHING ntt_itsm.high_disk WORKFLOW" + self.add_utc_time())
            self._sensor_service.dispatch(trigger='ntt_itsm.high_disk', payload=payload)
        elif (('memory usage on' in desc or 'memory used on' in desc) and ('intel' in assign_group.lower() or 'wintel' in assign_group.lower() or 'hyg-service' in assign_group.lower() or 'hyg-dba-sqlserver' in assign_group.lower())):
            self._logger.info("Inside memory usage on trigger condition")
            ci_address = ''
            rec_short_desc = ''
            rec_detailed_desc = ''
            Find_Before_Short = self.beforeString(short_desc,'is at')
            Find_Before_Short = Find_Before_Short.strip()
            rec_short_desc = Find_Before_Short
            Find_Before_long = self.beforeString(desc,'is at')
            Find_Before_long = Find_Before_long.strip()
            rec_detailed_desc = Find_Before_long

            if ', th is' in desc:
                threshold_begin = desc.split(', th is ')[-1]
                threshold = threshold_begin.split('%')[0]
            else:
                threshold = None

            if 'memory usage on' in desc:
                #rec_short_desc = 'memory usage on'
                #rec_detailed_desc = 'memory usage on'
                ci_address_begin = desc.split('memory usage on ')[-1]
                ci_address = ci_address_begin.split(' ')[0]
            elif 'memory used on' in desc:
                #rec_short_desc = 'memory used on'
                #rec_detailed_desc = 'memory used on'
                ci_address_begin = desc.split('memory used on ')[-1]
                ci_address = ci_address_begin.split(' ')[0]

            if 'physical memory' in desc:
                memory_type = 'Physical'
            elif 'virtual' in desc:
                memory_type = 'Virtual'
            elif ('physical' in desc or 'windows | memory usage |' in desc or  'memory utilization' in desc or 'memory usage on' in desc ):
                memory_type = 'Physical'
            elif ('high memory paging' in desc or 'paging is now' in desc):
               memory_type = 'PagesPerSec'
            elif ('paging file usage' in desc):
               memory_type = 'PagingFile'
            elif ('threshold of memory not met' in desc):
               memory_type = 'MemoryAvailableBytes'
            elif ('memory low:' in desc):
               memory_type = 'MemoryUsedBytesPct'
            else:
               memory_type = 'Physical'
            #cmdb_ci.name
            if configuration_item_name == "Event_CI_Not Found":
                rec_short_desc = Find_Before_Short
                rec_detailed_desc = Find_Before_long
            payload = {
                'assignment_group': assign_group,
                'ci_address': ci_address,
                'customer_name': company,
                'detailed_desc': inc['description'],
                'inc_number': inc['number'],
                'inc_sys_id': inc['sys_id'],
                'os_type': 'windows',
                'short_desc': inc['short_description'],
                'threshold_percent': threshold,
                'incident_state': inc['incident_state'],
                'rec_short_desc': rec_short_desc,
                'rec_detailed_desc': rec_detailed_desc,
                'configuration_item_name': configuration_item_name,
                'memory_type':memory_type
            }
            self._logger.info(inc['number'] + ": DISPATCHING ntt_itsm.win_memory_high WORKFLOW" + self.add_utc_time())
            self._sensor_service.dispatch(trigger='ntt_itsm.win_memory_high', payload=payload)

        elif (('windows service' in short_desc.lower() and 'is not running' in short_desc) or ('patrol agent' in short_desc.lower() and 'is disconnected' in short_desc)) and ('intel' in assign_group.lower() or 'HYG-DBA-SQLSERVER-TIER1' in assign_group):
            self._logger.info("Inside Windows Service trigger condition")
            ci_address = ''
            rec_short_desc = ''
            rec_detailed_desc = ''

            if ('truesight' in short_desc.lower() and 'windows service' in short_desc.lower() and 'is not running on host' in short_desc ):
               ci_address_begin = short_desc.strip().lower().split('truesight ')[-1]
               ci_address = ci_address_begin.split(' ')[0]

               Find_After = self.afterString(short_desc.lower(), "windows service")
               Find_After = Find_After.strip()
               Find_Before = self.beforeString(Find_After,'is not running on host')
               Find_Before =Find_Before.strip()
               rec_short_desc = 'Windows Service'
               rec_detailed_desc = Find_Before
               service_name  = Find_Before
            elif ('windows service' in short_desc.lower() and 'is not running on host' in short_desc ):
               ci_address = short_desc.strip().split(' ')[0]
               Find_After = self.afterString(short_desc.lower(), "windows service")
               Find_After = Find_After.strip()
               Find_Before = self.beforeString(Find_After,'is not running on host')
               Find_Before =Find_Before.strip()
               rec_short_desc = 'Windows Service'
               service_name  = Find_Before
               rec_detailed_desc = service_name
            elif ('patrol agent' in short_desc.lower() and 'is disconnected' in short_desc  ):
               ci_address = short_desc.strip().split(' ')[0]
               service_name = 'PatrolAgent'
               rec_short_desc = 'patrol agent'
               rec_detailed_desc = 'patrol agent'

            payload = {
                'assignment_group': assign_group,
                'ci_address': ci_address,
                'customer_name': company,
                'detailed_desc': inc['description'],
                'inc_number': inc['number'],
                'inc_sys_id': inc['sys_id'],
                'short_desc': inc['short_description'],
                'incident_state': inc['incident_state'],
                'service_name': service_name,
                'rec_short_desc': rec_short_desc,
                'rec_detailed_desc': rec_detailed_desc,
                'configuration_item_name': configuration_item_name
            }
            self._logger.info(inc['number'] + ": DISPATCHING ntt_itsm.win_service_check WORKFLOW" + self.add_utc_time())
            self._sensor_service.dispatch(trigger='ntt_itsm.win_service_check', payload=payload)

        elif (('cpu utilization on' in desc) and ('linux' in assign_group.lower())):
            self._logger.info("Inside cpu utilization on trigger condition")
            ci_address = ''

            # ci_address_begin = desc.split('cpu utilization on ')[-1]
            # ci_address = ci_address_begin.split(' ')[0]

            Find_Before = self.beforeString(short_desc,'Total CPU Utilization on')
            Find_Before =Find_Before.strip()
            ci_address = Find_Before
            Find_After = self.afterString(ci_address, "TrueSight ")
            Find_After = Find_After.strip()
            ci_address = Find_After
            rec_short_desc = 'Total CPU Utilization on'
            rec_detailed_desc = 'Total CPU Utilization on'

            if ', th is' in desc:
               # threshold_begin = desc.split(', th is ')[-1]
               # threshold = threshold_begin.split('%')[0]
               Find_After = self.afterString(desc, "th is")
               Find_After = Find_After.strip()
               threshold = Find_After

               Find_Before = self.beforeString(threshold,'%')
               Find_Before =Find_Before.strip()
               threshold = Find_Before
               threshold = self.beforeString(threshold,'.')
            else:
               threshold = 85

            payload = {
                'assignment_group': assign_group,
                'ci_address': ci_address,
                'cpu_name': '_total',
                'cpu_type': 'ProcessorTotalProcessorTime',
                'customer_name': company,
                'detailed_desc': inc['description'],
                'inc_number': inc['number'],
                'inc_sys_id': inc['sys_id'],
                'os_type': 'linux',
                'short_desc': inc['short_description'],
                'threshold_percent': threshold,
                'incident_state': inc['incident_state'],
                'rec_short_desc': rec_short_desc,
                'rec_detailed_desc': rec_detailed_desc
            }
            self._logger.info(inc['number'] + ": DISPATCHING ntt_itsm.win_service_check WORKFLOW" + self.add_utc_time())
            self._logger.info('Processing INC: ' + inc['number'] + '' + str(payload))
            #self._sensor_service.dispatch(trigger='ntt_itsm.linux_cpu_high', payload=payload)
        elif (('disk' in desc and 'is critical' in desc) and (('linux' in assign_group.lower()) or ('unix' in assign_group.lower()))):
            self._logger.info("Inside disk utilization on trigger condition")
            ci_address = ''
            threshold = '85'
            Find_Before = self.beforeString(short_desc,'Disk')
            Find_Before =Find_Before.strip()
            ci_address = Find_Before
            Find_After = self.afterString(short_desc, "Threshold is")
            Find_After = Find_After.strip()
            threshold = Find_After
            disk_name_before = self.beforeString(short_desc,'Critical.Used')
            disk_name_before =disk_name_before.strip()
            disk_name = disk_name_before
            disk_name_after = self.afterString(disk_name_before, "Disk")
            disk_name_after = disk_name_after.strip()
            disk_name = disk_name_after
            rec_short_desc = 'Disk Capacity'
            rec_detailed_desc = disk_name
            payload = {
                'assignment_group': assign_group,
                'ci_address': ci_address,
                'customer_name': company,
                'detailed_desc': inc['description'],
                'inc_number': inc['number'],
                'inc_sys_id': inc['sys_id'],
                'short_desc': inc['short_description'],
                'incident_state': inc['incident_state'],
                'disk_name': disk_name,
                'os_type': 'linux',
                'disk_threshold': threshold,
                'rec_short_desc': rec_short_desc,
                'rec_detailed_desc': rec_detailed_desc,
                'configuration_item_name': configuration_item_name
            }
            self._logger.info(inc['number'] + ": DISPATCHING ntt_itsm.disk_usage_check_linux WORKFLOW" + self.add_utc_time())
            #self._sensor_service.dispatch(trigger='ntt_itsm.disk_usage_check_linux', payload=payload)
        elif (('system performance processor queue length' in desc ) and ('intel' in assign_group.lower() or 'wintel' in assign_group.lower())):
            self._logger.info("Inside system performance processor queue length trigger condition")
            ci_address = ''
            rec_short_desc = ''
            rec_detailed_desc = ''
            desc_org = inc['description']

            Find_Before = self.beforeString(desc_org,'System Performance')
            ci_address =Find_Before.strip()

            Find_After = self.afterString(desc_org, ">")
            Find_After = Find_After.strip()
            Find_Before = self.beforeString(Find_After,'Number')
            threshold_queue =Find_Before.strip()

            rec_short_desc = 'System Performance Processor Queue Length'
            rec_detailed_desc = 'System Performance Processor Queue Length'

            payload = {
                'assignment_group': assign_group,
                'ci_address': ci_address,
                'customer_name': company,
                'detailed_desc': inc['description'],
                'inc_number': inc['number'],
                'inc_sys_id': inc['sys_id'],
                'os_type': 'windows',
                'short_desc': inc['short_description'],
                'threshold_queue': threshold_queue,
                'incident_state': inc['incident_state'],
                'rec_short_desc': rec_short_desc,
                'rec_detailed_desc': rec_detailed_desc,
                'configuration_item_name': configuration_item_name,
                'cpu_type':'ProcessorQueueLength'
            }
            self._logger.info(inc['number'] + ": DISPATCHING ntt_itsm.win_cpu_queue_length WORKFLOW" + self.add_utc_time())
            #self._sensor_service.dispatch(trigger='ntt_itsm.win_cpu_queue_length', payload=payload)

        elif ('is not running on host' in desc or ('patrol agent' in short_desc.lower() and 'is disconnected' in short_desc.lower())) and ('unix' in assign_group.lower() or 'linux' in assign_group.lower()):
            insertto_datastore = "true"
            #service
            if 'is not running on host' in desc:
                service_begin = desc.split('is not running on host')[0]
                service = service_begin.split('Linux process')[-1]
                service = service.strip()
                 #CI Name
                ci_name_begin = desc.split('is not running on host')[-1]
                ci_address = ci_name_begin.strip()
            if 'patrol agent' in short_desc.lower() and 'is disconnected' in short_desc.lower():
                service_begin = short_desc.split()[1] + " " + short_desc.split()[2]
                service = 'PatrolAgent'
                #CI Name
                ci_name_begin = short_desc.split()[0]
                ci_address = ci_name_begin.strip()

            payload = {
                'assignment_group': assign_group,
                'ci_address': ci_address,
                'customer_name': company,
                'detailed_desc': inc['description'],
                'inc_number': inc['number'],
                'inc_sys_id': inc['sys_id'],
                'os_type': 'linux',
                'short_desc': inc['short_description'],
                'service': service,
                'incident_state': inc['incident_state'],
                'configuration_item_name': configuration_item_name
            }
            self._sensor_service.dispatch(trigger='ntt_itsm.unix_process_alert', payload=payload)

        elif (('opsramp agent service is offline' in desc ) and ('intel' in assign_group.lower() or 'wintel' in assign_group.lower())):
            self._logger.info("Inside opsramp agent service is offline trigger condition")
            ci_address = ''
            rec_short_desc = ''
            rec_detailed_desc = ''
            desc_org = inc['description']
            Find_Before = self.beforeString(desc_org,'OpsRamp Agent service is offline')
            ci_address =Find_Before.strip()

            rec_short_desc = 'OpsRamp agent is offline '
            rec_detailed_desc = 'OpsRamp Agent service is offline'
            # self._logger.info('Already processing INC: ' + inc['number'] +'incident_open_at' + inc['opened_at'] )
            payload = {
                'assignment_group': assign_group,
                'ci_address': ci_address,
                'customer_name': company,
                'detailed_desc': inc['description'],
                'inc_number': inc['number'],
                'inc_sys_id': inc['sys_id'],
                'incident_open_at': inc['opened_at'],
                'os_type': 'windows',
                'short_desc': inc['short_description'],
                'incident_state': inc['incident_state'],
                'rec_short_desc': rec_short_desc,
                'rec_detailed_desc': rec_detailed_desc,
                'configuration_item_name': configuration_item_name,
                'configuration_item_env': configuration_item_env
            }
            self._logger.info(inc['number'] + ": DISPATCHING ntt_itsm.win_monitoring_heartbeat_failure WORKFLOW" + self.add_utc_time())
            #self._sensor_service.dispatch(trigger='ntt_itsm.win_monitoring_heartbeat_failure', payload=payload)

        elif (('network outage' in desc or 'device reboot detected' in desc ) and ('nttds-is netops' in assign_group.lower() or 'nttds-is network global' in assign_group.lower() or 'hyg-service desk-l1.5' in assign_group.lower() or 'ingr-network-voice' in assign_group.lower())):
            self._logger.info("Inside network outage trigger condition")
            insertto_datastore = 'true'
            desc_org = inc['description']
            if (( 'NMSENVPOLL' in desc_org ) and ( 'Network Outage' in desc_org)):
                Find_Before = self.beforeString(desc_org,': Network Outage')
                Find_Before = Find_Before.strip()
                Find_Between = self.betweenString(Find_Before,":",":")
                ci_address = Find_Between.strip()
            elif (( 'NMSENVPOLL' in desc_org ) and ('Device Warm Reboot' in desc_org ) ):
                Find_Before = self.beforeString(desc_org,': Device Warm Reboot')
                Find_Before = Find_Before.strip()
                Find_Between = self.betweenString(Find_Before,":",":")
                ci_address = Find_Between.strip()
                #self._logger.info("Inside Device warm reboot")
            elif (( 'NMSENVPOLL' in desc_org ) and ('Device Cold Reboot' in desc_org ) ):
                Find_Before = self.beforeString(desc_org,': Device Cold Reboot')
                Find_Before = Find_Before.strip()
                Find_Between = self.betweenString(Find_Before,":",":")
                ci_address = Find_Between.strip()
                #self._logger.info("Inside Device cold reboot")

            elif (( 'NMSENVPOLL' in desc_org ) and ( 'Device Reboot Detected' in desc_org)):
                Find_Before = self.beforeString(desc_org,': Device Reboot Detected')
                Find_Before = Find_Before.strip()
                Find_Between = self.betweenString(Find_Before,":",":")
                ci_address = Find_Between.strip()
            else:
                Find_Before = self.beforeString(desc_org,':Network Outage')
                Find_Before = Find_Before.strip()
                Find_Between = self.betweenString(Find_Before,":",":")
                Find_Between = Find_Between.strip()
                Find_After = self.afterString(Find_Between, ":")
                ci_address = Find_After.strip()

            if 'Network Outage' in desc_org:
                rec_short_desc = 'Network Outage'
                rec_detailed_desc = 'Network Outage'
            elif 'Device Reboot Detected' in desc_org:
                rec_short_desc = 'Device Reboot Detected'
                rec_detailed_desc = 'Device Reboot Detected'
            elif 'Device Reboot Detected' in desc_org:
                rec_short_desc = 'Device Warm Reboot'
                rec_detailed_desc = 'Device Warm Reboot'
            elif 'Device Reboot Detected' in desc_org:
                rec_short_desc = 'Device Cold Reboot'
                rec_detailed_desc = 'Device Cold Reboot'
            else:
                rec_short_desc = 'Network Outage'
                rec_detailed_desc = 'Network Outage'

            Find_Before = self.beforeString(desc,':')
            Find_Before = Find_Before.strip()
            nms_poll_data = self.beforeString(Find_Before,'.')
            if '|' in nms_poll_data:
                nms_poll_data = nms_poll_data.split('|')[1]
            nms_poll_data = nms_poll_data.strip()

            payload = {
                'inc_number': inc['number'],
                'inc_sys_id': inc['sys_id'],
                'ci_address': ci_address,
                'assignment_group': assign_group,
                'customer_name': company,
                'short_desc': inc['short_description'],
                'detailed_desc': inc['description'],
                'incident_state': inc['incident_state'],
                'incident_open_at': inc['opened_at'],
                'rec_short_desc': rec_short_desc,
                'rec_detailed_desc': rec_detailed_desc,
                'configuration_item_name': configuration_item_name,
                'nms_poll_data': nms_poll_data
            }
            self._logger.info(inc['number'] + ": DISPATCHING ntt_itsm.nw_unreachable_to_ping WORKFLOW" + self.add_utc_time())
            self._sensor_service.dispatch(trigger='ntt_itsm.nw_unreachable_to_ping', payload=payload)
        elif (('snmp agent not responding' in desc )):
            self._logger.info("Inside snmp agent not responding trigger condition")
            desc_org = inc['description']
            ci_address = ''
            if (( 'NMSENVPOLL' in desc_org )):
                Find_After = self.afterString(desc_org,'nttdataservices.com :')
                Find_Before = self.beforeString(Find_After,':')
                ci_address = Find_Before.strip()


            rec_short_desc = 'SNMP Agent Not Responding'
            rec_detailed_desc = 'SNMP Agent Not Responding'

            payload = {
                'inc_number': inc['number'],
                'inc_sys_id': inc['sys_id'],
                'ci_address': ci_address,
                'assignment_group': assign_group,
                'customer_name': company,
                'short_desc': inc['short_description'],
                'detailed_desc': inc['description'],
                'incident_state': inc['incident_state'],
                'incident_open_at': inc['opened_at'],
                'rec_short_desc': rec_short_desc,
                'rec_detailed_desc': rec_detailed_desc,
                'configuration_item_name': configuration_item_name
            }
            self._logger.info(inc['number'] + ": DISPATCHING ntt_itsm.nw_snmp_not_responding WORKFLOW" + self.add_utc_time())
            #self._sensor_service.dispatch(trigger='ntt_itsm.nw_snmp_not_responding', payload=payload)
        elif (('port down' in desc) and ('ifindex' in desc or 'oper down' in desc)):
            self._logger.info("Inside port down trigger condition")
            print("Print info:Portdown triggerred")
            desc_org = inc['description']
            rec_short_desc = inc['short_description']
            rec_detailed_desc='Port Down'
            ci_address = desc.split(': ')[1]
            ci_address = ci_address.strip()
            port_details = desc.split('[')[len(desc.split('[')) -1 ].split(']')[0].replace(" ", "")
            print(port_details)
            if 'port down' in desc and 'ifindex' in desc:
                workflow_type = 'PortLink'
                ifindex = desc_org.split('ifIndex=')[1].strip()
                rec_detailed_desc = desc_org.split(': ifIndex')[0]
            elif 'port down' in desc and 'ifindex' not in desc:
                workflow_type = "PortOper"
                ifindex = ""
                rec_detailed_desc = desc_org.split(']')[0]
                if '|' in rec_detailed_desc:
                    rec_detailed_desc = rec_detailed_desc.split('|')[1]
            rec_detailed_desc = rec_detailed_desc.strip()
            rec_short_desc = rec_short_desc.strip()
            mib = self.betweenString(desc_org, '[', ']').strip()
            snmp_version='v2'
            Find_Before = self.beforeString(desc,':')
            Find_Before = Find_Before.strip()
            nms_poll_data = self.beforeString(Find_Before,'.')
            if '|' in nms_poll_data:
                nms_poll_data = nms_poll_data.split('|')[1]
            nms_poll_data = nms_poll_data.strip()

            payload = {
                'assignment_group': assign_group,
                'device_ip': ci_address,
                'customer_name': company,
                'device_name': configuration_item_name,
                'detailed_desc': desc_org,
                'inc_number': inc['number'],
                'inc_sys_id': inc['sys_id'],
                'short_desc': inc['short_description'],
                'rec_detailed_desc': rec_detailed_desc,
                'rec_short_desc': rec_short_desc,
                'workflow_type': workflow_type,
                'ifindex': ifindex,
                'mib': mib,
                'port_details': port_details,
                'snmp_version': snmp_version,
                'nms_poll_data' : nms_poll_data.lower()
            }
            self._logger.info(inc['number'] + ": DISPATCHING ntt_itsm.nw_port_down WORKFLOW" + self.add_utc_time())
            self._sensor_service.dispatch(trigger='ntt_itsm.nw_port_down', payload=payload)
        elif ('bgp peer' in desc):
            self._logger.info("Inside bgp peer trigger condition")
            desc_org = inc['description']
            os_type = 'linux'
            rec_short_desc='BGP Peer'
            rec_detailed_desc='BGP Peer'

            ci_address = desc.split(': ')[1]
            ci_address = ci_address.strip()
            peer_ip_end = desc.split('peer to ')[1]
            peer_ip = peer_ip_end.split(')')[0]
            peer_ip = peer_ip.strip()


            Find_Before = self.beforeString(desc,':')
            Find_Before = Find_Before.strip()
            nms_poll_data = self.beforeString(Find_Before,'.')
            if '|' in nms_poll_data:
                nms_poll_data = nms_poll_data.split('|')[1]
            nms_poll_data = nms_poll_data.strip()

            payload = {
                'assignment_group': assign_group,
                'device_ip': ci_address,
                'customer_name': company,
                'device_name': configuration_item_name,
                'peer_ip': peer_ip,
                'detailed_desc': desc_org,
                'inc_number': inc['number'],
                'inc_sys_id': inc['sys_id'],
                #'os_type': os_type,
                'short_desc': inc['short_description'],
                'rec_detailed_desc': rec_detailed_desc,
                'rec_short_desc': rec_short_desc,
                'nms_poll_data': nms_poll_data.lower()
            }
            self._logger.info(inc['number'] + ": DISPATCHING ntt_itsm.bgp_peer_check WORKFLOW" + self.add_utc_time())
            #self._sensor_service.dispatch(trigger='ntt_itsm.bgp_peer_check', payload=payload)
        elif 'ap not associated with controller' in desc or 'ap unreachable (icmp)' in desc:
            insertto_datastore = 'true'
            self._logger.info("Inside ap not associated with controller trigger condition")
            if 'ap not associated with controller' in desc:
                ci_address = desc.split(':AP Not Associated With Controller:')[0].split(':')[1].strip()
                accesspoint_name = short_desc.partition(': AP Not Associated With Controller')[0].split(':')[-1].strip()
            elif 'ap unreachable (icmp)' in desc:
                ci_address = short_desc.split(':')[1].strip()
                accesspoint_name = short_desc.split(':')[2].strip()
            Find_Before = self.beforeString(desc,':')
            Find_Before = Find_Before.strip()
            nms_poll_data = self.beforeString(Find_Before,'.')
            if '|' in nms_poll_data:
                nms_poll_data = nms_poll_data.split('|')[1]
            nms_poll_data = nms_poll_data.strip()
            payload = {
                    'company': company,
                    'wlc_ip': ci_address,
                    'detailed_desc': inc['description'],
                    'inc_number': inc['number'],
                    'inc_sys_id': inc['sys_id'],
                    'short_desc': inc['short_description'],
                    'wap_name': accesspoint_name,
                    'entuity_name': nms_poll_data.lower()
            }
            self._logger.info(inc['number'] + ": DISPATCHING ntt_itsm.wireless_accesspoint_alarm WORKFLOW" + self.add_utc_time())
            self._sensor_service.dispatch(trigger='ntt_itsm.nw_wap_alert_check', payload=payload)
        #elif 'ap not associated with controller' in desc or 'ap unreachable (icmp)' in desc:
        #    self._logger.info("Inside ap not associated with controller trigger condition")
        #    if assign_group == '':
        #        chekc_uptime = False
        #        os_type = ''
        #    else:
        #        check_uptime = True
        #        os_type = 'windows' if 'intel' in assign_group.lower() else 'linux'
        #    if 'ap not associated with controller' in desc:
        #        ci_address = desc.split(':AP Not Associated With Controller:')[0].split(':')[1].strip()
        #        accesspoint_name = short_desc.partition(': AP Not Associated With Controller')[0].split(':')[-1].strip()
        #    elif 'ap unreachable (icmp)' in desc:
        #        ci_address = desc.split('AP UNREACHABLE (ICMP)')[0].split(':')[1].strip()
        #        accesspoint_name = short_desc.partition(': AP UNREACHABLE (ICMP)')[0].split(':')[-1].strip()
        #    Find_Before = self.beforeString(desc,':')
        #    Find_Before = Find_Before.strip()
        #    nms_poll_data = self.beforeString(Find_Before,'.')
        #    if '|' in nms_poll_data:
        #        nms_poll_data = nms_poll_data.split('|')[1]
        #    nms_poll_data = nms_poll_data.strip()
        #    payload = {
        #            'assignment_group': assign_group,
        #            'ci_address': ci_address,
        #            'customer_name': company,
        #            'detailed_desc': inc['description'],
        #            'inc_number': inc['number'],
        #            'inc_sys_id': inc['sys_id'],
        #            'short_desc': inc['short_description'],
        #            'accesspoint_name': accesspoint_name,
        #            'nms_poll_data': nms_poll_data.lower(),
        #            'configuration_item_name': configuration_item_name
        #    }
        #    self._logger.info(inc['number'] + ": DISPATCHING ntt_itsm.wireless_accesspoint_alarm WORKFLOW" + self.add_utc_time())
        #    self._sensor_service.dispatch(trigger='ntt_itsm.wireless_accesspoint_alarm', payload=payload)
        elif 'ap antenna offline' in desc:
            self._logger.info("Inside ap antenna offline trigger condition")
            rec_detailed_desc = "ap antenna offline"
            rec_short_desc = "ap antenna offline"
            if assign_group == '':
                check_uptime = False
                os_type = ''
            else:
                check_uptime = True
                os_type = 'windows' if 'intel' in assign_group.lower() else 'linux'
            ci_address = desc.split(':AP Antenna Offline:')[0].split(':')[1].strip()
            accesspoint_name = short_desc.partition(': AP Antenna Offline')[0].split(':')[-1].strip()
            Find_Before = self.beforeString(desc,':')
            Find_Before = Find_Before.strip()
            nms_poll_data = self.beforeString(Find_Before,'.')
            if '|' in nms_poll_data:
                nms_poll_data = nms_poll_data.split('|')[1]
            nms_poll_data = nms_poll_data.strip()
            payload = {
                    'assignment_group': assign_group,
                    'ci_address': ci_address,
                    'customer_name': company,
                    'detailed_desc': inc['description'],
                    'inc_number': inc['number'],
                    'inc_sys_id': inc['sys_id'],
                    'short_desc': inc['short_description'],
                    'configuration_item_name': configuration_item_name,
                    'rec_detailed_desc': rec_detailed_desc,
                    'rec_short_desc': rec_short_desc,
                    'accesspoint_name': accesspoint_name,
                    'nms_poll_data': nms_poll_data.lower()
            }
            self._logger.info(inc['number'] + ": DISPATCHING ntt_itsm.wireless_accesspoint_antenna_offline_alarm WORKFLOW" + self.add_utc_time())
            self._sensor_service.dispatch(trigger='ntt_itsm.wireless_accesspoint_antenna_offline_alarm', payload=payload)
        elif (('port utilization high' in desc) and ('nttds-is netops' in assign_group.lower())):
            self._logger.info("Inside port utilization high trigger condition")
            print("Port utilization is high workflow to be triggerred")
            insertto_datastore = 'true'
            ci_address= self.afterString (short_desc,"Entuity :")
            ci_address= self.beforeString (ci_address,":").strip()
            interface_descr= self.betweenString( short_desc, "[", "]").strip()
            desc_org = inc['description']
            payload = {
                'assignment_group': assign_group,
                'snmp_ip': ci_address,
                'customer_name': company,
                'configuration_item_name': configuration_item_name,
                'detailed_desc': desc_org,
                'inc_number': inc['number'],
                'inc_sys_id': inc['sys_id'],
                'short_desc': short_desc,
                'rec_detailed_desc': 'Port Utilization High',
                'rec_short_desc': 'Port Utilization High',
                'interface_descr': interface_descr,
                'utilization_threshold' : '90',
                'nms_ip': "NMSENVPOLLFTC05"
            }
            self._sensor_service.dispatch(trigger='ntt_itsm.port_utilization', payload=payload)
        elif ('temperature alarm' in desc):
            insertto_datastore = 'true'
            target_ip = short_desc.split(':')[1]
            nms_server = desc.split(':')[0].split('.')[0]

            Find_After = self.afterString(short_desc, "Entuity : ")
            Find_After_short = Find_After.strip()
            self._logger.info("Find_After" + Find_After_short)
            Find_Before = self.beforeString(desc_rec, ": Chassis temperature alarm on")
            Find_Before = Find_Before.strip()
            Find_After = self.afterString(Find_Before, "NMSENVPOLLFTC05.nttdataservices.com : ")
            Find_After_des = Find_After.strip()
            self._logger.info("Find_After" + Find_After_des)
            rec_short_desc = Find_After_short
            rec_detailed_desc = Find_After_des

            #rec_detailed_desc = 'Temperature Alarm'
            #rec_short_desc = 'Temperature Alarm'

            payload = {
                    'assignment_group': assign_group,
                    'customer_name': company,
                    'detailed_desc': inc['description'],
                    'inc_number': inc['number'],
                    'inc_sys_id': inc['sys_id'],
                    'incident_state': inc['incident_state'],
                    'short_desc': inc['short_description'],
                    'rec_detailed_desc': rec_detailed_desc,
                    'rec_short_desc': rec_short_desc,
                    'target_ip': target_ip,
                    'configuration_item_name': configuration_item_name,
                    'nms_server': nms_server
            }
            self._logger.info(inc['number'] + ": DISPATCHING ntt_itsm.nw_temperature_alarm WORKFLOW" + self.add_utc_time())
            self._sensor_service.dispatch(trigger='ntt_itsm.nw_temperature_alarm', payload=payload)

        elif 'eigrp' in desc:
            insertto_datastore = 'true'
            workflow_type = ''
            ifindex = ''
            peer_ip = ''

            desc_org = inc['description']
            #rec_short_desc = 'EIGRP Peer Briefly Not'
            #rec_detailed_desc = 'EIGRP Peer Briefly Not Established'

            Find_Before = self.beforeString(short_desc, "Peer Briefly")
            Find_Before = Find_Before.strip()
            Find_After = self.afterString(Find_Before, "Entuity : ")
            Find_After_short = Find_After.strip()
            self._logger.info("Find_After" + Find_After_short)
            rec_short_desc = Find_After_short

            Find_Before = self.beforeString(desc_rec, "Peer Briefly")
            Find_Before = Find_Before.strip()
            Find_After = self.afterString(Find_Before, "NMSENVPOLLFTC05.nttdataservices.com : ")
            Find_After_des = Find_After.strip()
            self._logger.info("Find_After" + Find_After_des)
            rec_detailed_desc = Find_After_des

            ci_address = desc.split(': ')[1]
            ci_address = ci_address.strip()

            if 'peer to' in desc_org:
                Find_After = self.afterString(desc_org, 'peer to')
                Find_After = Find_After.strip()
                Find_Before = self.beforeString(Find_After, ')')
                peer_ip = Find_Before.strip()
            elif 'peered to' in desc_org.lower():
                Find_After = self.afterString(desc_org.lower(), 'peered to')
                peer_ip = Find_After.strip()

            nms_poll_data = self.beforeString(desc, '.')
            if '|' in nms_poll_data:
                nms_poll_data = nms_poll_data.split('|')[1]
                nms_poll_data = nms_poll_data.strip()

            payload = {
                    'assignment_group': assign_group,
                    'ci_address': ci_address,
                    'customer_name': company,
                    'configuration_item_name': configuration_item_name,
                    'detailed_desc': desc_org,
                    'inc_number': inc['number'],
                    'inc_sys_id': inc['sys_id'],
                    'short_desc': inc['short_description'],
                    'rec_detailed_desc': rec_detailed_desc,
                    'rec_short_desc': rec_short_desc,
                    'peer_ip': peer_ip,
                    'nms_poll_data': nms_poll_data.lower()
                }
            #self._sensor_service.dispatch(trigger='ntt_itsm.eigrp_peer_route_disappeared', payload=payload)
            print("DISPATCHING ntt_itsm.eigrp_peer_route_disappeared WORKFLOW")
            self._logger.info(inc['number'] + ": DISPATCHING ntt_itsm.eigrp_peer_route_disappeared WORKFLOW" + self.add_utc_time())
            self._sensor_service.dispatch(trigger='ntt_itsm.eigrp_peer_route_disappeared', payload=payload)

        elif ('ospf' in desc):
            self._logger.info("Inside ospf trigger condition")
            ci_address = short_desc.split(":")[1].strip()
            #if ('ospf peer disappeared' in desc):
            #     ci_address = (short_desc.split(":")[1]).strip()
            #elif('ospf peer not established' in desc or 'ospf peer briefly not established' in desc):
            #      ci_address = short_desc.split(":")[2].strip().split(" ")[0]
            Find_Before = self.beforeString(desc,':')
            Find_Before = Find_Before.strip()
            nms_poll_data = self.beforeString(Find_Before,'.')
            if '|' in nms_poll_data:
                nms_poll_data = nms_poll_data.split('|')[1]
            nms_poll_data = nms_poll_data.lower().strip()

            payload = {
                    'assignment_group': assign_group,
                    'ci_address': ci_address,
                    'customer_name': company,
                    'detailed_desc': inc['description'],
                    'inc_number': inc['number'],
                    'inc_sys_id': inc['sys_id'],
                    'short_desc': inc['short_description'],
                    'nms_poll_data': nms_poll_data
            }
            self._logger.info(inc['number'] + ": DISPATCHING ntt_itsm.network_peer_route_disappeared_ospf WORKFLOW" + self.add_utc_time())
            #self._sensor_service.dispatch(trigger='ntt_itsm.network_peer_route_disappeared_ospf', payload=payload)
        elif (('power supply' in short_desc_lower) and ('nttds-is netops' in assign_group.lower())):
            insertto_datastore = 'true'
            ci_address = short_desc.split(':')[1].strip()
            nms_poll_data = desc.split(':')[0].split('.')[0]
            nms_poll_data = nms_poll_data.lower().strip()

            rec_short_desc = 'power supply'
            rec_detailed_desc = ci_address

            payload = {
                    'assignment_group': assign_group,
                    'customer_name': company,
                    'detailed_desc': inc['description'],
                    'inc_number': inc['number'],
                    'inc_sys_id': inc['sys_id'],
                    'incident_state': inc['incident_state'],
                    'short_desc': inc['short_description'],
                    'rec_detailed_desc': rec_detailed_desc,
                    'rec_short_desc': rec_short_desc,
                    'ci_address': ci_address,
                    'configuration_item_name': configuration_item_name,
                    'nms_poll_data': nms_poll_data
            }
            self._logger.info(inc['number'] + ": DISPATCHING ntt_itsm.nw_power_supply_alarm WORKFLOW" + self.add_utc_time())
            self._sensor_service.dispatch(trigger='ntt_itsm.nw_power_supply_alarm', payload=payload)


    def cleanup(self):
        pass

    def add_trigger(self, trigger):
        pass

    def update_trigger(self, trigger):
        pass

    def remove_trigger(self, trigger):
        pass


