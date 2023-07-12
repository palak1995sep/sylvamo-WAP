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
from lib.base_action import BaseAction
import datetime as dt    
import requests
import pprint
import json

class ServiceNowIncidentUpdate(BaseAction):
    def __init__(self, config):
        """Creates a new Action given a StackStorm config object (kwargs works too)
        :param config: StackStorm configuration object for the pack
        :returns: a new Action
        """
        super(ServiceNowIncidentUpdate, self).__init__(config)

    def run(self,filepath,servicenow_url,servicenow_username,servicenow_password,number):
        #endpoint = '/api/now/attachment/file?table_name=incident&table_sys_id='+table_sysid+'&file_name='+filepath
        url = 'https://'+servicenow_url+'/api/now/table/incident?sysparm_query=number='+number
        user = servicenow_username
        pwd = servicenow_password
        
        headers={"Content-Type":"application/json","Accept":"application/json"}

        response = requests.request(method='GET',url=url,auth=(user, pwd) ,headers=headers,verify=False)
        data = response.json()['result']
        for inc in data:
            table_sysid = inc['sys_id']
            print(table_sysid)
        
        attach_url = 'https://'+servicenow_url+'/api/now/attachment/upload'
        attach_headers = {"Accept":"*/*"}
        payload = {
                'table_name': 'incident',
                'table_sys_id': table_sysid

        }
        files = {'file': (filepath, open(filepath, 'rb'), 'image/jpg', {'Expires': '0'})}
        attach_response=requests.request('POST',attach_url,auth=(user, pwd) ,headers=attach_headers, files=files, data=payload, verify=False)
        return attach_response
