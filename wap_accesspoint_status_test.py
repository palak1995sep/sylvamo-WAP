#!/usr/bin/env python
import subprocess
import re
import time
import sys
import json
import ast

output_data = ""

def check_controller_ipaddress(script_name, script_options, username, password, mobility_command, ci_address, mobility_start_index_check, end_index_check, interface_ip):
    global output_data
    worknote_mobility = ["Gathering Mobility Group IP Addresses"]
    output_data = output_data + "\n" + convert_list_to_string(worknote_mobility, True) + "\n"
    ip_addresses = format_output(script_name, script_options, username, password, mobility_command, ci_address, mobility_start_index_check, end_index_check, interface_ip)
    return ip_addresses

def check_controller_mac_address(script_name, script_options, username, password, mobility_command, mac_command, accesspoint_name, ci_address, mobility_start_index_check, mac_start_index_check, end_index_check, interface_ip, ip_address_list):
    global output_data
    ip_mac_list = []
    mac_list = []
    mac_output = ""
    #print("IP address list: {}".format(ip_address_list))
    ap_cmd_name = mac_command + " " + accesspoint_name
    #print("mac command is: {}".format(ap_cmd_name))
    worknote_mobility = ["Fetching MAC Address for Accesspoint " + accesspoint_name]
    output_data = output_data + "\n" + convert_list_to_string(worknote_mobility, True) + "\n"
    mac_address = format_output(script_name, script_options, username, password, ap_cmd_name, ci_address, mac_start_index_check, end_index_check, interface_ip)
    #print("Mac addres is: {}".format(mac_address))
    for mac in mac_address:
        if '-' not in mac and ':' in mac:
            mac_list.append(mac)
    if len(mac_list) == 1:
        for ip in ip_address_list:
            mac_output = convert_list_to_string(mac_list, False)
            ip_mac_list.append(ip+"*"+mac_output)
    elif len(mac_list) < 1:
        ip_mac_list = []
    else:
        print("Multiple mac ids are available")

    return ip_mac_list, mac_output

def check_ip_mac_stauts(script_name, script_options, username, password, mobility_command, mac_command, accesspoint_name, ci_address, mobility_start_index_check, ap_join_status_cmd, mac_start_index_check, end_index_check, interface_ip, ip_address_list):
    try:
        global output_data
        print("Accesspoint MAC Address status:")
        print("Accesspoint name: {}".format(accesspoint_name))
        if(len(ip_address_list) < 1):
            ip_address_list = check_controller_ipaddress(script_name, script_options, username, password, mobility_command, ci_address, mobility_start_index_check, end_index_check, interface_ip)
        if(len(ip_address_list) < 1):
            result = "False_IP_EMPTY"
            print("IP Address list: {},,".format(ip_address_list))
            print("\nAutomation did not find any IP configured in the mobility group")
            print("\nOutput data is:\n {}".format(output_data))
            return result

        ip_mac_address, mac_output = check_controller_mac_address(script_name, script_options, username, password, mobility_command, mac_command, accesspoint_name, ci_address, mobility_start_index_check, mac_start_index_check, end_index_check, interface_ip, ip_address_list)
        if len(ip_mac_address) > 0:
            ip_address_list = json.dumps(ip_address_list)
            ip_mac_address = json.dumps(ip_mac_address)
            print("IP Address list: {},,".format(ip_address_list))
            print("IP Mac address list: {},,".format(ip_mac_address))
            print("\nAutomation found MAC Address {} for AP {} on controller {}".format(mac_output, accesspoint_name, ci_address))
            result = "True_SUCCESS"
        else:
            ip_address_list = json.dumps(ip_address_list)
            ip_mac_address = json.dumps(ip_mac_address)
            print("IP Address list: {},,".format(ip_address_list))
            print("IP Mac address list: {},,".format(ip_mac_address))
            print("\nAutomation did not find the MAC address in show ap search")
            result = "False_RESULTS_EMPTY"
        print("\nOutput data is:\n {}".format(output_data))
        return result
    except:
        print("Automation script failure")
        result = "False_FAILED_SCRIPT"
        return result

def check_ap_join_stauts(script_name, script_options, username, password, mobility_command, mac_command, accesspoint_name, ci_address, mobility_start_index_check, ap_join_status_cmd, mac_start_index_check, end_index_check, interface_ip, ip_mac_address):
    try:
        global output_data
        ap_join_timestamp_list = []
        controller_connected_status = ""
        ip_address_with_controller_connected = ci_address
        if len(ip_mac_address) > 0:
            for ip in ip_mac_address:
                #print("IP is: {}".format(ip))
                ip_output = ip.split('*')[0].strip()
                mac_output = ip.split('*')[1].strip()
                worknote_time1 = ["Command output of 1st join check:"]
                output_data = output_data + "\n\n" + convert_list_to_string(worknote_time1, True) + "\n"
                ap_join_sts = format_output(script_name, script_options, username, password, ap_join_status_cmd+" "+ mac_output, ip_output, ap_join_status_cmd, end_index_check, interface_ip)
                #print("ap join status: {}".format(ap_join_sts))
                for item in ap_join_sts:
                    if 'Is the AP currently connected to controller' in item:
                        controller_connected_status = item.split()[7]
                if controller_connected_status == 'Yes':
                    worknote_stats = ["Automation found that AP " + accesspoint_name + " with mac address " + mac_output + " is connected to controller " + ip_output + ". Waiting 90 seconds to check the join status again"]
                    output_data = output_data + "\n" + convert_list_to_string(worknote_stats, True)
                    time.sleep(90)
                    worknote_time2 = ["Command output of 2nd join check:"]
                    output_data = output_data + "\n\n" + convert_list_to_string(worknote_time2, True) + "\n"
                    new_ap_join_sts = format_output(script_name, script_options, username, password, ap_join_status_cmd+" "+mac_output, ip_output, ap_join_status_cmd, end_index_check, interface_ip)
                    for item in new_ap_join_sts:
                        if 'Is the AP currently connected to controller' in item:
                            controller_connected_status = item.split()[7]
                    if controller_connected_status != 'Yes':
                        controller_connected_status == 'No'
                    else:
                        ip_address_with_controller_connected = ip_output
                    break
                else:
                    controller_connected_status = "No"
                    continue

        if controller_connected_status == "":
            print("Automation did not find the MAC address in show ap search.\n")
            ticket_status = "False_RESULTS_EMPTY"
        elif controller_connected_status == "No":
            print("Automation found the controller connected status is 'No'.\n")
            ticket_status = "False_FAILURE"
        else:
            print("Controller connected status: {}\n".format(controller_connected_status))
            #print("Timestamp status: {}".format(timestamp_status))
            worknote_time = ["Automation found that the join status for AP "+ accesspoint_name +" on controller "+ ip_address_with_controller_connected +" is 'Yes' after 90 seconds."]
            output_data = output_data + "\n" + convert_list_to_string(worknote_time, True)
            ticket_status = "True_SUCCESS"
        #return controller_connected_status, timestamp_status
        print("Output data is: {}".format(output_data))
        print("\n")
        return ticket_status
    except:
        print("Automation script failure")
        return "False_FAILED_SCRIPT"

def format_output(script_name, script_options, username, password, command, ci_address, start_index_check, end_index_check, interface_ip):
    global output_data
    cmd_output = []
    list_data = []
    output = execute_command_data(script_name, script_options, username, password, command, ci_address, interface_ip)
    start_index = 0
    end_index = 0
    str_command_output = convert_bytes_to_string_list(output)
    output_data = output_data + " " + convert_list_to_string(str_command_output, False)
    for i in str_command_output:
        if start_index_check in i:
            start_index = str_command_output.index(i)
        if end_index_check in i:
            end_index = str_command_output.index(i)
    cmd_output = str_command_output[int(start_index)+1:int(end_index)]
    #print("Start Index is: {}".format(start_index))
    #print("End index is: {}".format(end_index))
    #print("Command output is: {}".format(cmd_output))

    for j in cmd_output:
        if 'show ap join stats summary' in command and j.strip() != '':
            list_data.append(j.strip())
        else:
            add_string = re.sub(' +', '*', j.strip())
            if add_string != '':
                list_data.append(add_string.split('*')[1])
    #print("Output: {}".format(list_data))
    return list_data

def execute_command_data(script_name, script_options, username, password, command, ci_address, interface_ip):
    execute_cmd = subprocess.Popen([script_name, script_options, '-u', username, '-p', password, '-b', interface_ip, '-c', command, ci_address], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    opt = execute_cmd.stdout.readlines()
    return opt

def convert_bytes_to_string_list(list_elements):
    str_list = []
    for k in list_elements:
        str_list.append(k.decode('utf-8'))
    return str_list

def convert_list_to_string(list_elements, include_space):
    string_value = ""
    for item in list_elements:
        if include_space:
            string_value += item + " "
        else:
            string_value += item
    return string_value

def validate_date(month, dt):
    is_valid_date = False
    month_list = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    if month in month_list and int(dt) <= 31:
        is_valid_date = True
    return is_valid_date


if __name__ == "__main__":
    script_name = sys.argv[1]
    script_options = sys.argv[2]
    username = sys.argv[3]
    password = sys.argv[4]
    mobility_command = sys.argv[5]
    mac_command = sys.argv[6]
    accesspoint_name = sys.argv[7]
    ci_address = sys.argv[8]
    mobility_start_index_check = sys.argv[9]
    ap_join_status_cmd = sys.argv[10]
    mac_start_index_check = sys.argv[11]
    end_index_check = sys.argv[12]
    interface_ip = sys.argv[13]
    action_to_perform = sys.argv[14]
    ip_mac_address = sys.argv[15]
    ip_address_list = sys.argv[16]
   # print("script name: {}".format(script_name))
   # print("script options: {}".format(script_options))
   # print("username: {}".format(username))
   # print("password: {}".format(password))
   # print("mobility command: {}".format(mobility_command))
   # print("mac command: {}".format(mac_command))
   # print("accesspoint name: {}".format(accesspoint_name))
   # print("ci address: {}".format(ci_address))
   # print("mobility index: {}".format(mobility_start_index_check))
   # print("ap join status: {}".format(ap_join_status_cmd))
   # print("mac start index: {}".format(mac_start_index_check))
   # print("end index: {}".format(end_index_check))
   # print("Interface ip: {}".format(interface_ip))
   # print("ip_mac_address: {}".format(ip_mac_address))
   # print("ip_address_list: {}".format(ip_address_list))
    try:
        if not isinstance(ip_mac_address, list):
            if '[' in ip_mac_address and ']' in ip_mac_address:
                ip_mac_address = ast.literal_eval(ip_mac_address)
        if not isinstance(ip_address_list, list):
            if '[' in ip_address_list and ']' in ip_address_list:
                ip_address_list = ast.literal_eval(ip_address_list)
    except:
        print('')
    if(action_to_perform == "ip_mac"):
        ip_mac_result = check_ip_mac_stauts(script_name, script_options, username, password, mobility_command, mac_command, accesspoint_name, ci_address, mobility_start_index_check, ap_join_status_cmd, mac_start_index_check, end_index_check, interface_ip, ip_address_list)
        print ip_mac_result
    else:
        controller_result = check_ap_join_stauts(script_name, script_options, username, password, mobility_command, mac_command, accesspoint_name, ci_address, mobility_start_index_check, ap_join_status_cmd, mac_start_index_check, end_index_check, interface_ip, ip_mac_address)
        #print("Access point details are:\n {}".format(controller_result))
        print controller_result

