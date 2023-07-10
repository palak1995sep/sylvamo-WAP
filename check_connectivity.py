#!/usr/bin/env python
import subprocess
import re
import sys

def check_connectivity_status(username, password, ci_address, interface_ip):
    convert_command_output = []
    return_result = []
    login_output = []
    script_name = "/home/bao_net_mon/scripts/nw_clogin.sh"
    script_options = '-noenable'
    command = 'help'
    execute_command = subprocess.Popen([script_name, script_options, '-u', username, '-p', password, '-b', interface_ip, '-c', command, ci_address], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    command_output = execute_command.stdout.readlines()
    start_index = end_index = 0
    convert_command_output = convert_bytes_to_string(command_output)
    for output in convert_command_output:
        if '>help' in output:
            start_index = convert_command_output.index(output)
        if '>logout' in output:
            end_index = convert_command_output.index(output)
    login_output = convert_command_output[int(start_index)+1:int(end_index)]
    connectivity_status = False
    for login_opt_str in login_output:
        if 'Ctrl-' in login_opt_str:
            connectivity_status = True
            break
    connect_sts = 'CONNECTION_STATUS_' + str(connectivity_status)
    return_result.append(connect_sts)
    return_result.append(convert_command_output)
    return return_result

def convert_bytes_to_string(cmd_output_list):
    converted_list  = []
    for item in cmd_output_list:
        converted_list.append(item.decode('utf-8'))
    return converted_list

if __name__ == "__main__":
    username = sys.argv[1]
    password = sys.argv[2]
    ci_address = sys.argv[3]
    interface_ip = sys.argv[4]
    connect_status = check_connectivity_status(username, password, ci_address, interface_ip)
    for i in connect_status:
        if isinstance(i, list):
            print("\n")
            for j in i:
                print(j.strip())
        else:
            print(i)



