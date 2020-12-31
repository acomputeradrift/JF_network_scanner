#! python3.9

import socket    
import subprocess
import re
import feenySpeedTest
import threading
import logging




class Wireless_Network:
    def __init__(self,ssid):
        self.ssid = ssid
        self.gateway = 'Unknown'
        self.mac_address = 'Unknown'
        self.signal_strength = 0
        self.channel = 0
        

class Device:
    def __init__(self,ip_address):
        self.name = 'Unknown'
        self.ip_address = ip_address
        self.mac_address = 'Unknown'
        self.manufacturer = 'Unknown'

    def assumed_gateway_from(self,this_ip_address):
        ip_address__string_list = this_ip_address.split('.')
        subnet = ip_address__string_list[2]
        gateway = '192.168.{}.1'.format(subnet)
        return gateway


#---------------------------------------------

def print_and_save(source):
    print(source,end='')
    save_display_data_to_file(source)

def save_display_data_to_file(source): 
    realFile = open(r'/Users/Jamie/Desktop/feenyScanDisplayReport.txt','a')  
    realFile.write('{}'.format(source))
    realFile.close() 

def save_log_data_to_file(source): #if the file exists, it just adds to the end
    realFile = open(r"/Users/Jamie/Desktop/feenyScanLogReport.txt", 'a')  
    realFile.write('\n{}\n'.format(source))
    realFile.close() 

def get_your_device_name(): 
    this_process_call = subprocess.run(['networksetup', '-getcomputername' ], 
                             stdout=subprocess.PIPE, 
                             universal_newlines= True)
    standard_output_with_newline = this_process_call.stdout
    standard_output = standard_output_with_newline.rstrip()
    print_and_save('\nThis device\'s name is: {}'.format(standard_output)) #, end=''
    save_log_data_to_file(standard_output)
    return(standard_output)

def get_your_active_network_interface(): #what happens if there is 2?
    this_process_call = subprocess.Popen(['route','get','default'],shell=False, stdout=subprocess.PIPE)
    grep_output = subprocess.Popen(['grep','interface'],shell=False, stdin=this_process_call.stdout
                                                       ,stdout=subprocess.PIPE)
    awk_output = subprocess.Popen(['awk','{print $2}'],shell=False, stdin=grep_output.stdout
                                                       ,stdout=subprocess.PIPE
                                                       ,universal_newlines=True)
    standard_output_with_newline,_ = awk_output.communicate()
    standard_output = standard_output_with_newline.rstrip()
    save_log_data_to_file('\nThis device\'s active network interface: {}'.format(standard_output))
    return(standard_output)

def get_your_device_ip_from(active_network_interface):
    print_and_save("\nDevice:\n")
    this_process_call = subprocess.run(['ipconfig','getifaddr','{}'.format(active_network_interface)], 
                             stdout=subprocess.PIPE, 
                             universal_newlines=True)
    standard_output_with_newline = this_process_call.stdout
    standard_output = standard_output_with_newline.rstrip()
    save_log_data_to_file('device IP results: {}'.format(standard_output))
    print_and_save('\nThis device\'s IP Address is: {}'.format(standard_output)) 
    return(standard_output)

def get_your_device_mac_address_from(active_network_interface):
    this_process_call = subprocess.Popen(['ifconfig','{}'.format(active_network_interface)],shell=False, stdout=subprocess.PIPE)
    awk_output = subprocess.Popen(['awk','/ether/{print $2}'],shell=False, stdin=this_process_call.stdout
                                                       ,stdout=subprocess.PIPE
                                                       ,universal_newlines=True)
    standard_output_with_newline,_ = awk_output.communicate()
    standard_output = standard_output_with_newline.rstrip()
    save_log_data_to_file('device mac address results: {}'.format(standard_output))
    print_and_save('\nThis device\'s MAC Address is: {}'.format(standard_output)) 
    return(standard_output)

def get_connected_ap_info():
    print_and_save('\n\nWireless Connection:\n')
    this_process_call = subprocess.run(['airport', '-I' ], 
                             stdout=subprocess.PIPE, 
                             universal_newlines=True)
    standard_output_list = this_process_call.stdout
    save_log_data_to_file('get_connected_ap_info results: {}'.format(standard_output_list))
    return(standard_output_list)

def parse_data_with(term,source):
    #use regEx to get term matches
    search_result = re.search(r' {} (\S+.*)'.format(term),source)
    specified_result_list = search_result.group(1)
    save_log_data_to_file('parse_data_with results for term {} : {}'.format(term,specified_result_list))
    return specified_result_list

def get_connected_ap_ssid_from(your_connected_ap_info):
    connected_ap_ssid = parse_data_with(' SSID:',your_connected_ap_info)
    save_log_data_to_file('get_connected_ssid_name: {}'.format(connected_ap_ssid))
    print_and_save('\nThe SSID of the wireless network you are connected to: {}'.format(connected_ap_ssid))
    return connected_ap_ssid

def get_connected_ap_mac_address_from(your_connected_ap_info):
    connected_ap_mac_address = parse_data_with('BSSID:',your_connected_ap_info)
    save_log_data_to_file('get_connected_ap_mac_address: {}'.format(connected_ap_mac_address))
    #print_and_save('\nThe MAC address of the wireless network you are connected to: {}'.format(connectedNetworkSSIDName))
    return connected_ap_mac_address

def get_connected_ap_signal_strength_from(your_connected_ap_info):
    connected_ap_signal_strength = float(parse_data_with('agrCtlRSSI:',your_connected_ap_info))
    #print_and_save('\nThe signal strength of your connection is {} db.'.format(connected_ap_signal_strength))
    #print_and_save('\nThe signal strength of your connection is {} db. ({})'.format(connectedApSignalStrength,signalStrengthComment(connectedApSignalStrength)))
    save_log_data_to_file('get_connected_ap_signal_strength results: {}'.format(connected_ap_signal_strength))
    return connected_ap_signal_strength

def get_connected_ap_channel_from(your_connected_ap_info):
    connected_ap_channel = parse_data_with('channel:',your_connected_ap_info)
    channel_string_list = connected_ap_channel.split(',')
    connected_channel = int(channel_string_list[0])
    print_and_save('\nThe AP you are connected to is broadcasting on channel {}.'.format(connected_channel))
    save_log_data_to_file('get_connected_ap_channel results: {}'.format(connected_channel))
    return connected_channel 

def get_site_noise_level_from(your_connected_ap_info):
    site_noise_level = float(parse_data_with('agrCtlNoise:',your_connected_ap_info))
    #print_and_save('\nThe signal noise in your area is {} dB.  The closer to -120 the better.'.format(site_noise_level))
    save_log_data_to_file('get_site_noise_level results: {}'.format(site_noise_level))
    return site_noise_level

def get_site_quality_level_from(connected_ap_signal_strength,site_noise_level): #https://www.netspotapp.com/what-is-rssi-level.html
    site_quality_level = 2*(float(connected_ap_signal_strength) - float(site_noise_level))
    print_and_save('\nThe overall quality of your wireless connection is {}% (rssi: {}, noise: {}).'.format(int(site_quality_level), connected_ap_signal_strength, site_noise_level))
    save_log_data_to_file('get_site_quality_level results: {}'.format(site_quality_level))
    return site_quality_level

def get_other_wireless_networks_info():
    print_and_save('\n\nOther networks: ')
    print('(This will take a few seconds...)')
    this_process_call = subprocess.run(['airport','-s' ], 
                             stdout=subprocess.PIPE, 
                             universal_newlines= True)
    standard_output = this_process_call.stdout
    #this fails sometimes, how do I capture the error?
    save_log_data_to_file('get_other_wireless_networks_info results: {}'.format(standard_output))
    return standard_output

def get_mac_address_list_from(source): #expects a string
    mac_address_regex = r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"
    matches = re.finditer(mac_address_regex,source,re.MULTILINE)
    matches_list = [i.group(0) for i in matches]
    count = len(matches_list)
    save_log_data_to_file('{} get_mac_address_list results: {}'.format(count,matches_list))
    return matches_list

def get_formatted_network_list_from(other_wireless_networks_info):
    all_words_split = []       
    formatted_list = []                                           
    string_source = str(other_wireless_networks_info)                       
    #grab each line of the source string
    grab_each_line_regex = r'\n(.*)'                                       
    matches = re.finditer(grab_each_line_regex,string_source,re.MULTILINE)  
    matches_list = [i.group(1) for i in matches]                            
    #get number of lines from the list for loop
    number_of_lines = len(matches_list)
    for i in range(number_of_lines-1) : # -1 removes the last line of blank space
        white_space_removed = matches_list[i].strip()
        #split the line into words
        all_words_split = white_space_removed.split()
        formatted_list.append(all_words_split)
    count = len(formatted_list)
    save_log_data_to_file('{} get_formatted_network_list results: {}'.format(count,formatted_list))
    return formatted_list

def get_mac_address_index_from(formatted_line,mac_address):
    mac_address_index = formatted_line.index(mac_address)
    return mac_address_index

def get_ssid_list_from(formatted_network_list, mac_address_list):
    ssid_list = []
    number_of_lines = len(formatted_network_list)
    for i in range(number_of_lines):
        this_ssid = ''
        combined_ssid = ''
        formatted_line = formatted_network_list[i]
        mac_adress_index =get_mac_address_index_from(formatted_line,mac_address_list[i])
        #gather all words in front the MAC Address (this should be the network name, could be multiple words)
        for c in range(mac_adress_index):
            #combine all words with space to get network name (will there be an extra space at the end?)
            combined_ssid += formatted_line[c] + " " #how to remove trailing space?
            this_ssid = combined_ssid.rstrip()
        ssid_list.append(this_ssid)
    count = len(ssid_list)
    save_log_data_to_file('{} get_ssid_list results: {}'.format(count,ssid_list))
    return ssid_list

def get_rssi_list_from(formatted_network_list, mac_address_list):                                  
    rssi_list = []
    number_of_lines = len(formatted_network_list)
    for i in range(number_of_lines) : # -1 removes the last line of blank space
        formatted_line = formatted_network_list[i]
        mac_adress_index =get_mac_address_index_from(formatted_line, mac_address_list[i])
        rssi_index_number = mac_adress_index + 1
        this_network_rssi = formatted_line[rssi_index_number]
        rssi_list.append(this_network_rssi)
    count = len(rssi_list)
    save_log_data_to_file('{} get_rssi_list results: {}'.format(count,rssi_list))
    return rssi_list

def get_channel_list_from(formatted_network_list, mac_address_list):
    channel_list = []
    number_of_lines = len(formatted_network_list)
    for i in range(number_of_lines) :
        formatted_line = formatted_network_list[i]
        mac_adress_index =get_mac_address_index_from(formatted_line, mac_address_list[i])
        channel_index = mac_adress_index + 2
        both_channels_string = formatted_line[channel_index]
        both_channels_list = both_channels_string.split(',')
        single_channel_number = int(both_channels_list[0])
        channel_list.append(single_channel_number)
    count = len(channel_list)
    save_log_data_to_file('{} get_channel_list results: {}'.format(count, channel_list))
    return channel_list

def get_other_network_devices_info_from(network_gateway):
    gateway_to_scan = '{}/24'.format(network_gateway)
    print_and_save('Other devices using gateway {}: \n'.format(network_gateway))
    # print('This will take a few minutes...')
    this_process_call = subprocess.run(['sudo', 'nmap', '-sn', '{}'.format(gateway_to_scan)],
    #this_process_call = subprocess.run(['sudo', 'nmap', '-PA', '{}'.format(scanIpAddress)],  
    #sudo nmap -PA 192.168.1.0/24 - all ports, slow
    #sudo nmap -sn 192.168.1.20/24 -sP > file1.txt - outputs to file
    #sudo nmap -sn 192.168.20.1/24 - no port scan, IP, MAC and Vendor 
                         stdout=subprocess.PIPE, 
                         universal_newlines=True)
    save_log_data_to_file(this_process_call.stdout)
    return this_process_call.stdout

def get_device_ip_address_list_from(other_network_devices_info):
    ip_address_regex = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    extracted_ip_list = re.findall(ip_address_regex,other_network_devices_info)
    #remove duplicates
    duplicates_removed_from_list = list(dict.fromkeys(extracted_ip_list))
    #remove the last device which is the host computer
    device_ip_address_list = duplicates_removed_from_list[:-1]
    count = len(device_ip_address_list)
    save_log_data_to_file('{} get_device_ip_address_list_from results: {}'.format(count,device_ip_address_list))
    return device_ip_address_list

# def get_device_names_from(other_network_devices_info):
#     return device_names_list

def get_device_mac_address_list_from(other_network_devices_info):
    device_mac_address_list = get_mac_address_list_from(other_network_devices_info)
    count = len(device_mac_address_list)
    save_log_data_to_file('{} get_device_mac_address_list_from results: {}'.format(count,device_ip_address_list))
    return device_mac_address_list

def get_device_manufacturer_list_from(other_network_devices_info):
    device_manufacturer_list = []
    device_mac_address_list = get_device_mac_address_list_from(other_network_devices_info)
    #for each mac address, use it as a new regEx term to get the words after it to the end of the line
    for i in device_mac_address_list :
        manufacturer_regex = r'{} (\S+.*)'.format(i)
        manufacturer_result = re.search(manufacturer_regex,other_network_devices_info)
        manufacturer_specified_result = manufacturer_result.group(1)
        manufacturer_without_parentheses = re.sub('[()]','',manufacturer_specified_result)
        device_manufacturer_list.append(manufacturer_without_parentheses)
    count = len(device_manufacturer_list)
    save_log_data_to_file('{} get_device_manufacturer_list_from results: {}'.format(count,device_manufacturer_list))
    return device_manufacturer_list

def generate_a_display_for(all_items):
    #get headers
    below_titles = '--------------'
    first_line = all_items[0]
    items_as_dictionary = vars(first_line)
    all_keys = (items_as_dictionary.keys())
    #print titles
    print_and_save('\n')
    for key in all_keys:
        key_with_spaces = key.replace('_',' ')
        key_capitalized = key_with_spaces.title()
        print_and_save('{: <30}'.format(key_capitalized))
    print_and_save('\n')

    for key in all_keys:
        print_and_save('{: <30}'.format(below_titles))
    print_and_save('\n')

    for i in range(len(all_items)):
        these_items_as_dictionary = vars(all_items[i])
        all_values = (these_items_as_dictionary.values())
        for value in all_values:
            print_and_save('{: <30}'.format(value))
        print_and_save('\n')
    print_and_save('\n')

def get_speed_test_results():
    try:
        results = feenySpeedTest.run_speed_test()
        for key, value in results.items() :
            print_and_save('\n{}'.format(key))
            print_and_save(value)
    except LookupError as e:
        print_and_save('Cannot get speed results')
        print_and_save(e)
        exit(1)

def start_speed_test_thread():
    speed_test_thread = threading.Thread(target = get_speed_test_results, args = ())
    print('\nStarting speed test in the background...\n ')
    speed_test_thread.start()

#-----------------------------------------------------BEGIN-------------------------------

all_devices = []
all_networks = []

start_speed_test_thread() 

#-------------YOUR DEVICE OBJECT-------------------

active_network_interface = get_your_active_network_interface()

ip_address = get_your_device_ip_from(active_network_interface)

your_device = Device(ip_address)
your_device.name = get_your_device_name()
your_device.mac_address = get_your_device_mac_address_from(active_network_interface)
#your_device.manufacturer = get_your_device_manufacturer()
all_devices.append(your_device)

#--------------------------------------------------

your_connected_ap_info = get_connected_ap_info()
connected_ssid_name = get_connected_ap_ssid_from(your_connected_ap_info)

#-------------YOUR NETWORK OBJECT-------------------

your_network = Wireless_Network(connected_ssid_name)
your_network.mac_address = get_connected_ap_mac_address_from(your_connected_ap_info)
your_network.gateway = your_device.assumed_gateway_from(ip_address)
your_network.signal_strength = get_connected_ap_signal_strength_from(your_connected_ap_info)
your_network.channel = get_connected_ap_channel_from(your_connected_ap_info)
all_networks.append(your_network)

your_network_noise_level = get_site_noise_level_from(your_connected_ap_info)
your_network_quality_level = get_site_quality_level_from(your_network.signal_strength, your_network_noise_level)

#----------OTHER NETWORK ATTRIBUTES LIST-------------

other_wireless_networks_info = get_other_wireless_networks_info()
formatted_network_list = get_formatted_network_list_from(other_wireless_networks_info)
 
network_mac_address_list =get_mac_address_list_from(other_wireless_networks_info)
network_ssid_list = get_ssid_list_from(formatted_network_list,network_mac_address_list)
network_signal_strength_list = get_rssi_list_from(formatted_network_list,network_mac_address_list)
network_channel_list = get_channel_list_from(formatted_network_list,network_mac_address_list)

#----------ADD NETWORK ATTRIBUTES TO OBJECT-----------

for i in range(len(network_ssid_list)):
    this_network = Wireless_Network(network_ssid_list[i])
    this_network.mac_address = network_mac_address_list[i]
    this_network.channel = network_channel_list[i]
    this_network.signal_strength = network_signal_strength_list[i]
    if this_network.mac_address != your_network.mac_address: #removes the duplicate network from the list
        all_networks.append(this_network)

generate_a_display_for(all_networks)

#----------OTHER DEVICE ATTRIBUTES LIST---------------

other_network_devices_info = get_other_network_devices_info_from(your_network.gateway)
device_ip_address_list = get_device_ip_address_list_from(other_network_devices_info)
# device_name_list = get_device_names_from(other_network_devices_info)
device_mac_address_list = get_device_mac_address_list_from(other_network_devices_info,)
device_manufacturer_list = get_device_manufacturer_list_from(other_network_devices_info)

#----------ADD DEVICE ATTRIBUTES TO OBJECT-----------

for i in range(len(device_ip_address_list)):
    this_device = Device(device_ip_address_list[i])
    # this_device.name = device_name_list[i]
    this_device.mac_address = device_mac_address_list[i]
    this_device.manufacturer = device_manufacturer_list[i]
    all_devices.append(this_device)

generate_a_display_for(all_devices)
print('\nWaiting for speed test results...')

# TODO: number_of_competing_channels = number_of_competing_channels_from(connected_channel,channel_list)
# TODO: get the device names
# TODO:
# TODO:

#Often it’s the code that calls the function, not the function itself, that knows how to handle an exception. So you 
#will commonly see a raise statement inside a function and the try and except statements in the code calling the function.











