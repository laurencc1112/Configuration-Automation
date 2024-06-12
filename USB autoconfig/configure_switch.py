import os
import serial
import time
import pandas as pd
import ipaddress


def prompt_user():
    bldg_acro = input("Enter the buildng acronym: ")
    enable_password = input("Enter the enable password: ")
    admin_password = input("Enter the admin password: ")
    loopback_ip = input("Enter the loopback IP address: ")
    ospf_num = input("Enter the OSPF number: ")
    tacacs_key = input("Enter the TACACS key: ")
    port = input("Enter the serial port (e.g., /dev/cu.usbserial-XXXX): ")
    model = input("Select the switch model (1. 9500, 2. 9300): ")
    stacked = input("Is this a stacked switch? (yes/no): ")
    uplink_description = input("Enter the uplink description: ")
    first_ptp_address = input("Enter the first point-to-point address (enter the EVEN NUMERED address): ")
    second_ptp_address = input("Enter the second point-to-point address (enter the EVEN NUMERED address): ")
    ospf_message_key = input("Enter the OSPF message key: ")
    hostname = f"{bldg_acro}-1"
    return (bldg_acro, hostname, enable_password, admin_password, loopback_ip, ospf_num, tacacs_key, port,
            model, stacked, uplink_description, first_ptp_address, second_ptp_address, ospf_message_key)


def find_csv_file(bldg_acro):
    downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")
    csv_filename = f"{bldg_acro}-networks.csv"
    csv_filepath = os.path.join(downloads_folder, csv_filename)
    if os.path.exists(csv_filepath):
        return csv_filepath
    else:
        raise FileNotFoundError(f"CSV file '{csv_filename}' not found in Downloads folder.")

def read_csv_file(filepath):
    return pd.read_csv(filepath)

def generate_wildcard_mask(cidr):
    prefix_length = int(cidr.split('/')[-1])
    wildcard_mask = cidr_to_wildcard(cidr)
    return wildcard_mask

def generate_subnet_mask(cidr):
    subnet_mask = cidr_to_subnet_mask(cidr)
    return subnet_mask

def cidr_to_wildcard(subnet_mask):
    prefix_length = int(subnet_mask.split('/')[-1])
    subnet_mask_binary = '1' * prefix_length + '0' * (32 - prefix_length)
    wildcard_mask_binary = ''.join(['1' if bit == '0' else '0' for bit in subnet_mask_binary])
    octets = [wildcard_mask_binary[i:i+8] for i in range(0, 32, 8)]
    wildcard_octets = [str(int(octet, 2)) for octet in octets]
    wildcard_mask = '.'.join(wildcard_octets)
    return wildcard_mask

def cidr_to_subnet_mask(cidr_notation):
    ip_address, prefix_length = cidr_notation.split('/')
    prefix_length = int(prefix_length)
    subnet_mask_binary = '1' * prefix_length + '0' * (32 - prefix_length)
    octets = [subnet_mask_binary[i:i+8] for i in range(0, 32, 8)]
    subnet_octets = [str(int(octet, 2)) for octet in octets]
    subnet_mask = '.'.join(subnet_octets)
    return subnet_mask

def generate_interface_config(model, stacked, uplink_description, first_ptp_address, second_ptp_address, ospf_message_key, ospf_num):
    if model == "1":  # 9500
        if stacked.lower() == "yes":
            return f"""
            Interface twe1/0/23
            Desc {uplink_description}
            No switchport
            Ip address {first_ptp_address}
            Ip ospf message-digest-key 1 md5 7 {ospf_message_key}
            Ip ospf network point-to-point
            mtu 1500
            ip pim sparse-mode
            No shut
            Exit

            Int twe2/0/23
            Desc {uplink_description}
            No switchport
            Ip address {second_ptp_address}
            Ip ospf message-digest-key 1 md5 7 {ospf_message_key}
            Ip ospf network point-to-point
            mtu 1500
            ip pim sparse-mode
            no shut
            Exit

            router ospf {ospf_num}
            no passive-interface twe1/0/23
            no passive-interface twe2/0/23
            network {first_ptp_address} 0.0.0.1 area {ospf_num}
            network {second_ptp_address} 0.0.0.1 area {ospf_num}
            exit
            """
        else:
            return f"""
            Interface twe1/0/23
            Desc {uplink_description}
            No switchport
            Ip address {first_ptp_address}
            Ip ospf message-digest-key 1 md5 7 {ospf_message_key}
            Ip ospf network point-to-point
            No shut
            mtu 1500
            ip pim sparse-mode
            Exit

            Int twe1/0/24
            Desc {uplink_description}
            No switchport
            Ip address {second_ptp_address}
            Ip ospf message-digest-key 1 md5 7 {ospf_message_key}
            Ip ospf network point-to-point
            mtu 1500
            ip pim sparse-mode
            no shut
            Exit

            router ospf {ospf_num}
            no passive-interface twe1/0/23
            no passive-interface twe1/0/24
            network {first_ptp_address} 0.0.0.1 area {ospf_num}
            network {second_ptp_address} 0.0.0.1 area {ospf_num}
            exit

            """
    elif model == "2":  # 9300
        if stacked.lower() == "yes":
            return f"""
            Interface twe1/1/1
            Desc {uplink_description}
            No switchport
            Ip address {first_ptp_address}
            Ip ospf message-digest-key 1 md5 7 {ospf_message_key}
            Ip ospf network point-to-point
            mtu 1500
            ip pim sparse-mode
            no shut
            Exit

            Int twe2/1/1
            Desc {uplink_description}
            No switchport
            Ip address {second_ptp_address}
            Ip ospf message-digest-key 1 md5 7 {ospf_message_key}
            Ip ospf network point-to-point
            mtu 1500
            ip pim sparse-mode
            no shut
            Exit

            router ospf {ospf_num}
            no passive interface twe1/1/1
            no passive interface twe2/1/1
            network {first_ptp_address} 0.0.0.1 area {ospf_num}
            network {second_ptp_address} 0.0.0.1 area {ospf_num}
            exit

            """
        else:
            return f"""
            Interface twe1/1/1
            Desc {uplink_description}
            No switchport
            Ip address {first_ptp_address}
            Ip ospf message-digest-key 1 md5 7 {ospf_message_key}
            Ip ospf network point-to-point
            mtu 1500
            ip pim sparse-mode
            no shut
            Exit

            Int twe1/1/2
            Desc {uplink_description}
            No switchport
            Ip address {second_ptp_address}
            Ip ospf message-digest-key 1 md5 7 {ospf_message_key}
            Ip ospf network point-to-point
            mtu 1500
            ip pim sparse-mode
            no shut
            Exit

            router ospf {ospf_num}
            no passive interface twe1/1/1
            no passive interface twe1/1/2
            network {first_ptp_address} 0.0.0.1 area {ospf_num}
            network {second_ptp_address} 0.0.0.1 area {ospf_num}
            exit
            
            """
    else:
        return ""

def generate_configuration(hostname, enable_password, admin_password, loopback_ip, ospf_num, tacacs_key, port, model, stacked, uplink_description, first_ptp_address, second_ptp_address, ospf_message_key, vlan_data):
    config = f"""
    hostname {hostname}
    
    no logging console    
    ip routing
    logging buffered 1024000
    no logging monitor
    no ip domain lookup
    ip ssh logging events
    ip ssh version 2

    lldp run
    
    no service pad
    service timestamps debug datetime msec localtime
    service timestamps log datetime localtime show-timezone
    service password-encryption
    service compress-config
    service sequence-numbers
    service nagle
    service counters max age 10

    enable secret {enable_password}
    username admin privilege 15 secret {admin_password}

    ip domain name net.tamu.edu
    ip multicast-routing
    vtp mode transparent
    clock timezone CST -6
    clock summer-time CDT recurring 2 Sun Mar 2:00 1 Sun Nov 2:00
    crypto key generate rsa general-keys modulus 1024

    no ip http server
    no ip http authentication local
    no ip http secure-server

    ip pim rp-address 128.194.255.164
    ip access-list extended acl-copp-match-igmp
    deny pim any host 224.0.0.13
    permit pim any any
    ip tacacs source-interface Loopback0

    logging facility syslog
    logging source-interface Loopback0
    logging host 128.194.12.52 transport udp port 1514

    access-list 3 permit 128.194.147.13
    access-list 3 permit 128.194.177.0 0.0.0.255
    access-list 177 permit ip 128.194.177.0 0.0.0.255 any log
    access-list 177 permit ip 128.194.208.128 0.0.0.63 any log
    access-list 177 permit ip host 128.194.147.10 any log
    access-list 177 permit ip host 128.194.147.30 any log
    access-list 177 permit ip host 128.194.147.54 any log
    access-list 177 permit ip host 128.194.147.120 any log
    access-list 177 deny ip any any log

    snmp-server community homernet RO 0
    snmp-server packetsize 8192
    snmp-server enable traps snmp authentication warmstart
    snmp-server enable traps entity
    snmp-server enable traps vtp
    snmp-server enable traps envmon fan shutdown supply temperature status
    snmp-server enable traps config
    snmp-server enable traps ipmulticast
    snmp-server enable traps ipsla
    snmp-server enable traps syslog

    interface Loopback0
    description router-id, OSPF {ospf_num}
    ip address {loopback_ip} 255.255.255.255
    ip pim sparse-mode

    router ospf {ospf_num}
    network {loopback_ip} 0.0.0.0 area {ospf_num}

    aaa new-model
    aaa authentication login default group tacacs+ local
    aaa authentication enable default group tacacs+ enable
    aaa authorization config-commands
    aaa authorization exec default group tacacs+ local if-authenticated
    aaa authorization commands 0 default group tacacs+ local
    aaa authorization commands 1 default group tacacs+ if-authenticated
    aaa authorization commands 15 default group tacacs+ local if-authenticated
    aaa accounting exec default start-stop group tacacs+
    aaa accounting commands 0 default start-stop group tacacs+
    aaa accounting commands 1 default start-stop group tacacs+
    aaa accounting commands 15 default start-stop group tacacs+
    aaa accounting connection default start-stop group tacacs+
    aaa accounting system default start-stop group tacacs+

    Tacacs-server directed-request
    Ip tacacs source-interface Loopback0
    Tacacs server ISE_igloo-wcdc
    Address ipv4 128.194.177.200
    Key {tacacs_key}
    Tacacs server ISE_igloo-csce
    Address ipv4 128.194.177.100
    Key {tacacs_key}
    timeout 3

    router ospf {ospf_num}
    router-id {loopback_ip}
    auto-cost reference-bandwidth 10000
    area {ospf_num} authentication message-digest
    passive-interface default

    errdisable recovery cause storm-control
    errdisable recovery cause udld
    errdisable recovery cause bpduguard
    errdisable recovery cause security-violation
    errdisable recovery cause channel-misconfig 
    errdisable recovery cause pagp-flap
    errdisable recovery cause dtp-flap
    errdisable recovery cause link-flap
    errdisable recovery cause gbic-invalid
    errdisable recovery cause psecure-violation
    errdisable recovery cause dhcp-rate-limit
    errdisable recovery cause loopback
    errdisable recovery interval 60
    diagnostic bootup level minimal
    identity policy webauth-global-inactive
    inactivity-timer 3600
    spanning-tree mode rapid-pvst
    spanning-tree portfast bpduguard default
    no spanning-tree optimize bpdu transmission
    spanning-tree extend system-id
    Redundancy 
    mode sso


    alias interface add vlan switchport trunk allowed vlan add
    alias interface remove vlan switchport trunk allowed vlan remove
    alias exec ct config t
    alias exec ir sh ip route
    alias exec ib sh ip int brief
    alias exec sb sh run | begin
    alias exec sbb sh run | begin router bgp
    alias exec si sh run | inc
    alias exec sr sh run
    alias exec ss sh interface status
    alias exec sibs sh ip bgp summary
    alias exec sib4s show ip bgp vpnv4 all sum
    alias exec sib4 show ip bgp vpnv4 all
    alias exec sib6 show ip bgp vpnv6 unicast all
    alias exec sib6s show ip bgp vpnv6 unicast all sum
    alias exec smi sh mpls interfaces
    alias exec smlv sh mpls l2transport vc

     banner login ^C

    ########################################################################################
    #                                                                                      #
    # This computer system and the data herein are available only for authorized           #
    # purposes by authorized users. Use for any other purpose is prohibited and may        #
    # result in disciplinary actions or criminal prosecution against the user. Usage may   #
    # be subject to security testing and monitoring. There is no expectation of privacy    #
    # on this system except as otherwise provided by applicable privacy laws. Refer to     #
    # University SAP 29.01.03.M0.02 Acceptable Use for more information.                   #
    #                                                                                      #
    ########################################################################################

    ^C

    line con 0
     exec-timeout 20 0
     timeout login response 60
     logging synchronous
     stopbits 1
    line aux 0
    line vty 0 4
     access-class 177 in
     exec-timeout 20 0
     timeout login response 60
     logging synchronous
     transport input ssh
     transport output ssh
    line vty 5 15
     access-class 177 in
     exec-timeout 20 0
     timeout login response 60
     logging synchronous
     transport input ssh
     transport output ssh
    
    ntp server 128.194.211.237 prefer
    ntp server 165.91.16.135

    
    """



    for index, row in vlan_data.iterrows():
        vlan_num = row['VLAN']
        description = row['Description']
        network = row['Network']
        gateway = row['Gateway']
        size = row['New Network Size']
        subnet_mask = generate_subnet_mask(size)
        wildcard_mask = generate_wildcard_mask(size)
        config += f"""
        vlan {vlan_num}
        name {description}
        !
        interface Vlan{vlan_num}
        description {description}
        ip address {gateway} {subnet_mask}
        ip helper-address 165.91.16.135
        ip helper-address 128.194.211.237
        shutdown
        exit
        !
        """
        config += f"""
        router ospf {ospf_num}
        network {network} {wildcard_mask} area {ospf_num}
        exit
    """

    # Add interface configurations based on model and stacked
    config += generate_interface_config(model, stacked, uplink_description, first_ptp_address, second_ptp_address, ospf_message_key, ospf_num)

    return config




def send_configuration_to_switch(config, port=None, baudrate=9600):
    try:
        # Open serial connection
        # Print the generated configuration and ask for approval
        print("\nGenerated Configuration:\n")
        print(config)
        
        approval = input("\nDo you approve this configuration? (yes/no): ")
        if approval.lower() != 'yes':
            print("Configuration upload aborted.")
        return
    
        print("\nProvisioning switch...")
        with serial.Serial(port, baudrate, timeout=1) as ser:
            print("Connecting to the switch...")
            ser.write(b'\r\n')  # Wake up the console
            time.sleep(1)
            ser.write(b'enable\r\n')
            time.sleep(1)
            ser.write(b'configure terminal\r\n')
            time.sleep(1)
            for line in config.split('\n'):
                ser.write(line.encode('utf-8') + b'\r\n')
                time.sleep(0.1)  # Adjust this if needed to avoid overruns
            ser.write(b'end\r\n')
            ser.write(b'write memory\r\n')
            print("Configuration applied successfully.")
    except serial.SerialException as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    bldg_acro, hostname, enable_password, admin_password, loopback_ip, ospf_num, tacacs_key, port, model, stacked, uplink_description, first_ptp_address, second_ptp_address, ospf_message_key  = prompt_user()
    try:
        csv_filepath = find_csv_file(bldg_acro)
        vlan_data = read_csv_file(csv_filepath)
        config = generate_configuration(hostname, enable_password, admin_password, loopback_ip, ospf_num, tacacs_key, port, model, stacked, first_ptp_address, second_ptp_address, ospf_message_key, vlan_data)
        send_configuration_to_switch(config, port=port)
    except FileNotFoundError as e:
        print(f"Error: {e}")
