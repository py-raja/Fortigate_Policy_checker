import argparse
import socket
from netmiko import ConnectHandler
import ipaddress
import re

def validate_ip(ip_address):
    try:
        ipaddress.IPv4Address(ip_address)
    except ValueError:
        print(f"Invalid IP address: {ip_address}. Please enter a valid IP address.")
        exit()

def resolve_domain_to_ip(destination):
    try:
        ipaddress.IPv4Address(destination)
        return destination
    except ValueError:
        try:
            resolved_ip = socket.gethostbyname(destination)
            print(f"Resolved domain '{destination}' to IP: {resolved_ip}")
            return resolved_ip
        except socket.gaierror:
            print(f"Error: Unable to resolve domain name '{destination}'.")
            exit()

def get_policy_action(policy_id, net_connect):
    command = f"show full firewall policy {policy_id}"
    action_output = net_connect.send_command(command)
    policy_action_match = re.search(r"set action (.*?)$", action_output, flags=re.MULTILINE)
    return policy_action_match.group(1).strip() if policy_action_match else None

def get_firewall_policies(device_ip, device_username, device_password, source_ip, source_port, destination_ip, destination_port, protocol):
    device_type = 'fortinet'
    device = {
        'device_type': device_type,
        'ip': device_ip,
        'username': device_username,
        'password': device_password
    }
    net_connect = ConnectHandler(**device)

    try:
        command = f"get router info routing-table details {source_ip}"
        route_output = net_connect.send_command(command)
        line_with_star = [line for line in route_output.splitlines() if "*" in line][0]
        source_interface = re.search(r"via (\w+)", line_with_star).group(1)
    except IndexError:
        print(f"Error: Could not determine source interface for {source_ip}.")
        net_connect.disconnect()
        return

    output = f"diag firewall iprope lookup {source_ip} {source_port} {destination_ip} {destination_port} {protocol} {source_interface}"
    policy_raw = net_connect.send_command(output)
    match = re.search(r"matches policy id: (\d+)", policy_raw)

    if match:
        policy_id = match.group(1)
        if policy_id == "0":
            print(f"Source: {source_ip}, Destination: {destination_ip}, Port: {destination_port} => No specific policy; Implicit Deny.")
        else:
            action = get_policy_action(policy_id, net_connect)
            print(f"Source: {source_ip}, Destination: {destination_ip}, Port: {destination_port} => Policy ID: {policy_id}, Action: {action}")
    else:
        print(f"Source: {source_ip}, Destination: {destination_ip}, Port: {destination_port} => Policy ID not found.")

    net_connect.disconnect()

def read_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        exit()

def read_credentials(file_path):
    try:
        with open(file_path, 'r') as file:
            device_username = file.readline().strip()
            device_password = file.readline().strip()
        return device_username, device_password
    except FileNotFoundError:
        print(f"Error: Credentials file '{file_path}' not found.")
        exit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firewall Policy Checker")
    parser.add_argument("-S", "--source_file", help="Path to the source IP list file")
    parser.add_argument("-D", "--destination_file", help="Path to the destination IP list file")
    parser.add_argument("--dport_file", help="Path to the destination port list file")
    parser.add_argument("--credentials", default="credentials.txt", help="Path to the credentials file (default: credentials.txt)")
    parser.add_argument("--firewall_ip", help="IP address of the firewall")
    parser.add_argument("--source_port", default="12345", help="Source port (default: 12345)")
    parser.add_argument("--protocol", default="tcp", choices=["tcp", "udp"], help="Protocol (default: tcp)")

    args = parser.parse_args()

    # Read credentials
    device_username, device_password = read_credentials(args.credentials)

    # If files are provided, read them; otherwise, prompt for manual input
    if args.source_file:
        sources = read_file(args.source_file)
    else:
        sources = [input("Enter source IP address: ")] or "0.0.0.0"
        validate_ip(sources[0])
    if not args.protocol:
        protocol = input("Enter the protocol TCP/UDP: ").lower() or "tcp"


    if args.destination_file:
        destinations = read_file(args.destination_file)
        if destinations:
            destinations = [resolve_domain_to_ip(dest) for dest in destinations]
    else:
        destinations = [input("Enter destination (IP address or domain name): ")] or "0.0.0.0"
        destinations = [resolve_domain_to_ip(dest) for dest in destinations]

    if args.dport_file:
        ports = read_file(args.dport_file)
    else:
        ports = [input("Enter destination port: ")]

    if not args.firewall_ip:
        firewall_ip = input("Enter Firewall IP address: ")
        validate_ip(firewall_ip)
    else:
        firewall_ip = args.firewall_ip

    # Loop through all combinations of sources, destinations, and ports
    for source in sources:
        validate_ip(source)
        for destination in destinations:
            validate_ip(destination)
            for port in ports:
                get_firewall_policies(
                    device_ip=firewall_ip,
                    device_username=device_username,
                    device_password=device_password,
                    source_ip=source,
                    source_port=args.source_port,
                    destination_ip=destination,
                    destination_port=port,
                    protocol=args.protocol
                )
