from netmiko import ConnectHandler
import ipaddress
import re

def validate_ip(ip_address):
    """
    Validates an IP address and throws an error if invalid.

    Args:
        ip_address (str): The IP address to validate.
    """
    try:
        ipaddress.IPv4Address(ip_address)
    except ValueError:
        print(f"Invalid IP address: {ip_address}. Please enter a valid IP address.")
        exit()  # Exit the program on invalid IP

def get_policy_action(policy_id, net_connect):
    command = f"show full firewall policy {policy_id}"
    action_output = net_connect.send_command(command)
    policy_action_match = re.search(r"set action (.*?)$", action_output, flags=re.MULTILINE)
    return policy_action_match.group(1).strip() if policy_action_match else None

def get_firewall_policies(device_ip, device_username, device_password, source_ip, source_port, destination_ip, destination_port, protocol):

    device_type = 'fortinet'

    # Connect to the FortiGate device
    device = {
        'device_type': device_type,
        'ip': device_ip,
        'username': device_username,
        'password': device_password
    }

    net_connect = ConnectHandler(**device)

    # Execute the command
    command = f"get router info routing-table details {source_ip}"
    route_output = net_connect.send_command(command)
    line_with_star = [line for line in route_output.splitlines() if "*" in line][0]
    source_interface = re.search(r"via (\w+)", line_with_star).group(1)

    output = f"diag firewall iprope lookup {source_ip} {source_port} {destination_ip} {destination_port} {protocol} {source_interface}"
    #print(f"Using lookup command {output}")  #Debugging
    policy_raw = net_connect.send_command(output)
    match = re.search(r"matches policy id: (\d+)", policy_raw)
    
    if match:
        policy_id = match.group(1)
        if policy_id == "0":
            print("There is no specific policy; it is matching to Implicit Deny.")
        else:
            print(f"Policy ID: {policy_id}")
            action = get_policy_action(policy_id, net_connect)  # Call the updated function
            print(f"It matches the policy ID: {policy_id} with the action {action}")
    else:
        print("Policy ID not found.")

    # Close the connection
    net_connect.disconnect()

# Replace with your FortiGate device credentials
source_ip = input("Enter source IP address: ") or "0.0.0.0"
validate_ip(source_ip)
destination_ip = input("Enter destination IP address: ") or "0.0.0.0"
validate_ip(destination_ip)
source_port = "12345"  # Optional, can be commented out
destination_port = input("Enter destination port: ")  # Optional, can be commented out
protocol = input("Enter the protocol TCP/UDP: ") or "tcp"
device_ip = input("Enter Firewall IP address: ")

def read_credentials(file_path):
    with open(file_path, 'r') as file:
        device_username = file.readline().strip()
        device_password = file.readline().strip()
    return device_username, device_password

credentials_file = "credentials.txt"

# Read username and password from the credentials file
device_username, device_password = read_credentials(credentials_file)

get_firewall_policies(device_ip, device_username, device_password, source_ip, source_port, destination_ip, destination_port, protocol)
