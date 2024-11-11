# FortiGate Firewall Policy Lookup Script:
This Python script retrieves firewall policy information for a given traffic flow on a FortiGate device using Netmiko. It connects to the device, determines the outgoing interface for the source IP, and then uses the diag firewall iprope lookup command to identify the matching policy ID.

## Features:

- Connects to a FortiGate firewall using Netmiko.
- Validates source and destination IP addresses.
- Looks up the matching policy ID for a given traffic flow (source IP, destination IP, protocol, ports).
- Retrieves the policy action for the identified policy ID.
## Requirements:

- Python 3
- Netmiko library (pip install netmiko)
- ipaddress library (pip install ipaddress)
## Usage:

- Clone or download the script.
- Install the required libraries (pip install netmiko ipaddress).
- Create a file named credentials.txt in the same directory containing your FortiGate device username and password on separate lines.
- Run the script from the command line: python rule2.py
- Enter the requested information:
- Source IP address (optional, defaults to 0.0.0.0)
- Destination IP address (optional, defaults to 0.0.0.0)
- Source port (optional, defaults to "12345")
- Destination port (optional)
- Protocol (TCP/UDP, defaults to "tcp")
- Firewall IP address
The script will display the matching policy ID (or "Implicit Deny" if no policy matches) and the policy action.
### Note:

- This script retrieves basic policy information. Additional configuration is required to retrieve the full policy details.
- Modify the script as needed for your specific use case.
- Consider error handling for missing credentials files or other potential issues.
Example Output:
```
Enter source IP address: 10.0.0.1
Enter destination IP address: 8.8.8.8
Enter destination port: 53
Enter the protocol TCP/UDP: udp
Enter Firewall IP address: 192.168.1.1

Policy ID: 10
It matches the policy ID: 10 with the action accept
```
This script is a helpful tool for network administrators to quickly identify firewall policies for specific traffic flows on their FortiGate devices.
