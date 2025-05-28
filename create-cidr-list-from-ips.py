import requests
import ipaddress

# Step 1: Retrieve the IP list
url = 'https://raw.githubusercontent.com/az0/vpn_ip/refs/heads/main/data/output/ip.txt'
response = requests.get(url)
data = response.text

# Step 2: Parse and clean the data
ips = []
for line in data.splitlines():
    if line.strip() and not line.startswith('#'):
        ip = line.split()[0]
        try:
            # Validate IP address
            ipaddress.ip_address(ip)
            ips.append(ip)
        except ValueError:
            continue

# Step 3: Convert IPs to CIDR blocks
ip_objects = sorted(ipaddress.ip_address(ip) for ip in ips)
cidr_blocks = list(ipaddress.collapse_addresses(ip_objects))

# Step 4: Output the CIDR blocks
for cidr in cidr_blocks:
    print(cidr)
