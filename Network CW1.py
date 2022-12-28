import time
from xml.sax import ContentHandler
import paramiko
import netmiko
import scapy.all as scapy

if __name__ == "__main__":
    # Establish SSH connections to all 7 routers
    router_ips = ["192.168.169.1", "192.168.169.2", "192.168.169.3", "192.168.169.4", "192.168.169.5", "192.168.169.6","192.168.169.10"]
    clients = []
    switch = "192.168.169.10"
    for ip in router_ips:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password)
    return client
        
# Function to be called for every packet captured
def packet_callback(packet):
    # Check if the packet is an unknown type of traffic
    if packet.haslayer(Unknown):
        # Connect to the switch using paramiko
        ssh = paramiko.SSHClient()
        ssh.connect(switch, username="username", password="password")
        # Issue a command to change the switch configuration
        stdin, stdout, stderr = ssh.exec_command("configure terminal")
        stdin.write("interface ethernet 1/1\n")
        stdin.write("switchport mode access\n")
        stdin.write("exit\n")
        stdin.flush()
        # Close the SSH connection
        ssh.close()
# Start sniffing the traffic on the network
sniff(prn=packet_callback)


# Function to change the designated router on a daily basis
def change_dr(client):
    net_connect = ContentHandler(client)
    # Determine the current DR
    output = net_connect.send_command('show ip ospf interface')
    lines = output.split('\n')
    for line in lines:
        if 'Designated Router (ID)' in line:
            current_dr = line.split()[-1]
            break
    # Change the OSPF priority for the current DR
    net_connect.send_config_set(['ip ospf priority 0 interface {}'.format(current_dr)])
    # Restart the OSPF process
    net_connect.send_command('clear ip ospf process')
    # Disconnect from the device
    net_connect.disconnect()
time.sleep(86400)  # Sleep for 86400 seconds (24 hours)

# Function to detect unknown packets and change the operating VLAN
def detect_packet(vlan):
    def custom_action(packet):
        Macaddrs = ["0050.0F79.E002","0001.972C.9702","0010.11D4.0502","00D0.974D.D302","0006.2A48.9602","0009.7CC9.4802"]
        if packet[scapy.Ether].src != Macaddrs:  # Check if source MAC is trusted
            net_connect = netmiko.Netmiko(client)
            net_connect.send_command("configure terminal")
            net_connect.send_command("interface g0/0/1")
            net_connect.send_command("spanning-tree vlan 70 root primary")
            net_connect.send_command("spanning-tree vlan 88 secondary")
            net_connect.exit_config_mode()
            net_connect.send_command("write memory")
            net_connect.disconnect()
            packet.show()  # Forward a copy of the packet to VLAN 88
    scapy.sniff(prn=custom_action)

# Function to extract information from the routing packet and verify OSPF domain
def verify_ospf(packet, trusted_domains):
    ospf_domain = packet[scapy.OSPF]."0"  # Extract OSPF domain
    if ospf_domain in trusted_domains:  # Check if OSPF domain is trusted
        return True
    return False






