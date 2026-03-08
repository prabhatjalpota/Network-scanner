import os
import platform
import subprocess

# Function to perform ICMP Ping

def icmp_ping(target):
    print(f"Pinging {target}...")
    result = subprocess.run(['ping', '-c', '4', target], stdout=subprocess.PIPE)
    return result.stdout.decode('utf-8')

# Function to perform ARP-based host discovery

def arp_discovery():
    print("Performing ARP based host discovery...")
    result = subprocess.run(['arp', '-a'], stdout=subprocess.PIPE)
    return result.stdout.decode('utf-8')

# Main function

def main():
    # Example target for ICMP Ping
    target = '8.8.8.8'  # Google DNS for testing
    print(icmp_ping(target))

    # ARP Discovery
    print(arp_discovery())

if __name__ == '__main__':
    main()