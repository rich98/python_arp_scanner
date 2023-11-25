from scapy.all import ARP, Ether, srp

def discover_devices(ip_range):
    # ARP request packet
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)

    # Sending packet and capture the response
    result = srp(arp_request, timeout=3, verbose=0)[0]

    # Processing the results
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def print_results(devices):
    print("IP Address\tMAC Address")
    print("-----------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t{device['mac']}")

if __name__ == "__main__":
    # set the ip range
    target_ip_range = "192.168.0.1/24"

    # Device discovery
    devices = discover_devices(target_ip_range)

    # Output the results
    print_results(devices)
