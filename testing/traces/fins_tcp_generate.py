#!/usr/bin/python3

from scapy.all import *
import struct

# Function to create an Omron FINS/TCP packet
def create_fins_tcp_packet(src_ip, dst_ip, src_port, dst_port, fins_command, seq, ack):
    # Omron FINS/TCP header
    magic_bytes = b'\x46\x49\x4E\x53'
    tcp_header_command = 2
    tcp_header_error_code = 0
    fins_tcp_header = struct.pack(">4sIII", magic_bytes, len(fins_command) + 8, tcp_header_command, tcp_header_error_code)

    # Combine FINS/TCP header and FINS command
    fins_tcp_payload = fins_tcp_header + fins_command
    
    # Create the TCP packet with the FINS/TCP payload
    packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, seq=seq, ack=ack, flags="PA")/Raw(load=fins_tcp_payload)

    del packet[TCP].chksum
    del packet[IP].chksum
    packet = packet.__class__(bytes(packet))


    return packet

# Example usage
src_ip = "192.168.0.2"
dst_ip = "192.168.0.1"
src_port = 5000
dst_port = 9600

# Initial sequence and acknowledgment numbers
seq = 1000
ack = 2000

# Omron FINS commands
commands = {
    'RUN':                    (b'\x80\x00\x02\x00\x00\x00\x00\x00\x00\x7a\x04\x01\x00\x00\x01',                 b'\xC1\x00\x02\x00\x00\x00\x00\x00\x00\x7a\x04\x01\x00\x00'),
    'STOP':                   (b'\x80\x00\x02\x00\x00\x00\x00\x00\x00\x7a\x04\x02',                             b'\xC1\x00\x02\x00\x00\x00\x00\x00\x00\x7a\x04\x02\x00\x00'),
    'CONTROLLER DATA READ 1': (b'\x80\x00\x02\x00\xc8\x00\x00\x00\xef\x05\x05\x01\x00',                         b'\xc1\x00\x02\x00\x00\x00\x00\x00\x00\x7a\x05\x01\x00\x00\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x00\x01\x01\x00\x02\x01\x02\x00\x02\x00\x00\x04'),
    'CONTROLLER DATA READ 2': (b'\x80\x00\x02\x00\xc8\x00\x00\x00\xef\x05\x05\x01\x00',                         b'\xc1\x00\x02\x00\x00\x00\x00\x00\x00\x7a\x05\x01\x00\x00\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x00\x01\x01\x00\x02\x01\x02\x00\x02\x00\x00\x04'),
    'CLOCK READ':             (b'\x80\x00\x02\x00\x00\x00\x00\x00\x00\x7a\x07\x01',                             b'\xc1\x00\x02\x00\x00\x00\x00\x00\x00\x7a\x07\x01\x00\x00\x09\x01\x20\x01\x02\x01\x03'),
    'CLOCK WRITE':            (b'\x80\x00\x02\x00\x00\x00\x00\x00\x00\x7a\x07\x02\x09\x01\x20\x01\x02\x01\x03', b'\xc1\x00\x02\x00\x00\x00\x00\x00\x00\x7a\x07\x02\x00\x00'),
}

# Create a list of packets
packets = []

# TCP handshake (SYN, SYN-ACK, ACK)
syn_packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="S", seq=seq)
packets.append(syn_packet)
seq += 1

syn_ack_packet = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="SA", seq=ack, ack=seq)
packets.append(syn_ack_packet)
ack += 1

ack_packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="A", seq=seq, ack=ack)
packets.append(ack_packet)

# Generate commands
for command_name, (command, response) in commands.items():
    packet_command = create_fins_tcp_packet(src_ip, dst_ip, src_port, dst_port, command, seq, ack)
    packets.append(packet_command)

    # Update seq number base on command length
    seq += len(packet_command[TCP].payload)

    packet_response = create_fins_tcp_packet(dst_ip, src_ip, dst_port, src_port, response, ack, seq)
    packets.append(packet_response)

    # UPdate ack number based on response length
    ack += len(packet_response[TCP].payload)


# TCP session teardown (FIN, FIN-ACK, ACK)
fin_packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="FA", seq=seq, ack=ack)
packets.append(fin_packet)
seq += 1

fin_ack_packet = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="FA", seq=ack, ack=seq)
packets.append(fin_ack_packet)
ack += 1

ack_fin_packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="A", seq=seq, ack=ack)
packets.append(ack_fin_packet)

# Write the packets to a pcap file
output_pcap_file = 'omron_fins_tcp_commands_responses.pcap'
wrpcap(output_pcap_file, packets)

print(f"Packet capture with Omron FINS/TCP command and response pairs saved to {output_pcap_file}")
