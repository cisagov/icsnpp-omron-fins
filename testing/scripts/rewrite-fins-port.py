#!/usr/bin/env python3

"""Create deterministic custom-port FINS test traces without extra packages."""

import argparse
import struct
from pathlib import Path


PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\xa1\xb2\x3c\x4d": ">",
}


def packet_layout(packet, linktype, protocol):
    if linktype == 1:  # Ethernet
        if len(packet) < 14:
            return None
        network_offset = 14
        ethertype = struct.unpack_from("!H", packet, 12)[0]
        while ethertype in (0x8100, 0x88A8):
            if len(packet) < network_offset + 4:
                return None
            ethertype = struct.unpack_from("!H", packet, network_offset + 2)[0]
            network_offset += 4
        if ethertype != 0x0800:
            return None
    elif linktype in (101, 228):  # Raw IPv4
        network_offset = 0
    else:
        raise ValueError(f"unsupported link type: {linktype}")

    if len(packet) < network_offset + 20 or packet[network_offset] >> 4 != 4:
        return None

    ip_header_length = (packet[network_offset] & 0x0F) * 4
    transport_number = 6 if protocol == "tcp" else 17
    if packet[network_offset + 9] != transport_number:
        return None

    transport_offset = network_offset + ip_header_length
    if len(packet) < transport_offset + 8:
        return None

    source_port, destination_port = struct.unpack_from("!HH", packet, transport_offset)
    total_length = struct.unpack_from("!H", packet, network_offset + 2)[0]
    ip_end = min(len(packet), network_offset + total_length)

    if protocol == "tcp":
        if len(packet) < transport_offset + 20:
            return None
        transport_header_length = (packet[transport_offset + 12] >> 4) * 4
    else:
        transport_header_length = 8

    return {
        "network_offset": network_offset,
        "transport_offset": transport_offset,
        "source_port": source_port,
        "destination_port": destination_port,
        "payload_length": max(0, ip_end - transport_offset - transport_header_length),
    }


def transform_packet(packet, linktype, protocol, source_port, custom_port, direction):
    layout = packet_layout(packet, linktype, protocol)
    if layout is None:
        return packet, False, False

    if direction == "server-first":
        selected = (
            layout["source_port"] == source_port and layout["payload_length"] > 0
        )
        if not selected:
            return packet, False, False

    packet = bytearray(packet)
    transport_offset = layout["transport_offset"]
    changed = False
    for offset in (transport_offset, transport_offset + 2):
        if struct.unpack_from("!H", packet, offset)[0] == source_port:
            struct.pack_into("!H", packet, offset, custom_port)
            changed = True

    if direction == "reverse":
        network_offset = layout["network_offset"]
        if linktype == 1:
            packet[0:6], packet[6:12] = packet[6:12], packet[0:6]
        packet[network_offset + 12 : network_offset + 16], packet[
            network_offset + 16 : network_offset + 20
        ] = (
            packet[network_offset + 16 : network_offset + 20],
            packet[network_offset + 12 : network_offset + 16],
        )
        packet[transport_offset : transport_offset + 2], packet[
            transport_offset + 2 : transport_offset + 4
        ] = (
            packet[transport_offset + 2 : transport_offset + 4],
            packet[transport_offset : transport_offset + 2],
        )

    network_offset = layout["network_offset"]
    packet[network_offset + 10 : network_offset + 12] = b"\x00\x00"
    checksum_offset = 16 if protocol == "tcp" else 6
    packet[
        transport_offset + checksum_offset : transport_offset + checksum_offset + 2
    ] = b"\x00\x00"
    return bytes(packet), changed, True


def rewrite_pcap(data, protocol, source_port, custom_port, direction):
    endian = PCAP_MAGICS[data[:4]]
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    output = bytearray(data[:24])
    offset = 24
    changed = 0
    selected = 0

    while offset < len(data):
        record_header = data[offset : offset + 16]
        captured_length = struct.unpack_from(endian + "I", record_header, 8)[0]
        packet_start = offset + 16
        packet_end = packet_start + captured_length
        packet, was_changed, keep = transform_packet(
            data[packet_start:packet_end],
            linktype,
            protocol,
            source_port,
            custom_port,
            direction,
        )
        if direction != "server-first" or keep:
            output.extend(record_header)
            output.extend(packet)
            selected += 1
        changed += int(was_changed)
        offset = packet_end

    return bytes(output), changed, selected


def rewrite_pcapng(data, protocol, source_port, custom_port, direction):
    if direction == "server-first":
        raise ValueError("server-first filtering requires a pcap input")

    output = bytearray(data)
    offset = 0
    endian = None
    linktypes = []
    changed = 0
    selected = 0

    while offset < len(output):
        raw_type = bytes(output[offset : offset + 4])
        if raw_type == b"\x0a\x0d\x0d\x0a":
            byte_order_magic = bytes(output[offset + 8 : offset + 12])
            endian = "<" if byte_order_magic == b"\x4d\x3c\x2b\x1a" else ">"
            linktypes = []
        if endian is None:
            raise ValueError("pcapng section header is missing")

        block_type, block_length = struct.unpack_from(endian + "II", output, offset)
        if block_type == 1:
            linktypes.append(struct.unpack_from(endian + "H", output, offset + 8)[0])
        elif block_type == 6:
            interface_id = struct.unpack_from(endian + "I", output, offset + 8)[0]
            captured_length = struct.unpack_from(endian + "I", output, offset + 20)[0]
            packet_start = offset + 28
            packet_end = packet_start + captured_length
            packet, was_changed, _ = transform_packet(
                output[packet_start:packet_end],
                linktypes[interface_id],
                protocol,
                source_port,
                custom_port,
                direction,
            )
            output[packet_start:packet_end] = packet
            changed += int(was_changed)
            selected += 1
        offset += block_length

    return bytes(output), changed, selected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--transport", required=True, choices=("tcp", "udp"))
    parser.add_argument("--source-port", type=int, default=9600)
    parser.add_argument("--custom-port", type=int, default=12345)
    parser.add_argument(
        "--direction", choices=("normal", "reverse", "server-first"), default="normal"
    )
    args = parser.parse_args()

    data = args.input.read_bytes()
    if data[:4] in PCAP_MAGICS:
        output, changed, selected = rewrite_pcap(
            data,
            args.transport,
            args.source_port,
            args.custom_port,
            args.direction,
        )
    elif data[:4] == b"\x0a\x0d\x0d\x0a":
        output, changed, selected = rewrite_pcapng(
            data,
            args.transport,
            args.source_port,
            args.custom_port,
            args.direction,
        )
    else:
        raise ValueError("input is neither pcap nor pcapng")

    if changed == 0 or selected == 0:
        raise ValueError("no matching packets were transformed")
    args.output.write_bytes(output)


if __name__ == "__main__":
    main()
