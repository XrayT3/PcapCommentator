import os
import json
from scapy.all import rdpcap, wrpcapng


def is_packet_number_valid(packets, packet_number):
    if packet_number > len(packets) or packet_number < 1:
        print(f"Invalid packet number {packet_number}")
        return False
    return True


def packet_to_json(packet, packet_number):
    packet_dict = {'packet_number': packet_number}

    comment = getattr(packet, 'comment', None)
    if comment is None:
        packet_dict['comment'] = 'None'
    else:
        packet_dict['comment'] = comment.decode("utf-8")

    for layer in packet:
        packet_dict[layer.__class__.__name__] = layer.fields

    return json.dumps(packet_dict, indent=4)


def add_comment_to_packet(pcapng_file: str, comment: str, packet_number: int):
    if not os.path.exists(pcapng_file):
        print(f"File {pcapng_file} not found!")
        return

    packets = rdpcap(pcapng_file)

    if is_packet_number_valid(packets, packet_number):
        packets[packet_number - 1].comment = comment

        wrpcapng('output.pcapng', packets)
        print(f"Comment added to packet {packet_number} and saved to output.pcapng")


def read_comment_from_packet(pcapng_file: str, packet_number: int):
    if not os.path.exists(pcapng_file):
        print(f"File {pcapng_file} not found!")
        return

    packets = rdpcap(pcapng_file)

    if is_packet_number_valid(packets, packet_number):
        print(packet_to_json(packets[packet_number - 1], packet_number))


if __name__ == '__main__':
    add_comment_to_packet('stratosphere_capture_0x7.pcap', 'This is a comment.', 123)
    read_comment_from_packet('output.pcapng', 123)
