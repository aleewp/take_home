import struct
from scapy.all import Ether, IP, UDP, Raw, PcapWriter

def create_sample_packet(sequence_number:int, seconds:int, nanoseconds:int) -> Ether:
    """
    Create a sample packet with the given sequence number, seconds, and nanoseconds.

    Paramters
    ---------
    sequence_number: int
        The message sequence number for the test packet.
    seconds: int
        The seconds value for the packet arrival time.
    nanoseconds: int
        The nanoseconds value for the packet arrival time correction.

    Returns
    -------
    packet: Ether
        An Ether packet with the specified values.
    """
    header = bytes(12)
    body = bytes(96)
    offset = bytes(4)
    ending = bytes(4)
    seq = struct.pack('<I', sequence_number)
    secs = struct.pack('>I', seconds)
    nanos = struct.pack('>I', nanoseconds)
    payload = header + seq + body + offset + secs + nanos + ending
    packet = Ether() / IP() / UDP() / Raw(load=bytes(payload))
    return packet

def create_packet_file(packets: list, file_name: str) -> None:
    """
    Create a packet file (.pcap) with the given list of packets.

    Parameters
    ----------
    packets: list
        List of packets to be written to the file.
    file_name: str
        File name for the packet file

    Returns
    -------
        None
    """
    with PcapWriter(file_name, append=True, sync=True) as pktdump:
        for packet in packets:
            pktdump.write(packet)
