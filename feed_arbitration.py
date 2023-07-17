import os
import sys
import struct
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from typing import Generator, Dict
from scapy.all import PcapReader, Raw


def process_files(file_a: str, file_b: str) -> Dict[str, float]:
    """
    Process the two packet files (.pcap) from feed A and B and compute the statistics.

    Paramters
    ---------
    file_a: str
        Path to the packet capture file for feed A. (ex. 'test_a.pcap')
    file_a: str
        Path to the packet capture file for feed B. (ex. 'test_b.pcap')

    Returns
    -------
    stats: dict
        A dictionary containing the total packets, number of missing packets,
        packets that were faster for each respective feed, and how fast those packets were on average
        (ex. {'a_total': 2, 'b_total': 2, 'a_missing': 0, 'b_missing': 0, 'a_faster': 1, 'b_faster': 1, 'a_speed_avg': 1.0, 'b_speed_avg': 1.0})
    """
    feed_a = feed_packets_to_generator(file_a)
    feed_b = feed_packets_to_generator(file_b)
    stats = compare_feeds(feed_a, feed_b)
    stats['a_speed_avg'] = stats['a_diff']*1.0/stats['a_faster']/1e9 if stats['a_faster'] > 0 else None
    stats['b_speed_avg'] = stats['b_diff']*1.0/stats['b_faster']/1e9 if stats['b_faster'] > 0 else None
    return stats


def feed_packets_to_generator(file_path: str) -> Generator[bytes, None, None]:
    """
    Turn the packet capture file into a generator to avoid reading all into memory

    Paramters
    ---------
    file_path: str
        Path to the packet capture file (ex. 'test_a.pcap')

    Yields
    ------
    packet: bytes/None
        Will yield packet available in the file, and return None to signify end of file
    """
    # Set the scapy.runtime logging to be error to avoid the Warnings
    with PcapReader(file_path) as pcap_reader:
        for packet in pcap_reader:
            yield packet
    yield None


def process_packet(packet: bytes) -> tuple[int, int]:
    """
    From each packet, per the CME documentation (https://www.cmegroup.com/confluence/display/EPICSANDBOX/MDP+3.0+-+SBE+Technical+Headers),
    extract the sequence number and sending time, also knowing the trailer is a Metamako trailer, grab arrival timestamps

    Paramters
    ---------
    packet: bytes
        The packet which needs to be parsed for sequence and timestamps

    Returns
    -------
    sequence_number : int
        A unique sequence number given to each packet sent, each channel will have its own separate set of sequence numbers 
        that will increment sequentially with each packet and reset weekly
    trailer_nanoseconds : int
        The trailer gave the package arrival timestamps in two pieces, the seconds since epoch and nanosecond correction,
        opted to turn the seconds into nanoseconds to preserve the nanosecond precision as datetime object does not offer it
    """
    sequence_number = struct.unpack('<I', bytes(packet[Raw])[:4])[0]
    sending_time = struct.unpack('<Q', bytes(packet[Raw])[4:12])[0]
    trailer = bytes(packet[Raw])[-20:]
    seconds = struct.unpack('>I', trailer[8:12])[0]
    nanoseconds = struct.unpack('>I', trailer[12:16])[0]
    trailer_nanoseconds = seconds * 1e9 + nanoseconds
    return sequence_number, trailer_nanoseconds


def compare_packets(packet_a: bytes, packet_b: bytes, stats: Dict[str, int]) -> tuple[bool, bool, Dict[str, int]]:
    """
    Compare two packets to recognize if they are the same sequence number, if they are check the arrival difference.
    If one is faster denote that it is faster, by how much. If one sequence number is higher than the other, that means
    the lower one should be incremented, also that one of the feeds was missing the lower sequence number package.
        
    Paramters
    ---------
    packet_a: bytes
        The packet from channel A
    packet_b: bytes
        The packet from channel B
    stats: dict
        Dictionary containing the most recent counting statistics for the feed comparison
        
    Returns
    -------
    advance_a : boolean
        Boolean whether the generator pointing to channel A needs to be incremented
    advance_b : boolean
        Boolean whether the generator pointing to channel B needs to be incremented
    stats : dict
        Dictionary containing the most recent counting statistics, updated from this packet comparison
        (ex. {'a_total': 2, 'b_total': 2, 'a_missing': 0, 'b_missing': 0, 'a_faster': 1, 'b_faster': 1, 'a_diff': 1000000000.0, 'b_diff': 1000000000.0})
    """
    advance_a, advance_b = True, True
    sequence_a, time_a = process_packet(packet_a)
    sequence_b, time_b = process_packet(packet_b)
    if sequence_a == sequence_b:
        if time_a < time_b:
            stats['a_faster'] += 1
            stats['a_diff'] += (time_b - time_a)
        if time_b < time_a:
            stats['b_faster'] += 1
            stats['b_diff'] += (time_a - time_b)
    elif sequence_a < sequence_b:
        stats['b_missing'] += 1
        advance_b = False
    else:
        stats['a_missing'] += 1
        advance_a = False
    return advance_a, advance_b, stats
    

def compare_feeds(feed_a: Generator[bytes, None, None], feed_b: Generator[bytes, None, None]) -> Dict[str, int]:
    """
    Compare the packets from feeds A and B and compute the statistics

    Paramters
    ---------
    feed_a: Generator 
        Generator for packets from side A that will return None when out of packets
    feed_b: Generator 
        Generator for packets from side N that will return None when out of packets

    Returns
    -------
    stats: dict
        A dictionary containing the total packets, number of missing packets,
        packets that were faster for each respective feed, and how big of a difference the feeds were (expressed in nanoseconds)
        (ex. {'a_total': 2, 'b_total': 2, 'a_missing': 0, 'b_missing': 0, 'a_faster': 1, 'b_faster': 1, 'a_diff': 1000000000.0, 'b_diff': 1000000000.0})
    """
    packet_a = next(feed_a)
    packet_b = next(feed_b)
    stats = {
        'a_total': 0,
        'b_total': 0,
        'a_missing': 0,
        'b_missing': 0,
        'a_faster': 0,
        'b_faster': 0,
        'a_diff': 0,
        'b_diff': 0,
    }
    while packet_a and packet_b:
        advance_a, advance_b, stats = compare_packets(packet_a, packet_b, stats)
        if advance_a:
            stats['a_total'] += 1
            packet_a = next(feed_a)
        if advance_b:
            stats['b_total'] += 1
            packet_b = next(feed_b)
    
    # Check which of the packets are None and make sure to count out
    while packet_a:
        stats['a_total'] += 1
        stats['b_missing'] += 1
        packet_a = next(feed_a)
        
    while packet_b:
        stats['b_total'] += 1
        stats['a_missing'] += 1
        packet_b = next(feed_b)
        
    return stats


def main():
    """
    This function parses command line arguments and expects either a directory or specific file names for feed A and feed B.
    If given a directory, it will look for a .pcap file with 14310 to be feed A's packets, and 15310 for feed B
    It then calls the process_files function to process the packets and compute the statistics, finally, it prints the stats.

    Usage
    -----
    Run the script with the desired command line arguments to process specific files.

    Command Line Arguments
    ----------------------
    -d/--directory: Directory containing the input files (optional, mutually exclusive with -fa/-fb)
    -fa/--file_a: File name for feed A (optional, mutually exclusive with -d)
    -fb/--file_b: File name for feed B (optional, mutually exclusive with -d)
    """
    
    parser = argparse.ArgumentParser(description='Process packet files and compute statistics.')
    parser.add_argument('-d', '--directory', type=str, help='Directory containing the input files')
    parser.add_argument('-fa', '--file_a', type=str, help='File name for feed A')
    parser.add_argument('-fb', '--file_b', type=str, help='File name for feed B')
    args = parser.parse_args()

    if args.directory and not (args.file_a and args.file_b):
        file_a = os.path.join(args.directory, [f for f in os.listdir(args.directory) if '14310' in f and f.endswith('.pcap')][0])
        file_b = os.path.join(args.directory, [f for f in os.listdir(args.directory) if '15310' in f and f.endswith('.pcap')][0])
    elif args.file_a and args.file_b:
        file_a = args.file_a
        file_b = args.file_b
    else:
        parser.error('Either provide the directory or both file names.')
        
    stats = process_files(file_a, file_b)

    print('Total Packets A:', stats['a_total'])
    print('Total Packets B:', stats['b_total'])
    print('Missing Packets A:', stats['a_missing'])
    print('Missing Packets B:', stats['b_missing'])
    print('Faster Packets A:', stats['a_faster'])
    print('Faster Packets B:', stats['b_faster'])
    print('Average Speed Advantage A (in seconds if None, no packets faster):', stats['a_speed_avg'])
    print('Average Speed Advantage B (in seconds if None, no packets faster):', stats['b_speed_avg'])
    

if __name__ == '__main__':
    main()
