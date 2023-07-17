import unittest
from unittest.mock import patch
import os
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from util import create_sample_packet, create_packet_file
from feed_arbitration import process_files


class CompareFeedsTestCase(unittest.TestCase):
            
    def test_process_files_same_packets_one_faster(self):
        packets_a = [create_sample_packet(66051, 16777216, 83886080), create_sample_packet(66052, 16777217, 83886080)]
        packets_b = [create_sample_packet(66051, 16777217, 83886080),create_sample_packet(66052, 16777218, 83886080)]
        create_packet_file(packets_a, 'test_a.pcap')
        create_packet_file(packets_b, 'test_b.pcap')
        
        stats = process_files('test_a.pcap', 'test_b.pcap')
        os.remove('test_a.pcap')
        os.remove('test_b.pcap')
        self.assertEqual(stats['a_total'], 2)
        self.assertEqual(stats['b_total'], 2)
        self.assertEqual(stats['a_missing'], 0)
        self.assertEqual(stats['b_missing'], 0)
        self.assertEqual(stats['a_faster'], 2)
        self.assertEqual(stats['b_faster'], 0)
        self.assertEqual(stats['a_speed_avg'], 1.0)
        self.assertEqual(stats['b_speed_avg'], None)
        
        
    def test_process_files_same_packets_both_faster(self):
        packets_a = [create_sample_packet(66051, 16777216, 83886080), create_sample_packet(66052, 16777218, 83886080)]
        packets_b = [create_sample_packet(66051, 16777217, 83886080),create_sample_packet(66052, 16777217, 83886080)]
        create_packet_file(packets_a, 'test_a1.pcap')
        create_packet_file(packets_b, 'test_b1.pcap')
        stats = process_files('test_a1.pcap', 'test_b1.pcap')
        os.remove('test_a1.pcap')
        os.remove('test_b1.pcap')
        self.assertEqual(stats['a_total'], 2)
        self.assertEqual(stats['b_total'], 2)
        self.assertEqual(stats['a_missing'], 0)
        self.assertEqual(stats['b_missing'], 0)
        self.assertEqual(stats['a_faster'], 1)
        self.assertEqual(stats['b_faster'], 1)
        self.assertEqual(stats['a_speed_avg'], 1.0)
        self.assertEqual(stats['b_speed_avg'], 1.0)
        

    def test_compare_feeds_with_missing_packets(self):
        packets_a = [create_sample_packet(66051, 16777216, 83886080), create_sample_packet(66052, 16777217, 83886080)]
        packets_b = [create_sample_packet(66051, 16777217, 83886080)]
        create_packet_file(packets_a, 'test_c.pcap')
        create_packet_file(packets_b, 'test_d.pcap')
        stats = process_files('test_c.pcap', 'test_d.pcap')
        os.remove('test_c.pcap')
        os.remove('test_d.pcap')
        self.assertEqual(stats['a_total'], 2)
        self.assertEqual(stats['b_total'], 1)
        self.assertEqual(stats['a_missing'], 0)
        self.assertEqual(stats['b_missing'], 1)
        self.assertEqual(stats['a_faster'], 1)
        self.assertEqual(stats['b_faster'], 0)
        self.assertEqual(stats['a_speed_avg'], 1.0)
        self.assertEqual(stats['b_speed_avg'], None)
        

    def test_compare_feeds_with_multiple_missing_from_a(self):
        packets_a = [create_sample_packet(66051, 16777216, 83886080)]
        packets_b = [ create_sample_packet(66051, 16777216, 83886080), create_sample_packet(66052, 16777217, 83886080), create_sample_packet(66053, 16777217, 83886080)]
        create_packet_file(packets_a, 'test_e.pcap')
        create_packet_file(packets_b, 'test_f.pcap')
        stats = process_files('test_e.pcap', 'test_f.pcap')
        os.remove('test_e.pcap')
        os.remove('test_f.pcap')
        self.assertEqual(stats['a_total'], 1)
        self.assertEqual(stats['b_total'], 3)
        self.assertEqual(stats['a_missing'], 2)
        self.assertEqual(stats['b_missing'], 0)
        self.assertEqual(stats['a_faster'], 0)
        self.assertEqual(stats['b_faster'], 0)
        self.assertEqual(stats['a_speed_avg'], None)
        self.assertEqual(stats['b_speed_avg'], None)
        
       
    def test_compare_feeds_with_missing_from_both(self):
        packets_a = [create_sample_packet(66051, 16777216, 83886080), create_sample_packet(66052, 16777217, 83886080)]
        packets_b = [ create_sample_packet(66050, 16777216, 83886080), create_sample_packet(66053, 16777217, 83886080)]
        create_packet_file(packets_a, 'test_g.pcap')
        create_packet_file(packets_b, 'test_h.pcap')
        stats = process_files('test_g.pcap', 'test_h.pcap')
        os.remove('test_g.pcap')
        os.remove('test_h.pcap')
        self.assertEqual(stats['a_total'], 2)
        self.assertEqual(stats['b_total'], 2)
        self.assertEqual(stats['a_missing'], 2)
        self.assertEqual(stats['b_missing'], 2)
        self.assertEqual(stats['a_faster'], 0)
        self.assertEqual(stats['b_faster'], 0)
        self.assertEqual(stats['a_speed_avg'], None)
        self.assertEqual(stats['b_speed_avg'], None)
        
