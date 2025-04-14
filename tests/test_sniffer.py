## File: tests/test_sniffer.py
import os

def test_sniffer_output():
    """Check if packet sniffer output file exists."""
    assert os.path.isfile("datasets/raw_packets.csv"), "Packet sniffer output file missing"
    print("Packet sniffer test passed.")

test_sniffer_output()