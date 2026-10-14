"""Tiny UDP syslog sender for smoke-testing ingestion (task 1.6).

Usage (with the listener running):
    python scripts/syslog_sender.py [count] [host] [port]
    python scripts/syslog_sender.py 50
"""
import random
import socket
import sys

HOST = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 1514
COUNT = int(sys.argv[1]) if len(sys.argv) > 1 else 10

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(COUNT):
    msg = (
        f"<134>1 firewall ts-edge - - - "
        f"src=10.0.0.{10 + i % 8} dst=192.168.1.{20 + i % 12} "
        f"sport={40000 + i} dport={random.choice([22, 80, 443, 53, 3389])} "
        f"proto={random.choice(['TCP', 'UDP', 'ICMP'])} size={random.randint(64, 1500)} "
        f"flags={'SYN' if i % 4 == 0 else 'ACK'} "
        f"outcome={'ESTABLISHED' if i % 3 else 'REJECTED'} sev=6"
    )
    sock.sendto(msg.encode(), (HOST, PORT))
sock.close()
print(f"sent {COUNT} datagrams to {HOST}:{PORT}")
