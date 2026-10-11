from scapy.all import IP, UDP, send, Raw
import hmac
import hashlib
import time

timestamp = int(time.time())

secret = b"your_secret"

timestamp_bytes = timestamp.to_bytes(8, "big")

hmac_sig = hmac.new(secret, timestamp_bytes, hashlib.sha256).digest()

payload = timestamp_bytes + hmac_sig

pkt = IP(dst="127.0.0.1") / UDP(dport=9999) / Raw(load=payload)

send(pkt, verbose=True)
