# src/packet_handler.py

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
import threading
from logger import FirewallLogger
from firewall_rules import RuleManager, Action, Protocol

class PacketHandler:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.logger = FirewallLogger()
        self.rule_manager = RuleManager()
        self.running = False
        self.packet_count = 0
        self.lock = threading.Lock()
        
        # Add some default rules
        self.rule_manager.add_rule(
            action=Action.ALLOW,
            protocol=Protocol.ANY,
            source_ip="192.168.1.0/24",  # Local network
            description="Allow local network traffic"
        )
        
        self.rule_manager.add_rule(
            action=Action.DENY,
            protocol=Protocol.TCP,
            destination_port=22,
            description="Block incoming SSH"
        )

    def process_packet(self, packet):
        """Process and filter captured packets"""
        try:
            with self.lock:
                self.packet_count += 1
            
            # Extract packet information
            packet_info = self._extract_packet_info(packet)
            if not packet_info:
                return
            
            # Evaluate packet against rules
            action = self.rule_manager.evaluate_packet(packet_info)
            
            # Log the action
            self.logger.log_info(
                f"Packet {self.packet_count}: "
                f"{packet_info['src_ip']}:{packet_info.get('src_port', '')} -> "
                f"{packet_info['dst_ip']}:{packet_info.get('dst_port', '')} "
                f"[{packet_info['protocol']}] - {action.value.upper()}"
            )
            
            # Return True to allow packet, False to block
            return action == Action.ALLOW
            
        except Exception as e:
            self.logger.log_error(f"Error processing packet: {str(e)}")
            return False  # Default to blocking on error

    def _extract_packet_info(self, packet):
        """Extract relevant information from a packet"""
        if IP not in packet:
            return None
            
        info = {
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': 'unknown'
        }
        
        if TCP in packet:
            info.update({
                'protocol': 'tcp',
                'src_port': packet[TCP].sport,
                'dst_port': packet[TCP].dport,
                'flags': packet[TCP].flags
            })
        elif UDP in packet:
            info.update({
                'protocol': 'udp',
                'src_port': packet[UDP].sport,
                'dst_port': packet[UDP].dport
            })
        elif ICMP in packet:
            info.update({
                'protocol': 'icmp',
                'type': packet[ICMP].type,
                'code': packet[ICMP].code
            })
            
        return info