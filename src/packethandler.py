from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
import threading
from logger import FirewallLogger

class PacketHandler:
    def __init__(self, interface="eth0"):
        """Initialize packet handler with specified network interface"""
        self.interface = interface
        self.logger = FirewallLogger()
        self.running = False
        self.packet_count = 0
        self.lock = threading.Lock()
        
    def _extract_packet_info(self, packet):
        """Extract relevant information from captured packet"""
        packet_info = {
            'src_ip': None,
            'dst_ip': None,
            'protocol': None,
            'src_port': None,
            'dst_port': None,
            'length': len(packet)
        }
        
        # Extract IP layer information
        if IP in packet:
            packet_info.update({
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': packet[IP].proto
            })
            
            # Extract transport layer information
            if TCP in packet:
                packet_info.update({
                    'protocol': 'TCP',
                    'src_port': packet[TCP].sport,
                    'dst_port': packet[TCP].dport,
                    'flags': packet[TCP].flags
                })
            elif UDP in packet:
                packet_info.update({
                    'protocol': 'UDP',
                    'src_port': packet[UDP].sport,
                    'dst_port': packet[UDP].dport
                })
            elif ICMP in packet:
                packet_info.update({
                    'protocol': 'ICMP',
                    'type': packet[ICMP].type,
                    'code': packet[ICMP].code
                })
                
        return packet_info
    
    def packet_callback(self, packet):
        """Callback function for packet processing"""
        try:
            with self.lock:
                self.packet_count += 1
            
            # Extract and log packet information
            packet_info = self._extract_packet_info(packet)
            self.logger.log_packet(packet_info)
            
            # Basic packet statistics
            if self.packet_count % 100 == 0:
                self.logger.log_info(f"Processed {self.packet_count} packets")
                
        except Exception as e:
            self.logger.log_error(f"Error processing packet: {str(e)}")
    
    def start_capture(self):
        """Start packet capture"""
        try:
            self.running = True
            self.logger.log_info(f"Starting packet capture on interface {self.interface}")
            
            # Start packet capture using scapy
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                store=0,
                stop_filter=lambda _: not self.running
            )
            
        except Exception as e:
            self.logger.log_error(f"Error starting capture: {str(e)}")
    
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        self.logger.log_info("Stopping packet capture")