from dataclasses import dataclass
from typing import List, Optional, Dict
import ipaddress
import logging
from enum import Enum

class Action(Enum):
    #Defines possible actions for firewall rules
    ALLOW = "allow"
    DENY = "deny"
    LOG = "log"

class Protocol(Enum):
    #Supported network protocols
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"

@dataclass
class Rule:
    #Represents a single firewall rule
    id: int
    action: Action
    protocol: Protocol
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    description: str = ""
    enabled: bool = True

    def __post_init__(self):
        #Validate rule parameters after initialization
        if self.source_ip:
            try:
                ipaddress.ip_network(self.source_ip)
            except ValueError:
                raise ValueError(f"Invalid source IP address: {self.source_ip}")
        
        if self.destination_ip:
            try:
                ipaddress.ip_network(self.destination_ip)
            except ValueError:
                raise ValueError(f"Invalid destination IP address: {self.destination_ip}")

class RuleManager:
    #Manages firewall rules and their application
    
    def __init__(self):
        self.rules: List[Rule] = []
        self.logger = logging.getLogger(__name__)
        self._rule_counter = 0

    def add_rule(self, 
                 action: Action,
                 protocol: Protocol,
                 source_ip: Optional[str] = None,
                 destination_ip: Optional[str] = None,
                 source_port: Optional[int] = None,
                 destination_port: Optional[int] = None,
                 description: str = "") -> Rule:
        """
        Add a new firewall rule
        Returns the created rule
       """
        self._rule_counter += 1
        rule = Rule(
            id=self._rule_counter,
            action=action,
            protocol=protocol,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            description=description
        )
        self.rules.append(rule)
        self.logger.info(f"Added rule {rule.id}: {description}")
        return rule

    def remove_rule(self, rule_id: int) -> bool:
        #Remove a rule by its ID#
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id:
                self.rules.pop(i)
                self.logger.info(f"Removed rule {rule_id}")
                return True
        return False

    def evaluate_packet(self, packet_info: Dict) -> Action:
        """
        Evaluate a packet against all rules
        Returns the action to take for this packet
        """
        for rule in self.rules:
            if not rule.enabled:
                continue

            # Check protocol match
            if (rule.protocol != Protocol.ANY and 
                packet_info['protocol'].lower() != rule.protocol.value):
                continue

            # Check IP matches
            if rule.source_ip and not self._ip_matches(
                packet_info['src_ip'], rule.source_ip):
                continue

            if rule.destination_ip and not self._ip_matches(
                packet_info['dst_ip'], rule.destination_ip):
                continue

            # Check port matches for TCP/UDP
            if packet_info['protocol'].lower() in ('tcp', 'udp'):
                if (rule.source_port and 
                    packet_info.get('src_port') != rule.source_port):
                    continue
                
                if (rule.destination_port and 
                    packet_info.get('dst_port') != rule.destination_port):
                    continue

            # If we reach here, all rule conditions matched
            self.logger.debug(
                f"Packet matched rule {rule.id}: {rule.description}")
            return rule.action

        # If no rules match, default to DENY
        return Action.DENY

    def _ip_matches(self, ip: str, rule_ip: str) -> bool:
        #Check if an IP matches a rule's IP
        try:
            packet_ip = ipaddress.ip_address(ip)
            rule_network = ipaddress.ip_network(rule_ip)
            return packet_ip in rule_network
        except ValueError:
            self.logger.error(f"Invalid IP address in comparison: {ip} or {rule_ip}")
            return False

    def list_rules(self) -> List[Rule]:
        #Return all current rules#
        return self.rules