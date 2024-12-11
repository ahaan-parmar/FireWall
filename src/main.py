import os
import sys
import signal
import threading
import time
from packethandler import PacketHandler
from firewall_rules import Rule, Action, Protocol
from rule_config import RuleConfiguration
from logger import FirewallLogger
import yaml

class FirewallApplication:
    def __init__(self, interface="eth0", config_file="config/rules.yaml"):
        # Get the project root directory (one level up from src)
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.config_file = os.path.join(base_dir, config_file)
        # Initialize our core components
        self.logger = FirewallLogger()
        self.packet_handler = PacketHandler(interface=interface)
        self.config = RuleConfiguration(self.config_file)
        self.running = False
        
        # Instead of setting up signals in __init__, we'll do it in start()
        self.logger.log_info("Firewall application initialized")

    def load_rules(self) -> list:
        # Add debug print to show exact path
        print(f"Attempting to load rules from: {os.path.abspath(self.config_file)}")
        try:
            with open(self.config_file, 'r') as f:
                config = yaml.safe_load(f)

            rules = []
            for rule_config in config.get('rules', []):
                try:
                    rule = self._create_rule_from_config(rule_config)
                    rules.append(rule)
                except Exception as e:
                    self.logger.error(f"Error creating rule: {str(e)}")
                    continue

            return rules

        except Exception as e:
            self.logger.error(f"Error loading rules: {str(e)}")
            return []

    def shutdown(self):
        """
        Handles the shutdown process for our firewall.
        This ensures all components are properly cleaned up.
        """
        print("\nShutting down firewall...")
        self.running = False
        self.packet_handler.stop_capture()
        self.logger.log_info("Firewall shutdown complete")
        sys.exit(0)

    def start(self):
        """
        Starts the firewall application and sets up signal handling.
        This is where we begin capturing packets and processing them.
        """
        try:
            self.running = True
            self.logger.log_info("Starting firewall application")
            
            # Set up signal handlers here instead of in __init__
            def signal_handler(signum, frame):
                self.shutdown()
            
            # Register our signal handler
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
            
            # Load configuration
            self.load_config()
            
            # Start packet capture in a separate thread
            capture_thread = threading.Thread(
                target=self.packet_handler.start_capture
            )
            capture_thread.daemon = True
            capture_thread.start()
            
            print("Firewall is running. Press Ctrl+C to stop.")
            
            # Keep the main thread alive
            while self.running:
                capture_thread.join(1)
                
        except Exception as e:
            self.logger.log_error(f"Error in firewall operation: {str(e)}")
            self.running = False
            self.packet_handler.stop_capture()
            raise

    def load_config(self):
        """
        Loads firewall rules from configuration file.
        Falls back to default rules if the config file is missing.
        """
        try:
            rules = self.config.load_rules()
            for rule in rules:
                self.packet_handler.add_rule(rule)
            self.logger.log_info(f"Loaded {len(rules)} rules from configuration")
        except FileNotFoundError:
            self.logger.log_warning("Configuration file not found, using default rules")
        except Exception as e:
            self.logger.log_error(f"Error loading configuration: {str(e)}")

# Rest of the code remains the same...