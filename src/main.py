import os
import sys
import signal
import threading
import time
from packet_handler import PacketHandler
from firewall_rules import Rule, Action, Protocol
from rule_config import RuleConfiguration
from logger import FirewallLogger

class FirewallApplication:
    def __init__(self, interface="eth0", config_file="config/rules.yaml"):
        # Initialize our core components
        self.logger = FirewallLogger()
        self.packet_handler = PacketHandler(interface=interface)
        self.config = RuleConfiguration(config_file)
        self.running = False
        
        # Instead of setting up signals in __init__, we'll do it in start()
        self.logger.log_info("Firewall application initialized")

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

def check_root():
    """
    Verifies that the program is running with root privileges,
    which are required for packet capture.
    """
    if os.geteuid() != 0:
        print("Error: This program must be run with root privileges!")
        print("Please try again using 'sudo python3 src/main.py'")
        sys.exit(1)

def main():
    """
    Main entry point for our firewall application.
    Sets up the environment and starts the firewall.
    """
    try:
        # Check for root privileges
        check_root()
        
        # Get available network interface
        interfaces = os.listdir('/sys/class/net/')
        interface = 'eth0' if 'eth0' in interfaces else interfaces[0]
        
        # Create and start the firewall
        app = FirewallApplication(interface=interface)
        app.start()
        
    except KeyboardInterrupt:
        print("\nFirewall stopped by user")
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()