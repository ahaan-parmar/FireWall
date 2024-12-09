import os
import sys
import signal
import threading
import time
from packethandler import PacketHandler
from firewall_rules import Rule, Action, Protocol
from rule_config import RuleConfiguration
from logger import FirewallLogger

class FirewallApplication:
    def __init__(self, interface="eth0", config_file="config/rules.yaml"):
        # Initialize core components
        self.logger = FirewallLogger()
        self.packet_handler = PacketHandler(interface=interface)
        self.config = RuleConfiguration(config_file)
        self.running = False
        
        #set up signal handlers shutdown
        signal.signal(signal.SIGINT, self.handle_shutdown)
        signal.signal(signal.SIGTERM, self.handle_shutdown)
        
        self.logger.log_info("Firewall application initialized")

    def load_config(self):
        try:
            rules = self.config.load_rules()
            for rule in rules:
                self.packet_handler.add_rule(rule)
            self.logger.log_info(f"Loaded {len(rules)} rules from configuration")
        except Exception as e:
            self.logger.log_error(f"Error loading configuration: {str(e)}")

    def handle_shutdown(self, signum, frame):
        print("\nReceived shutdown signal. Stopping firewall...")
        self.running = False
        self.packet_handler.stop_capture()
        self.logger.log_info("Firewall shutdown complete")
        sys.exit(0)

    def start(self):
        #start the firewall application
        try:
            self.running = True
            self.logger.log_info("Starting firewall application")
            
            # Load configuration rules
            self.load_config()
            
            # Start packet capture in a separate thread
            capture_thread = threading.Thread(
                target=self.packet_handler.start_capture
            )
            capture_thread.daemon = True
            capture_thread.start()
            
            print("Firewall is running. Press Ctrl+C to stop.")
            
            # Keep the main thread alive and responsive
            while self.running:
                if not capture_thread.is_alive():
                    self.logger.log_error("Capture thread died unexpectedly")
                    break
                capture_thread.join(1)
                
        except Exception as e:
            self.logger.log_error(f"Error in firewall operation: {str(e)}")
            self.running = False
            self.packet_handler.stop_capture()
            raise

def check_root():
    #verify root/administrator privileges.
 
    if os.geteuid() != 0:
        print("Error: This program must be run with root privileges!")
        print("Please try again using 'sudo python3 src/main.py'")
        sys.exit(1)

def setup_directories():
    """
    Create necessary directories for logs and configuration.
    """
    directories = ['logs', 'config']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)

def main():
    try:
        # Verify root privileges
        check_root()
        
        # Create required directories
        setup_directories()
        
        # Initialize logging
        logger = FirewallLogger()
        logger.log_info("Starting firewall program")
        
        # Get available network interface
        interfaces = os.listdir('/sys/class/net/')
        interface = 'eth0' if 'eth0' in interfaces else interfaces[0]
        
        # Create and start firewall application
        app = FirewallApplication(interface=interface)
        app.start()
        
    except KeyboardInterrupt:
        logger.log_info("Firewall stopped by user")
        print("\nFirewall stopped by user")
        
    except Exception as e:
        logger.log_error(f"Critical error in main: {str(e)}")
        print(f"Error: {str(e)}")
        sys.exit(1)
        
    finally:
        time.sleep(1)  # Allow final logs to be writtenc

if __name__ == "__main__":
    main()