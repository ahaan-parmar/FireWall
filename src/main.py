import os
import sys
import signal
import threading
from packethandler import PacketHandler
from firewall_rules import Rule, Action, Protocol
from rule_config import RuleConfiguration
from logger import FirewallLogger
import time

class FirewallApplication:
    #Main firewall application class that coordinates all components
    def __init__(self, interface="eth0", config_file="config/rules.yaml"):
        self.logger = FirewallLogger()
        self.packet_handler = PacketHandler(interface=interface)
        self.config = RuleConfiguration(config_file)
        self.running = False
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self.handle_shutdown)
        signal.signal(signal.SIGTERM, self.handle_shutdown)
        
        self.logger.log_info("Firewall application initialized")

    def load_config(self):
        """Load firewall rules from configuration file"""
        rules = self.config.load_rules()
        for rule in rules:
            self.packet_handler.add_rule(rule)
        self.logger.log_info(f"Loaded {len(rules)} rules from configuration")

    def handle_shutdown(self, signum, frame):
        """Handle shutdown signals gracefully"""
        print("\nReceived shutdown signal. Stopping firewall...")
        self.running = False
        self.packet_handler.stop_capture()
        self.logger.log_info("Firewall shutdown complete")
        sys.exit(0)

    def start(self):
        """Start the firewall application"""
        try:
            self.running = True
            self.logger.log_info("Starting firewall application")
            
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

def check_root():
    """Verify root/administrator privileges"""
    if os.geteuid() != 0:
        print("Error: This program must be run with root privileges!")
        print

def main():
    """
    Main entry point for the firewall application.
    Handles initial setup, program execution, and proper cleanup.
    """
    # Verify root privileges before starting
    check_root()
    
    # Create a logger instance for main function logging
    main_logger = FirewallLogger()
    main_logger.start_automatic_logging()
    
    try:
        # Log the start of the program
        main_logger.queue_log('INFO', "Starting firewall program")
        
        # Create and start the firewall application with automatic logging
        app = FirewallApplication(interface="eth0")  # Adjust interface as needed
        
        # Log successful application creation
        main_logger.queue_log('INFO', "Firewall application created successfully")
        
        # Start the application
        app.start()
        
    except KeyboardInterrupt:
        # Handle user interruption gracefully
        main_logger.queue_log('INFO', "Firewall stopped by user")
        print("\nFirewall stopped by user")
        
    except Exception as e:
        # Log any unexpected errors
        main_logger.queue_log('ERROR', f"Critical error in main: {str(e)}")
        print(f"Error: {str(e)}")
        
        # Give logger time to process final messages
        time.sleep(1)
        sys.exit(1)
        
    finally:
        # Ensure logging is properly stopped
        main_logger.queue_log('INFO', "Shutting down main logger")
        main_logger.stop_automatic_logging()
        
        # Give time for final log messages to be processed
        time.sleep(1)

if __name__ == "__main__":
    main()