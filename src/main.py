import os
import sys
import signal
import threading
from packethandler import PacketHandler
from firewall_rules import RuleManager, Action, Protocol
from logger import FirewallLogger
import time

class FirewallApplication:
    """
    Main firewall application class that coordinates all components and handles
    user interrupts and system signals.
    """
    def __init__(self, interface="eth0"):
        # Initialize our enhanced logger with automatic logging capabilities
        self.logger = FirewallLogger()
        
        # Start the automatic logging system
        self.logger.start_automatic_logging()
        
        # Initialize packet handler with the specified network interface
        self.packet_handler = PacketHandler(interface=interface)
        self.running = False
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.handle_shutdown)
        signal.signal(signal.SIGTERM, self.handle_shutdown)
        
        # Log application startup using the enhanced logging system
        self.logger.queue_log('INFO', "Firewall application initialized")
        
    def setup_default_rules(self):
        # Configure initial firewall rules
        rule_manager = self.packet_handler.rule_manager
        
        # Allow established connections for maintaining existing network sessions
        rule_manager.add_rule(
            action=Action.ALLOW,
            protocol=Protocol.ANY,
            description="Allow established connections"
        )
        
        # Allow local network traffic for internal communication
        rule_manager.add_rule(
            action=Action.ALLOW,
            protocol=Protocol.ANY,
            source_ip="192.168.1.0/24",
            description="Allow local network traffic"
        )
        
        # Block incoming SSH attempts for security
        rule_manager.add_rule(
            action=Action.DENY,
            protocol=Protocol.TCP,
            destination_port=22,
            description="Block incoming SSH connections"
        )
        
        # Log rule setup completion using the queue system
        self.logger.queue_log('INFO', "Default firewall rules configured")

    def handle_shutdown(self, signum, frame):
        # Handle shutdown signals with proper cleanup
        print("\nReceived shutdown signal. Stopping firewall...")
        self.running = False
        self.packet_handler.stop_capture()
        
        # Log shutdown using queue system and stop automatic logging
        self.logger.queue_log('INFO', "Firewall shutdown initiated")
        self.logger.stop_automatic_logging()
        
        # Give the logger a moment to process remaining messages
        time.sleep(1)
        sys.exit(0)

    def start(self):
        try:
            self.running = True
            self.logger.queue_log('INFO', "Starting firewall application")
            
            # Set up initial firewall rules
            self.setup_default_rules()
            
            # Create a separate thread for packet capture
            capture_thread = threading.Thread(
                target=self.packet_handler.start_capture
            )
            capture_thread.daemon = True  # Thread will stop when main program exits
            capture_thread.start()
            
            print("Firewall is running. Press Ctrl+C to stop.")
            
            # Keep the main thread alive while monitoring both logging and capture
            while self.running:
                # Check capture thread status and process any pending logs
                capture_thread.join(1)
                
        except Exception as e:
            self.logger.queue_log('ERROR', f"Error in firewall operation: {str(e)}")
            self.running = False
            self.packet_handler.stop_capture()
            
            # Stop automatic logging before raising the exception
            self.logger.stop_automatic_logging()
            raise

def check_root():
    # Verify that the program is running with root privileges
    if os.geteuid() != 0:
        print("Error: This program must be run with root privileges!")
        print("Please try again using 'sudo python3 src/main.py'")
        sys.exit(1)

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