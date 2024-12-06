import os
import sys
import signal
import threading
from packethandler import PacketHandler
from firewall_rules import RuleManager, Action, Protocol
from logger import FirewallLogger

class FirewallApplication:
    """
    Main firewall application class that coordinates all components and handles
    user interrupts and system signals.
    """
    def __init__(self, interface="eth0"):
        # Initialize our core components
        self.logger = FirewallLogger()
        self.packet_handler = PacketHandler(interface=interface)
        self.running = False
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.handle_shutdown)
        signal.signal(signal.SIGTERM, self.handle_shutdown)
        
        # Log application startup
        self.logger.log_info("Firewall application initialized")
        
    def setup_default_rules(self):
        #Configure initial firewall rules
        rule_manager = self.packet_handler.rule_manager
        
        # Allow established connections
        rule_manager.add_rule(
            action=Action.ALLOW,
            protocol=Protocol.ANY,
            description="Allow established connections"
        )
        
        # Allow local network traffic
        rule_manager.add_rule(
            action=Action.ALLOW,
            protocol=Protocol.ANY,
            source_ip="192.168.1.0/24",
            description="Allow local network traffic"
        )
        
        # Block incoming SSH attempts
        rule_manager.add_rule(
            action=Action.DENY,
            protocol=Protocol.TCP,
            destination_port=22,
            description="Block incoming SSH connections"
        )
        
        # Log rule setup completion
        self.logger.log_info("Default firewall rules configured")

    def handle_shutdown(self, signum, frame):
        #Handle shutdown signals
        print("\nReceived shutdown signal. Stopping firewall...")
        self.running = False
        self.packet_handler.stop_capture()
        self.logger.log_info("Firewall shutdown complete")
        sys.exit(0)

    def start(self):
        try:
            self.running = True
            self.logger.log_info("Starting firewall application")
            
            # Set up initial firewall rules
            self.setup_default_rules()
            
            # Create a separate thread for packet capture
            capture_thread = threading.Thread(
                target=self.packet_handler.start_capture
            )
            capture_thread.daemon = True  # Thread will stop when main program exits
            capture_thread.start()
            
            print("Firewall is running. Press Ctrl+C to stop.")
            
            # Keep the main thread alive and responsive to signals
            while self.running:
                capture_thread.join(1)  # Check status every second
                
        except Exception as e:
            self.logger.log_error(f"Error in firewall operation: {str(e)}")
            self.running = False
            self.packet_handler.stop_capture()
            raise

def check_root():
    #Verify that the program is running with root privileges
    if os.geteuid() != 0:
        print("Error: This program must be run with root privileges!")
        print("Please try again using 'sudo python3 src/main.py'")
        sys.exit(1)

def main():
    """
    Main entry point for the firewall application.
    Handles initial setup and program execution.
    """
    # Verify root privileges
    check_root()
    
    try:
        # Create and start the firewall application
        app = FirewallApplication(interface="eth0")  # Adjust interface as needed
        app.start()
        
    except KeyboardInterrupt:
        print("\nFirewall stopped by user")
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()