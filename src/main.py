import os
import sys
import signal
from packethandler import PacketHandler
import threading

class FirewallApplication:
    def __init__(self):
        """Initialize the firewall application"""
        self.packet_handler = PacketHandler()
        self.capture_thread = None
        
    def signal_handler(self, signum, frame):
        """Handle system signals for graceful shutdown"""
        print("\nShutting down firewall...")
        self.packet_handler.stop_capture()
        sys.exit(0)
        
    def start(self):
        """Start the firewall application"""
        # Register signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        try:
            # Start packet capture in a separate thread
            self.capture_thread = threading.Thread(
                target=self.packet_handler.start_capture
            )
            self.capture_thread.start()
            
            print("Firewall is running. Press Ctrl+C to stop.")
            self.capture_thread.join()
            
        except Exception as e:
            print(f"Error starting firewall: {str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    # Check for root privileges
    if os.geteuid() != 0:
        print("This program must be run as root!")
        sys.exit(1)
        
    app = FirewallApplication()
    app.start()