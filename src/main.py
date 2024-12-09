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
       #Load firewall rules from configuration file
       rules = self.config.load_rules()
       for rule in rules:
           self.packet_handler.add_rule(rule)
       self.logger.log_info(f"Loaded {len(rules)} rules from configuration")

   def handle_shutdown(self, signum, frame):
       #Handle shutdown signals gracefully
       print("\nReceived shutdown signal. Stopping firewall...")
       self.running = False
       self.packet_handler.stop_capture()
       self.logger.log_info("Firewall shutdown complete")
       sys.exit(0)

   def start(self):
       #Start the firewall application
       try:
           self.running = True
           self.logger.log_info("Starting firewall application")
           
           # Load config
           self.load_config()
           
           # Start packet capture in a separate thread
           capture_thread = threading.Thread(
               target=self.packet_handler.start_capture
           )
           capture_thread.daemon = True
           capture_thread.start()
           
           print("Firewall is running. Press Ctrl+C to stop.")
           
           #keep the main thread alive
           while self.running:
               capture_thread.join(1)
               
       except Exception as e:
           self.logger.log_error(f"Error in firewall operation: {str(e)}")
           self.running = False
           self.packet_handler.stop_capture()
           raise

def check_root():
   #Verify root/administrator privileges#
   if os.geteuid() != 0:
       print("Error: This program must be run with root privileges!")
       print("Please try again using 'sudo python3 src/main.py'")
       sys.exit(1)

def get_available_interface():
   #Get first available network interface#
   try:
       interfaces = os.listdir('/sys/class/net/')
       return 'eth0' if 'eth0' in interfaces else interfaces[0]
   except:
       return 'eth0'  
   # Fallback to eth0

def main():
   #Main entry point for the firewall application
   check_root()
   
   try:
       # Get available network interface
       interface = get_available_interface()
       
       # Create and start firewall application
       app = FirewallApplication(interface=interface)
       app.start()
       
   except KeyboardInterrupt:
       print("\nFirewall stopped by user")
   except Exception as e:
       print(f"Error: {str(e)}")
       sys.exit(1)

if __name__ == "__main__":
   main()