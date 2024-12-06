import logging
import os
from datetime import datetime

class FirewallLogger:
    def __init__(self, log_directory='logs'):
        #Initialize the logging system with specified directory
        self.log_directory = log_directory
        self._setup_logging()
    
    def _setup_logging(self):
        #Configure the logging system with proper formatting and handlers
        # Create logs directory if it doesn't exist
        if not os.path.exists(self.log_directory):
            os.makedirs(self.log_directory)
            
        # Create log filename with timestamp
        log_filename = os.path.join(
            self.log_directory,
            f'firewall_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
        )
        
        # Configure logging format
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            handlers=[
                logging.FileHandler(log_filename),
                logging.StreamHandler()  # Also print to console
            ]
        )
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("Logging system initialized")
    
    def log_packet(self, packet_info):
        #Log packet information with appropriate level
        try:
            self.logger.info(
                f"Packet captured - "
                f"Source: {packet_info.get('src_ip', 'Unknown')}, "
                f"Destination: {packet_info.get('dst_ip', 'Unknown')}, "
                f"Protocol: {packet_info.get('protocol', 'Unknown')}"
            )
        except Exception as e:
            self.logger.error(f"Error logging packet: {str(e)}")
    
    def log_error(self, error_message):
        #Log error messages
        self.logger.error(f"Error: {error_message}")
    
    def log_warning(self, warning_message):
        #Log warning messages
        self.logger.warning(f"Warning: {warning_message}")
    
    def log_info(self, info_message):
        #Log informational messages
        self.logger.info(info_message)