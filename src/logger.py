import os
import logging
from datetime import datetime
import pathlib
import time
import threading
from queue import Queue

class FirewallLogger:
    def __init__(self, log_directory='logs'):
        """Initialize the logging system with proper directory handling"""
        # Queue to store messages that need to be logged
        self.log_queue = Queue()
        
        # Flag to control the automatic logging thread
        self.is_running = False
        
        # Convert to absolute path from project root
        self.log_directory = self._ensure_absolute_path(log_directory)
        self._setup_logging()
        
        # Start the automatic logging thread
        self.start_automatic_logging()
    
    def _ensure_absolute_path(self, directory):
        """Convert relative path to absolute path from project root"""
        project_root = pathlib.Path(__file__).parent.parent
        return os.path.join(project_root, directory)
    
    def _setup_logging(self):
        """Configure the logging system with proper directory creation"""
        try:
            # Create logs directory if it doesn't exist
            os.makedirs(self.log_directory, exist_ok=True)
            
            # Create log filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_filename = os.path.join(
                self.log_directory,
                f'firewall_{timestamp}.log'
            )
            
            # Configure logging with both file and console output
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
                handlers=[
                    logging.FileHandler(log_filename),
                    logging.StreamHandler()  # Also print to console
                ]
            )
            
            self.logger = logging.getLogger(__name__)
            self.logger.info(f"Logging initialized. Writing to: {log_filename}")
            
        except Exception as e:
            print(f"Error setting up logging: {str(e)}")
            print(f"Attempted to create log directory at: {self.log_directory}")
            raise

    def start_automatic_logging(self):
        """Start the automatic logging thread"""
        if not self.is_running:
            self.is_running = True
            self.logging_thread = threading.Thread(target=self._automatic_logging_worker)
            self.logging_thread.daemon = True  # Thread will stop when main program stops
            self.logging_thread.start()
            self.logger.info("Automatic logging started")

    def stop_automatic_logging(self):
        """Stop the automatic logging thread"""
        self.is_running = False
        if hasattr(self, 'logging_thread'):
            self.logging_thread.join()
            self.logger.info("Automatic logging stopped")

    def _automatic_logging_worker(self):
        """Worker function that processes the log queue"""
        while self.is_running:
            try:
                # Get message from queue if available, wait up to 1 second
                try:
                    log_entry = self.log_queue.get(timeout=1)
                    level, message = log_entry
                    
                    # Log the message with appropriate level
                    if level == 'INFO':
                        self.logger.info(message)
                    elif level == 'WARNING':
                        self.logger.warning(message)
                    elif level == 'ERROR':
                        self.logger.error(message)
                    elif level == 'PACKET':
                        self.log_packet(message)
                        
                    self.log_queue.task_done()
                except Queue.Empty:
                    continue  # No messages in queue, continue waiting
                    
            except Exception as e:
                self.logger.error(f"Error in logging worker: {str(e)}")
                time.sleep(1)  # Prevent tight loop in case of repeated errors

    def queue_log(self, level, message):
        """Add a log message to the queue"""
        self.log_queue.put((level, message))

    def log_info(self, message):
        """Queue an informational message"""
        self.queue_log('INFO', message)
    
    def log_warning(self, message):
        """Queue a warning message"""
        self.queue_log('WARNING', message)
    
    def log_error(self, message):
        """Queue an error message"""
        self.queue_log('ERROR', message)
    
    def log_packet(self, packet_info):
        """Log packet information"""
        if isinstance(packet_info, dict):
            message = (
                f"Packet captured - "
                f"Source: {packet_info.get('src_ip', 'Unknown')}, "
                f"Destination: {packet_info.get('dst_ip', 'Unknown')}, "
                f"Protocol: {packet_info.get('protocol', 'Unknown')}"
            )
            self.logger.info(message)
        else:
            self.logger.info(str(packet_info))