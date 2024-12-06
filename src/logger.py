import os
import logging
from datetime import datetime
import pathlib
import time
import threading
from queue import Queue, Empty

class FirewallLogger:
    """
    A thread-safe logging system for firewall operations that automatically processes
    log messages in the background. This class handles log file creation, message
    queuing, and asynchronous writing to prevent blocking operations.
    """
    def __init__(self, log_directory='logs'):
        """
        Initialize the logging system with proper directory handling and background
        processing capabilities.

        Args:
            log_directory (str): The directory where log files will be stored.
                               Defaults to 'logs' in the project root.
        """
        # Queue to store messages for asynchronous processing
        self.log_queue = Queue()
        
        # Control flag for the background logging thread
        self.is_running = False
        
        # Set up the log directory path and create logging infrastructure
        self.log_directory = self._ensure_absolute_path(log_directory)
        self._setup_logging()
        
        # Begin automatic logging as soon as the instance is created
        self.start_automatic_logging()
    
    def _ensure_absolute_path(self, directory):
        """
        Convert a relative path to an absolute path from the project root.
        This ensures logs are stored in a consistent location regardless of
        where the script is run from.

        Args:
            directory (str): The relative directory path.

        Returns:
            str: The absolute path to the log directory.
        """
        project_root = pathlib.Path(__file__).parent.parent
        return os.path.join(project_root, directory)
    
    def _setup_logging(self):
        """
        Configure the logging system with proper directory creation and formatting.
        Creates a new log file with a timestamp and sets up both file and console
        output handlers.
        """
        try:
            # Ensure the log directory exists
            os.makedirs(self.log_directory, exist_ok=True)
            
            # Create a timestamped log filename for this session
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_filename = os.path.join(
                self.log_directory,
                f'firewall_{timestamp}.log'
            )
            
            # Reset any existing logging configuration
            logging.getLogger().handlers = []
            
            # Configure logging with both file and console output
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
                handlers=[
                    logging.FileHandler(log_filename),
                    logging.StreamHandler()  # Also print to console
                ]
            )
            
            # Create a logger instance for this class
            self.logger = logging.getLogger(__name__)
            self.logger.info(f"Logging initialized. Writing to: {log_filename}")
            
        except Exception as e:
            print(f"Error setting up logging: {str(e)}")
            print(f"Attempted to create log directory at: {self.log_directory}")
            raise

    def start_automatic_logging(self):
        """
        Start the background thread that processes queued log messages.
        This method ensures only one logging thread is running at a time.
        """
        if not self.is_running:
            self.is_running = True
            self.logging_thread = threading.Thread(target=self._automatic_logging_worker)
            self.logging_thread.daemon = True  # Thread will stop when main program stops
            self.logging_thread.start()
            self.logger.info("Automatic logging started")

    def stop_automatic_logging(self):
        """
        Gracefully stop the automatic logging thread and process any remaining
        messages in the queue.
        """
        self.is_running = False
        if hasattr(self, 'logging_thread'):
            self.logging_thread.join()
            self.logger.info("Automatic logging stopped")

    def _automatic_logging_worker(self):
        """
        Background worker that continuously processes messages from the log queue.
        This method runs in a separate thread and handles the actual logging
        operations.
        """
        while self.is_running:
            try:
                # Attempt to get a message from the queue, waiting up to 1 second
                try:
                    log_entry = self.log_queue.get(timeout=1)
                    level, message = log_entry
                    
                    # Process the message based on its log level
                    if level == 'INFO':
                        self.logger.info(message)
                    elif level == 'WARNING':
                        self.logger.warning(message)
                    elif level == 'ERROR':
                        self.logger.error(message)
                    elif level == 'PACKET':
                        self.log_packet(message)
                        
                    self.log_queue.task_done()
                except Empty:
                    continue  # No messages in queue, continue waiting
                    
            except Exception as e:
                self.logger.error(f"Error in logging worker: {str(e)}")
                time.sleep(1)  # Prevent tight loop in case of repeated errors

    def queue_log(self, level, message):
        """
        Add a log message to the processing queue.
        
        Args:
            level (str): The log level ('INFO', 'WARNING', 'ERROR', 'PACKET')
            message (str): The message to be logged
        """
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
        """
        Log packet information in a standardized format.
        
        Args:
            packet_info (dict or str): Either a dictionary containing packet details
                                     or a string message to log directly
        """
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

# Example usage and testing code
def main():
    """
    Example usage of the FirewallLogger class.
    """
    try:
        # Create logger instance
        logger = FirewallLogger()
        
        # Example logging
        logger.log_info("Firewall system initialized")
        
        # Example packet data
        packet = {
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'protocol': 'TCP'
        }
        logger.queue_log('PACKET', packet)
        
        # Keep the program running to demonstrate automatic logging
        print("Logger is running. Press Ctrl+C to stop...")
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nShutting down logger...")
        logger.log_info("System shutdown initiated")
        logger.stop_automatic_logging()
        time.sleep(1)  # Give time for final messages to be processed

if __name__ == "__main__":
    main()