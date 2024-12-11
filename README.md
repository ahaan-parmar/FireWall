# Python Network Firewall

A robust Python-based network firewall implementation that provides real-time packet capture, analysis, and filtering capabilities. This project demonstrates fundamental concepts of network security and traffic monitoring while providing a foundation for building more advanced security tools.

## Features

This firewall implementation includes several key capabilities that make it a valuable tool for network monitoring and security:

- **Stateful Packet Inspection**: Advanced connection tracking for both TCP and UDP traffic, ensuring secure and reliable communications.
- **Rule-Based Filtering**: Configurable YAML-based rules system for precise traffic control.
- **Real-Time Monitoring**: Active packet capture and analysis using Scapy for deep protocol inspection.
- **Comprehensive Logging**: Detailed logging of all network activities with timestamps and traffic patterns.
- **Modular Architecture**: Well-structured codebase allowing easy extension and modification.

## Prerequisites

Before you begin working with this firewall, ensure you have the following prerequisites installed:

- Python 3.x
- Root/Administrator privileges
- Virtual environment support
- Git for version control

The project has the following package dependencies:
- Scapy for packet capture and analysis
- PyYAML for configuration management
- Python-logging for comprehensive logging capabilities

## Installation

Follow these steps to get the firewall up and running on your system:

```bash
# Clone the repository
git clone https://github.com/yourusername/FireWall.git
cd FireWall

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install required packages
pip install scapy pyyaml
```

## Configuration

Create a rules.yaml file in the config directory:

```yaml
rules:
  - action: allow
    protocol: tcp
    destination_port: 80
    description: "Allow HTTP traffic"
    priority: 100

  - action: allow
    protocol: tcp
    destination_port: 443
    description: "Allow HTTPS traffic"
    priority: 100

  - action: allow
    protocol: udp
    destination_port: 53
    description: "Allow DNS queries"
    priority: 90

  - action: allow
    protocol: any
    source_ip: "192.168.1.0/24"
    description: "Allow local network traffic"
    priority: 80
```

## Usage

To start the firewall, ensure you're in the project directory and run:

```bash
# Activate the virtual environment if not already active
source venv/bin/activate

# Start the firewall (requires root privileges)
sudo python3 src/main.py
```

To monitor the firewall's operation in real-time:

```bash
# In a separate terminal
tail -f logs/firewall_*.log
```

## Project Structure

The project is organized into several key components:

```
FireWall/
├── src/
│   ├── main.py           # Main application entry point
│   ├── packethandler.py  # Packet capture and processing
│   ├── logger.py         # Logging system
│   ├── firewall_rules.py # Rule management system
│   └── rule_config.py    # Configuration handling
├── config/
│   └── rules.yaml        # Firewall rules configuration
├── logs/                 # Log file directory
└── README.md            # Project documentation
```

## Implementation Details

The firewall features three main components:

1. **Packet Handler**: 
   - Network traffic interception using Scapy
   - Stateful connection tracking
   - Multi-threaded packet processing
   - Protocol-specific handling (TCP, UDP, DNS)

2. **Logger System**: 
   - Thread-safe logging
   - Comprehensive event tracking
   - Both file and console output
   - Timestamped entries

3. **Rule Management**: 
   - YAML-based configuration
   - Priority-based rule processing
   - Flexible filtering criteria
   - Default-deny security policy

## Security Considerations

When using this firewall, keep in mind several important security considerations:

- The system requires root privileges for packet capture
- Always run in a controlled environment
- Regularly monitor and review log files
- Keep the system and dependencies updated
- Ensure proper rule configuration

## Future Development

Planned enhancements include:

- Web-based management interface
- Advanced traffic analysis
- Rate limiting capabilities
- IP blacklisting/whitelisting
- NAT support
- ICMP traffic handling

## Contributing

Contributions to improve the firewall are welcome. Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License 

## Acknowledgments

- The Scapy project for packet manipulation capabilities
- PyYAML for configuration management


