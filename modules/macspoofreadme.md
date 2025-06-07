# MAC Address Spoofer Modules

A comprehensive collection of cross-platform MAC address spoofing utilities implemented in three different languages, each optimized for specific environments and use cases.

## Overview

MAC address spoofing allows you to temporarily change your network interface's hardware address, which can be useful for network testing, privacy protection, or troubleshooting connectivity issues. These modules provide robust, cross-platform solutions with comprehensive validation and error handling.

## Module Comparison

### Bash Version (`macpoof.sh`)
**Best for**: Unix-like systems, lightweight deployment, shell scripting integration

The Bash implementation provides excellent compatibility across Unix-like operating systems and requires no compilation or additional dependencies. It automatically detects your system's network utilities and adapts accordingly, supporting both modern `ip` commands and legacy `ifconfig` implementations.

**Key Features:**
- Automatic OS detection and command adaptation
- Support for both colon and dash MAC address formats
- Random MAC address generation with locally administered addressing
- Comprehensive interface validation using system commands
- Fallback mechanisms for different Unix variants

**Supported Systems:**
- Linux (all distributions with bash)
- macOS and BSD variants
- WSL and Cygwin environments
- Most POSIX-compliant Unix systems

### Go Version (`macpoof.go`)
**Best for**: Cross-platform deployment, performance-critical applications, standalone executables

The Go implementation leverages Go's excellent cross-platform capabilities and native network interface handling. It compiles to a single binary that runs on multiple architectures without requiring runtime dependencies, making it ideal for deployment across diverse environments.

**Key Features:**
- Native network interface detection using Go's `net` package
- Single binary deployment with no external dependencies
- Comprehensive error handling and user experience
- Automatic command detection and OS-specific optimization
- Memory-safe implementation with excellent performance

**Supported Systems:**
- Linux (all architectures supported by Go)
- macOS (Intel and Apple Silicon)
- Windows (with appropriate privileges)
- BSD systems and other Unix variants
- Any platform with Go runtime support

### PowerShell Version (`macpoof.ps1`)
**Best for**: Windows environments, enterprise administration, rich system integration

The PowerShell implementation provides deep Windows integration using WMI and registry manipulation techniques. It offers the most comprehensive Windows support while maintaining compatibility with PowerShell Core on other platforms.

**Key Features:**
- Native Windows registry manipulation for MAC address changes
- WMI-based network adapter management
- Rich object-oriented interface information
- Comprehensive privilege checking and validation
- Support for both Windows PowerShell and PowerShell Core

**Supported Systems:**
- Windows (all versions with PowerShell)
- Linux and macOS (with PowerShell Core 6+)
- Any system running PowerShell Core

## Installation and Usage

### Bash Version
```bash
# Make the script executable
chmod +x macpoof.sh

# Run with root privileges
sudo ./macpoof.sh

# The script will guide you through interface selection and MAC address configuration
```

### Go Version
```bash
# Compile the binary (one-time setup)
go build -o macpoof macpoof.go

# Run the compiled binary
sudo ./macpoof

# The program provides an interactive interface for configuration
```

### PowerShell Version
```powershell
# Run PowerShell as Administrator (Windows)
# Or with appropriate privileges on other systems

# Interactive mode
.\macpoof.ps1

# Command-line mode with parameters
.\macpoof.ps1 -List
.\macpoof.ps1 -Interface "Ethernet" -MacAddress "aa:bb:cc:dd:ee:ff"
.\macpoof.ps1 -Interface "Wi-Fi" -Random
```

## Security Considerations

Understanding the security implications of MAC address spoofing is crucial for responsible usage. These tools require elevated privileges because they modify low-level network interface settings, which operating systems protect to maintain system stability and security.

**Privilege Requirements:**
- Linux and Unix systems require root access or sudo privileges
- Windows requires administrator privileges for registry modifications
- macOS requires admin access for network interface changes

**Legal and Ethical Usage:**
- MAC spoofing legality varies by jurisdiction and intended use
- Always ensure you have permission to modify network interfaces
- Use these tools only on networks you own or have explicit permission to test
- Be aware that network administrators may have policies against MAC spoofing

## Technical Implementation Details

### Validation and Error Handling
All three implementations include comprehensive input validation to prevent common errors and ensure reliable operation. The MAC address validation uses regular expressions that support both colon-separated and dash-separated formats, automatically normalizing them to the standard colon format.

### Random MAC Generation
When generating random MAC addresses, all implementations ensure the generated addresses are locally administered by setting the appropriate bits in the first octet. This prevents conflicts with manufacturer-assigned addresses and follows IEEE standards for locally administered addresses.

### Cross-Platform Compatibility
Each implementation handles platform-specific differences in network interface management. The code automatically detects available system utilities and adapts its behavior accordingly, providing consistent functionality across different operating systems.

## Troubleshooting

### Common Issues and Solutions

**Permission Denied Errors:**
- Ensure you're running with appropriate privileges (root/sudo/administrator)
- Some systems require specific group memberships for network interface access

**Interface Not Found:**
- Verify interface names using system tools like `ip link show` or `ifconfig`
- Interface names may differ between systems (eth0, enp3s0, wlan0, etc.)

**MAC Address Not Changing:**
- Some network hardware doesn't support MAC address modification
- Driver limitations may prevent changes on certain adapters
- Network interfaces may need to be brought down and up again

**Windows-Specific Issues:**
- Some Windows versions have additional security restrictions
- Enterprise policies may prevent MAC address modifications
- Certain network adapters require specific registry modifications

## Best Practices

When using these MAC spoofing tools, consider these recommendations for optimal results and security. Always test changes in a controlled environment before using them in production scenarios, and maintain documentation of original MAC addresses for easy restoration.

Create backup procedures for your original network configuration, especially when making changes to critical network interfaces. Consider the impact on network-dependent services and applications before making modifications.

For enterprise environments, coordinate with network administrators to ensure MAC address changes don't conflict with network access controls or monitoring systems.

## Contributing

These modules are designed to be educational and practical tools for network administration and testing. If you encounter issues or have suggestions for improvements, consider the specific requirements of your target platform and the intended use cases for each implementation.

When extending functionality, maintain the existing validation patterns and error handling approaches to ensure consistency across all modules.
