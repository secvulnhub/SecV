package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// OSCommands holds the commands needed for different operating systems
type OSCommands struct {
	OSType    string
	ListCmd   []string
	DownCmd   []string
	SetMACCmd []string
	UpCmd     []string
}

// MACSpoofer represents our MAC spoofing utility
type MACSpoofer struct {
	commands OSCommands
	reader   *bufio.Reader
}

// NewMACSpoofer creates a new MAC spoofer instance with OS-specific commands
func NewMACSpoofer() *MACSpoofer {
	ms := &MACSpoofer{
		reader: bufio.NewReader(os.Stdin),
	}
	ms.detectOS()
	return ms
}

// detectOS determines the operating system and sets appropriate commands
func (ms *MACSpoofer) detectOS() {
	switch runtime.GOOS {
	case "linux":
		ms.commands = OSCommands{
			OSType:    "Linux",
			ListCmd:   []string{"ip", "link", "show"},
			DownCmd:   []string{"ip", "link", "set", "dev"},
			SetMACCmd: []string{"ip", "link", "set", "dev"},
			UpCmd:     []string{"ip", "link", "set", "dev"},
		}
		// Check if ip command is available, fallback to ifconfig
		if !ms.commandExists("ip") {
			if ms.commandExists("ifconfig") {
				ms.commands.ListCmd = []string{"ifconfig", "-a"}
				ms.commands.DownCmd = []string{"ifconfig"}
				ms.commands.SetMACCmd = []string{"ifconfig"}
				ms.commands.UpCmd = []string{"ifconfig"}
			}
		}
	case "darwin":
		ms.commands = OSCommands{
			OSType:    "macOS",
			ListCmd:   []string{"ifconfig", "-a"},
			DownCmd:   []string{"ifconfig"},     // macOS doesn't require down/up for MAC change
			SetMACCmd: []string{"ifconfig"},
			UpCmd:     []string{"ifconfig"},
		}
	case "freebsd", "openbsd", "netbsd":
		ms.commands = OSCommands{
			OSType:    "BSD",
			ListCmd:   []string{"ifconfig", "-a"},
			DownCmd:   []string{"ifconfig"},
			SetMACCmd: []string{"ifconfig"},
			UpCmd:     []string{"ifconfig"},
		}
	case "windows":
		ms.commands = OSCommands{
			OSType:    "Windows",
			ListCmd:   []string{"getmac", "/v"},
			DownCmd:   []string{},     // Windows uses different approach
			SetMACCmd: []string{},     // Will use netsh or registry
			UpCmd:     []string{},
		}
	default:
		ms.commands = OSCommands{
			OSType:    "Unknown",
			ListCmd:   []string{"ifconfig", "-a"},
			DownCmd:   []string{"ifconfig"},
			SetMACCmd: []string{"ifconfig"},
			UpCmd:     []string{"ifconfig"},
		}
	}
}

// commandExists checks if a command is available in the system PATH
func (ms *MACSpoofer) commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// validateMAC validates MAC address format and normalizes it
func (ms *MACSpoofer) validateMAC(mac string) (string, bool) {
	// Remove any whitespace and convert to lowercase
	mac = strings.ToLower(strings.TrimSpace(mac))
	
	// MAC address regex patterns
	colonPattern := regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`)
	dashPattern := regexp.MustCompile(`^([0-9a-f]{2}-){5}[0-9a-f]{2}$`)
	
	if colonPattern.MatchString(mac) {
		return mac, true
	} else if dashPattern.MatchString(mac) {
		// Convert dash format to colon format
		normalized := strings.ReplaceAll(mac, "-", ":")
		return normalized, true
	}
	
	return "", false
}

// getNetworkInterfaces returns a list of available network interfaces
func (ms *MACSpoofer) getNetworkInterfaces() ([]net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	
	// Filter out loopback and down interfaces
	var validInterfaces []net.Interface
	for _, iface := range interfaces {
		// Skip loopback interfaces
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		validInterfaces = append(validInterfaces, iface)
	}
	
	return validInterfaces, nil
}

// listInterfaces displays available network interfaces
func (ms *MACSpoofer) listInterfaces() {
	interfaces, err := ms.getNetworkInterfaces()
	if err != nil {
		fmt.Printf("Error getting interfaces: %v\n", err)
		return
	}
	
	fmt.Println("Available network interfaces:")
	for _, iface := range interfaces {
		status := "down"
		if iface.Flags&net.FlagUp != 0 {
			status = "up"
		}
		fmt.Printf("  %s (MAC: %s, Status: %s)\n", iface.Name, iface.HardwareAddr.String(), status)
	}
}

// validateInterface checks if the specified interface exists
func (ms *MACSpoofer) validateInterface(name string) (*net.Interface, bool) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, false
	}
	
	// Check if it's not a loopback interface
	if iface.Flags&net.FlagLoopback != 0 {
		return nil, false
	}
	
	return iface, true
}

// generateRandomMAC creates a random locally administered MAC address
func (ms *MACSpoofer) generateRandomMAC() string {
	// Seed the random number generator
	rand.Seed(time.Now().UnixNano())
	
	// Generate 6 random bytes
	mac := make([]byte, 6)
	rand.Read(mac)
	
	// Set the locally administered bit (bit 1 of first byte) to 1
	// and ensure it's unicast (bit 0 of first byte) by setting it to 0
	mac[0] = (mac[0] | 0x02) & 0xFE
	
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", 
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// changeMACAddress performs the actual MAC address change
func (ms *MACSpoofer) changeMACAddress(interfaceName, newMAC string) error {
	switch ms.commands.OSType {
	case "Linux":
		return ms.changeMACLinux(interfaceName, newMAC)
	case "macOS":
		return ms.changeMACMacOS(interfaceName, newMAC)
	case "BSD":
		return ms.changeMACBSD(interfaceName, newMAC)
	case "Windows":
		return ms.changeMACWindows(interfaceName, newMAC)
	default:
		return ms.changeMACGeneric(interfaceName, newMAC)
	}
}

// changeMACLinux handles MAC address change on Linux systems
func (ms *MACSpoofer) changeMACLinux(interfaceName, newMAC string) error {
	var commands [][]string
	
	if ms.commandExists("ip") {
		// Use modern ip command
		commands = [][]string{
			{"ip", "link", "set", "dev", interfaceName, "down"},
			{"ip", "link", "set", "dev", interfaceName, "address", newMAC},
			{"ip", "link", "set", "dev", interfaceName, "up"},
		}
	} else {
		// Fall back to ifconfig
		commands = [][]string{
			{"ifconfig", interfaceName, "down"},
			{"ifconfig", interfaceName, "hw", "ether", newMAC},
			{"ifconfig", interfaceName, "up"},
		}
	}
	
	return ms.executeCommands(commands)
}

// changeMACMacOS handles MAC address change on macOS
func (ms *MACSpoofer) changeMACMacOS(interfaceName, newMAC string) error {
	// macOS can change MAC without bringing interface down
	commands := [][]string{
		{"ifconfig", interfaceName, "ether", newMAC},
	}
	
	return ms.executeCommands(commands)
}

// changeMACBSD handles MAC address change on BSD systems
func (ms *MACSpoofer) changeMACBSD(interfaceName, newMAC string) error {
	commands := [][]string{
		{"ifconfig", interfaceName, "down"},
		{"ifconfig", interfaceName, "ether", newMAC},
		{"ifconfig", interfaceName, "up"},
	}
	
	return ms.executeCommands(commands)
}

// changeMACWindows handles MAC address change on Windows (basic implementation)
func (ms *MACSpoofer) changeMACWindows(interfaceName, newMAC string) error {
	// Windows MAC changing is more complex and typically requires registry changes
	// This is a simplified version - real implementation would need more work
	fmt.Println("Windows MAC address changing requires administrative privileges and registry modification.")
	fmt.Println("Consider using the PowerShell version or a dedicated Windows utility.")
	return fmt.Errorf("windows MAC changing not fully implemented in this version")
}

// changeMACGeneric handles MAC address change for unknown systems
func (ms *MACSpoofer) changeMACGeneric(interfaceName, newMAC string) error {
	commands := [][]string{
		{"ifconfig", interfaceName, "down"},
		{"ifconfig", interfaceName, "ether", newMAC},
		{"ifconfig", interfaceName, "up"},
	}
	
	return ms.executeCommands(commands)
}

// executeCommands runs a series of system commands
func (ms *MACSpoofer) executeCommands(commands [][]string) error {
	for _, cmdArgs := range commands {
		if len(cmdArgs) == 0 {
			continue
		}
		
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to execute %v: %w", cmdArgs, err)
		}
	}
	return nil
}

// promptUser prompts the user for input with a message
func (ms *MACSpoofer) promptUser(message string) string {
	fmt.Print(message)
	input, _ := ms.reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// confirmAction asks the user for confirmation
func (ms *MACSpoofer) confirmAction(message string) bool {
	response := ms.promptUser(message + " (y/N): ")
	return strings.ToLower(response) == "y" || strings.ToLower(response) == "yes"
}

// checkPrivileges warns about privilege requirements
func (ms *MACSpoofer) checkPrivileges() bool {
	if ms.commands.OSType == "Windows" {
		return true // Windows handling is different
	}
	
	if os.Geteuid() != 0 {
		fmt.Println("Warning: This program typically requires root/administrator privileges.")
		fmt.Println("You may need to run with sudo or as administrator.")
		return ms.confirmAction("Continue anyway?")
	}
	return true
}

// run executes the main MAC spoofing workflow
func (ms *MACSpoofer) run() {
	fmt.Printf("Welcome to MACPOOF (Go version) %s\n", os.Getenv("USER"))
	fmt.Printf("Operating System: %s\n", ms.commands.OSType)
	
	// Check privileges
	if !ms.checkPrivileges() {
		fmt.Println("Exiting...")
		return
	}
	
	// List available interfaces
	fmt.Println()
	ms.listInterfaces()
	fmt.Println()
	
	// Get and validate interface
	var selectedInterface *net.Interface
	for {
		interfaceName := ms.promptUser("Input INTERFACE needed to modify > ")
		if iface, valid := ms.validateInterface(interfaceName); valid {
			selectedInterface = iface
			fmt.Printf("Interface %s found.\n", interfaceName)
			fmt.Printf("Current MAC address: %s\n", iface.HardwareAddr.String())
			break
		} else {
			fmt.Printf("Error: Interface '%s' not found or is not valid.\n", interfaceName)
			fmt.Println("Please check available interfaces above.")
		}
	}
	
	// Get and validate MAC address
	var newMAC string
	for {
		input := ms.promptUser("Input dummy MACADDRESS preferred (or 'random' for random MAC) > ")
		
		if strings.ToLower(input) == "random" {
			newMAC = ms.generateRandomMAC()
			fmt.Printf("Generated random MAC: %s\n", newMAC)
			break
		} else if normalized, valid := ms.validateMAC(input); valid {
			newMAC = normalized
			fmt.Printf("MAC address format is valid: %s\n", newMAC)
			break
		} else {
			fmt.Println("Error: Invalid MAC address format.")
			fmt.Println("Please use format like aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff")
			fmt.Println("Or type 'random' for a random MAC address.")
		}
	}
	
	// Confirm the change
	fmt.Println()
	fmt.Println("Ready to change MAC address:")
	fmt.Printf("  Interface: %s\n", selectedInterface.Name)
	fmt.Printf("  From: %s\n", selectedInterface.HardwareAddr.String())
	fmt.Printf("  To: %s\n", newMAC)
	fmt.Println()
	
	if !ms.confirmAction("Proceed with MAC address change?") {
		fmt.Println("MAC address change cancelled.")
		return
	}
	
	// Perform the MAC address change
	fmt.Println("Changing MAC address...")
	if err := ms.changeMACAddress(selectedInterface.Name, newMAC); err != nil {
		fmt.Printf("✗ Error: Failed to change MAC address: %v\n", err)
		fmt.Println("This could be due to:")
		fmt.Println("  - Insufficient privileges")
		fmt.Println("  - Hardware/driver limitations")
		fmt.Println("  - Interface in use by active connections")
		return
	}
	
	fmt.Println("MAC address change completed!")
	
	// Verify the change by checking the interface again
	if updatedInterface, err := net.InterfaceByName(selectedInterface.Name); err == nil {
		fmt.Printf("New MAC address: %s\n", updatedInterface.HardwareAddr.String())
		
		if updatedInterface.HardwareAddr.String() == newMAC {
			fmt.Println("✓ MAC address successfully changed!")
		} else {
			fmt.Println("⚠ Warning: MAC address may not have changed as expected.")
			fmt.Println("This could be due to hardware limitations or driver restrictions.")
		}
	}
	
	fmt.Println()
	fmt.Println("MACPOOF session completed.")
}

func main() {
	spoofer := NewMACSpoofer()
	spoofer.run()
}
