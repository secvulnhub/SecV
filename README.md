# SecV - The Polyglot Cybersecurity Orchestration Platform

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-%3E%3D1.19-blue.svg)](https://golang.org/)
[![PowerShell](https://img.shields.io/badge/powershell-%3E%3D7.0-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Community](https://img.shields.io/badge/community-SecVulnHub-green.svg)](https://github.com/SecVulnHub)

SecV is a next-generation cybersecurity orchestration platform designed for performance, flexibility, and collaboration. Execute security tools and orchestrate sophisticated workflows from a unified engine that supports multiple programming languages and execution environments.

## 🚀 Features

### Core Platform Capabilities
- **Polyglot Module Support**: Write security modules in PowerShell, Python, Bash, Go, or any executable format
- **Unified Execution Engine**: Single command-line interface for all your security tools
- **Advanced Workflow Orchestration**: Chain modules together with conditional logic and error handling
- **Interactive Mode**: User-friendly interactive interface for ad-hoc security testing
- **Concurrent Execution**: Run multiple modules simultaneously for faster assessments
- **Timeout Management**: Built-in timeout controls to prevent hanging operations
- **Rich Output Formatting**: Structured JSON output with detailed execution metadata

### Developer-Friendly Architecture
- **Module Generator**: Automated scaffolding for new security modules
- **Template System**: Pre-built templates for common programming languages
- **Dependency Management**: Automatic dependency validation and tracking
- **Standardized I/O**: Consistent input/output format across all modules
- **Comprehensive Logging**: Detailed execution logs for debugging and auditing

## 📦 Installation

### Prerequisites
- **Go 1.19+** for the main SecV engine
- **PowerShell 7.0+** for PowerShell modules and the module generator
- **jq** for JSON processing (Linux/macOS)

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/SecVulnHub/SecV.git
cd SecV

# Initialize the platform
go run secv.go init

# Verify installation
go run secv.go list
```

### Platform-Specific Installation

#### Windows
```powershell
# Ensure PowerShell 7+ is installed
winget install Microsoft.PowerShell

# Run the PowerShell module generator
.\New-SecVModule.ps1
```

#### Linux/macOS
```bash
# Install jq for JSON processing
# Ubuntu/Debian
sudo apt-get install jq

# macOS
brew install jq

# Make scripts executable
chmod +x tools/*/*.sh
```

## 🏗️ Architecture

SecV follows a modular architecture that promotes flexibility and extensibility:

### Module Structure
Each SecV module consists of three core components:

1. **module.json**: Configuration file defining module metadata, inputs, outputs, and execution parameters
2. **Executable**: The actual implementation in your preferred language (PowerShell, Python, Bash, Go, etc.)
3. **README.md**: Documentation explaining usage, inputs, outputs, and examples

### Execution Flow
The SecV engine handles the complete execution lifecycle:

1. **Module Discovery**: Scans the `tools/` directory for valid modules
2. **Validation**: Verifies module configuration and executable accessibility  
3. **Context Preparation**: Serializes execution context to JSON format
4. **Execution**: Launches module with timeout and error handling
5. **Result Processing**: Parses and validates module output
6. **Reporting**: Presents results in human-readable format

### Workflow Engine
For complex security assessments, SecV supports sophisticated workflows:

- **Sequential Execution**: Run modules in a specific order
- **Conditional Logic**: Execute modules based on previous results
- **Error Handling**: Define behavior when modules fail (continue, stop, retry)
- **Data Flow**: Pass results between modules automatically
- **Parallel Processing**: Execute independent modules concurrently

## 🛠️ Usage Guide

### Basic Module Execution
Execute a single security module against a target:

```bash
# Run a port scan module
go run secv.go execute port-scanner --target 192.168.1.1

# Run with custom parameters
go run secv.go execute web-scanner --target https://example.com --params '{"depth": 3, "timeout": 30}'
```

### Interactive Mode
Launch SecV in interactive mode for guided security testing:

```bash
go run secv.go interactive
```

The interactive mode provides:
- Module selection from available options
- Guided parameter input
- Real-time result display
- Module information and documentation

### Workflow Execution
Execute complex multi-stage security assessments:

```bash
# Run a predefined workflow
go run secv.go workflow workflows/comprehensive-scan.json --target 192.168.1.0/24

# Workflow with global parameters
go run secv.go workflow workflows/web-assessment.json --target https://example.com --params '{"aggressive": true}'
```

### Module Management
List and inspect available modules:

```bash
# List all modules
go run secv.go list

# Get detailed module information
go run secv.go info nmap-scanner
```

## 📝 Creating Modules

### Using the PowerShell Generator
The PowerShell module generator provides the fastest way to create new modules:

```powershell
# Run the interactive generator
.\New-SecVModule.ps1

# Follow the prompts to configure your module
```

The generator will create:
- Complete directory structure
- Template executable in your chosen language
- Properly formatted module.json configuration
- Documentation template

### Manual Module Creation
For advanced users, modules can be created manually by following the SecV module specification:

1. Create a directory in `tools/your-module-name/`
2. Add a `module.json` configuration file
3. Implement your executable following SecV I/O conventions
