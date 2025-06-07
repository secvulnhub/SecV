#!/bin/bash

# SecV Module Generator - Bash Version
# This script helps contributors create new modules for the SecV platform
# Compatible with Linux and macOS systems

set -e  # Exit on any error

# Color codes for better user experience
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global variables to store module information
MODULE_NAME=""
MODULE_VERSION=""
MODULE_CATEGORY=""
MODULE_DESCRIPTION=""
MODULE_AUTHOR=""
MODULE_EXECUTABLE_TYPE=""
MODULE_TIMEOUT=""
MODULE_CONCURRENT=""
MODULE_DEPENDENCIES=()
MODULE_INPUTS=()
MODULE_OUTPUTS=()

# Function to print colored output
print_colored() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to print the welcome banner
print_banner() {
    print_colored $CYAN "╔══════════════════════════════════════════════════════════════╗"
    print_colored $CYAN "║                    SecV Module Generator                     ║"
    print_colored $CYAN "║              Create modules for SecV platform               ║"
    print_colored $CYAN "╚══════════════════════════════════════════════════════════════╝"
    echo
}

# Function to validate that input is not empty
validate_not_empty() {
    local input=$1
    local field_name=$2
    
    if [[ -z "$input" ]]; then
        print_colored $RED "❌ Error: $field_name cannot be empty"
        return 1
    fi
    return 0
}

# Function to validate module name (alphanumeric, hyphens, underscores)
validate_module_name() {
    local name=$1
    
    if [[ ! "$name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        print_colored $RED "❌ Error: Module name can only contain letters, numbers, hyphens, and underscores"
        return 1
    fi
    return 0
}

# Function to validate version format (semantic versioning)
validate_version() {
    local version=$1
    
    if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        print_colored $RED "❌ Error: Version must follow semantic versioning (e.g., 1.0.0)"
        return 1
    fi
    return 0
}

# Function to get user input with validation
get_input() {
    local prompt=$1
    local validator=$2
    local variable_name=$3
    local input=""
    
    while true; do
        echo -n "$prompt: "
        read input
        
        if [[ -n "$validator" ]]; then
            if $validator "$input" "$variable_name"; then
                break
            fi
        else
            if [[ -n "$input" ]]; then
                break
            else
                print_colored $RED "❌ This field is required"
            fi
        fi
    done
    
    echo "$input"
}

# Function to get yes/no input
get_yes_no() {
    local prompt=$1
    local default=$2
    local input=""
    
    while true; do
        echo -n "$prompt [y/N]: "
        read input
        
        if [[ -z "$input" ]]; then
            input=$default
        fi
        
        case $input in
            [Yy]|[Yy][Ee][Ss])
                echo "true"
                return
                ;;
            [Nn]|[Nn][Oo])
                echo "false"
                return
                ;;
            *)
                print_colored $RED "Please enter 'y' for yes or 'n' for no"
                ;;
        esac
    done
}

# Function to collect array input (dependencies, inputs, outputs)
collect_array_input() {
    local prompt=$1
    local description=$2
    local -n array_ref=$3
    
    print_colored $YELLOW "$description"
    echo "Enter items one by one (press Enter with empty input to finish):"
    
    local input=""
    local counter=1
    
    while true; do
        echo -n "  $counter. "
        read input
        
        if [[ -z "$input" ]]; then
            break
        fi
        
        array_ref+=("$input")
        ((counter++))
    done
}

# Function to collect input/output specifications
collect_io_specs() {
    local type=$1  # "input" or "output"
    local -n specs_ref=$2
    
    print_colored $YELLOW "Define $type specifications:"
    print_colored $BLUE "Format: name:type:description (e.g., 'target:string:IP address or hostname')"
    echo "Enter specifications one by one (press Enter with empty input to finish):"
    
    local input=""
    local counter=1
    
    while true; do
        echo -n "  $counter. "
        read input
        
        if [[ -z "$input" ]]; then
            break
        fi
        
        # Parse the input format: name:type:description
        IFS=':' read -ra parts <<< "$input"
        if [[ ${#parts[@]} -eq 3 ]]; then
            local spec_json="{\"name\":\"${parts[0]}\",\"type\":\"${parts[1]}\",\"description\":\"${parts[2]}\"}"
            specs_ref+=("$spec_json")
            ((counter++))
        else
            print_colored $RED "❌ Please use the format: name:type:description"
        fi
    done
}

# Function to create directory structure
create_directory_structure() {
    local base_dir="tools/$MODULE_NAME"
    
    if [[ -d "$base_dir" ]]; then
        print_colored $YELLOW "⚠️  Directory $base_dir already exists"
        local overwrite=$(get_yes_no "Do you want to overwrite it?" "n")
        
        if [[ "$overwrite" == "false" ]]; then
            print_colored $RED "❌ Module generation cancelled"
            exit 1
        fi
        
        rm -rf "$base_dir"
    fi
    
    mkdir -p "$base_dir"
    print_colored $GREEN "✅ Created directory: $base_dir"
}

# Function to generate module.json
generate_module_json() {
    local json_file="tools/$MODULE_NAME/module.json"
    
    # Build the JSON structure
    cat > "$json_file" << EOF
{
  "name": "$MODULE_NAME",
  "version": "$MODULE_VERSION",
  "category": "$MODULE_CATEGORY",
  "description": "$MODULE_DESCRIPTION",
  "author": "$MODULE_AUTHOR",
  "executable": "$MODULE_EXECUTABLE_TYPE",
  "timeout": $MODULE_TIMEOUT,
  "concurrent": $MODULE_CONCURRENT,
  "dependencies": [$(printf '"%s",' "${MODULE_DEPENDENCIES[@]}" | sed 's/,$//')],
  "inputs": {
$(for spec in "${MODULE_INPUTS[@]}"; do
    echo "$spec" | jq -r 'to_entries[] | "    \"" + .value.name + "\": {\"type\": \"" + .value.type + "\", \"description\": \"" + .value.description + "\"},"'
done | sed '$ s/,$//')
  },
  "outputs": {
$(for spec in "${MODULE_OUTPUTS[@]}"; do
    echo "$spec" | jq -r 'to_entries[] | "    \"" + .value.name + "\": {\"type\": \"" + .value.type + "\", \"description\": \"" + .value.description + "\"},"'
done | sed '$ s/,$//')
  }
}
EOF
    
    # Pretty print the JSON if jq is available
    if command -v jq &> /dev/null; then
        jq '.' "$json_file" > "${json_file}.tmp" && mv "${json_file}.tmp" "$json_file"
    fi
    
    print_colored $GREEN "✅ Generated: $json_file"
}

# Function to generate executable template based on type
generate_executable_template() {
    local executable_path="tools/$MODULE_NAME/$MODULE_EXECUTABLE_TYPE"
    
    case "$MODULE_EXECUTABLE_TYPE" in
        *.sh)
            generate_bash_template "$executable_path"
            chmod +x "$executable_path"
            ;;
        *.py)
            generate_python_template "$executable_path"
            chmod +x "$executable_path"
            ;;
        *.go)
            generate_go_template "$executable_path"
            ;;
        *.ps1)
            generate_powershell_template "$executable_path"
            ;;
        *)
            print_colored $YELLOW "⚠️  Unknown executable type. Creating basic template."
            touch "$executable_path"
            ;;
    esac
    
    print_colored $GREEN "✅ Generated executable template: $executable_path"
}

# Function to generate Bash script template
generate_bash_template() {
    local file_path=$1
    
    cat > "$file_path" << 'EOF'
#!/bin/bash

# SecV Module: MODULE_NAME_PLACEHOLDER
# This script reads JSON context from stdin and outputs JSON results to stdout

set -e

# Read the execution context from stdin
CONTEXT=$(cat)

# Extract target and parameters using jq
TARGET=$(echo "$CONTEXT" | jq -r '.target // empty')
PARAMETERS=$(echo "$CONTEXT" | jq -r '.parameters // {}')

# Initialize result structure
RESULT='{
  "success": false,
  "data": {},
  "errors": [],
  "execution_time_ms": 0,
  "module_name": "MODULE_NAME_PLACEHOLDER",
  "timestamp": ""
}'

# Function to output success result
output_success() {
    local data=$1
    local timestamp=$(date -Iseconds)
    
    echo "$RESULT" | jq --arg data "$data" --arg timestamp "$timestamp" '
        .success = true |
        .data = ($data | fromjson) |
        .timestamp = $timestamp
    '
}

# Function to output error result
output_error() {
    local error_message=$1
    local timestamp=$(date -Iseconds)
    
    echo "$RESULT" | jq --arg error "$error_message" --arg timestamp "$timestamp" '
        .success = false |
        .errors = [$error] |
        .timestamp = $timestamp
    '
}

# Main execution logic
main() {
    # Validate that target is provided
    if [[ -z "$TARGET" ]]; then
        output_error "Target is required"
        exit 0
    fi
    
    # TODO: Implement your module logic here
    # Example:
    # - Parse parameters
    # - Execute security tool/scan
    # - Process results
    # - Return structured data
    
    # For now, return a placeholder success result
    local sample_data='{"message": "Module executed successfully", "target": "'$TARGET'"}'
    output_success "$sample_data"
}

# Execute main function
main
EOF
    
    # Replace placeholder with actual module name
    sed -i "s/MODULE_NAME_PLACEHOLDER/$MODULE_NAME/g" "$file_path"
}

# Function to generate Python script template
generate_python_template() {
    local file_path=$1
    
    cat > "$file_path" << 'EOF'
#!/usr/bin/env python3

"""
SecV Module: MODULE_NAME_PLACEHOLDER
This script reads JSON context from stdin and outputs JSON results to stdout
"""

import json
import sys
import datetime
from typing import Dict, Any, List

class SecVModule:
    def __init__(self):
        self.module_name = "MODULE_NAME_PLACEHOLDER"
        
    def read_context(self) -> Dict[str, Any]:
        """Read execution context from stdin"""
        try:
            context = json.loads(sys.stdin.read())
            return context
        except json.JSONDecodeError as e:
            self.output_error(f"Failed to parse input context: {str(e)}")
            sys.exit(0)
    
    def output_success(self, data: Any) -> None:
        """Output successful result"""
        result = {
            "success": True,
            "data": data,
            "errors": [],
            "execution_time_ms": 0,
            "module_name": self.module_name,
            "timestamp": datetime.datetime.now().isoformat()
        }
        print(json.dumps(result, indent=2))
    
    def output_error(self, error_message: str) -> None:
        """Output error result"""
        result = {
            "success": False,
            "data": {},
            "errors": [error_message],
            "execution_time_ms": 0,
            "module_name": self.module_name,
            "timestamp": datetime.datetime.now().isoformat()
        }
        print(json.dumps(result, indent=2))
    
    def execute(self) -> None:
        """Main execution logic"""
        context = self.read_context()
        
        # Extract target and parameters
        target = context.get('target', '')
        parameters = context.get('parameters', {})
        
        # Validate that target is provided
        if not target:
            self.output_error("Target is required")
            return
        
        # TODO: Implement your module logic here
        # Example:
        # - Parse parameters
        # - Execute security tool/scan
        # - Process results
        # - Return structured data
        
        # For now, return a placeholder success result
        sample_data = {
            "message": "Module executed successfully",
            "target": target
        }
        self.output_success(sample_data)

if __name__ == "__main__":
    module = SecVModule()
    module.execute()
EOF
    
    # Replace placeholder with actual module name
    sed -i "s/MODULE_NAME_PLACEHOLDER/$MODULE_NAME/g" "$file_path"
}

# Function to generate Go template
generate_go_template() {
    local file_path=$1
    
    cat > "$file_path" << 'EOF'
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// ExecutionContext represents the input context from SecV
type ExecutionContext struct {
	Target     string                 `json:"target"`
	Parameters map[string]interface{} `json:"parameters"`
	Results    map[string]interface{} `json:"results"`
	WorkflowID string                 `json:"workflow_id,omitempty"`
	StepID     string                 `json:"step_id,omitempty"`
}

// ModuleResult represents the output result for SecV
type ModuleResult struct {
	Success         bool        `json:"success"`
	Data            interface{} `json:"data"`
	Errors          []string    `json:"errors"`
	ExecutionTimeMs int64       `json:"execution_time_ms"`
	ModuleName      string      `json:"module_name"`
	Timestamp       time.Time   `json:"timestamp"`
}

func outputSuccess(data interface{}) {
	result := ModuleResult{
		Success:         true,
		Data:            data,
		Errors:          []string{},
		ExecutionTimeMs: 0,
		ModuleName:      "MODULE_NAME_PLACEHOLDER",
		Timestamp:       time.Now(),
	}
	
	output, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(output))
}

func outputError(errorMessage string) {
	result := ModuleResult{
		Success:         false,
		Data:            nil,
		Errors:          []string{errorMessage},
		ExecutionTimeMs: 0,
		ModuleName:      "MODULE_NAME_PLACEHOLDER",
		Timestamp:       time.Now(),
	}
	
	output, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(output))
}

func main() {
	// Read execution context from stdin
	var context ExecutionContext
	decoder := json.NewDecoder(os.Stdin)
	if err := decoder.Decode(&context); err != nil {
		outputError(fmt.Sprintf("Failed to parse input context: %v", err))
		return
	}
	
	// Validate that target is provided
	if context.Target == "" {
		outputError("Target is required")
		return
	}
	
	// TODO: Implement your module logic here
	// Example:
	// - Parse parameters
	// - Execute security tool/scan
	// - Process results
	// - Return structured data
	
	// For now, return a placeholder success result
	sampleData := map[string]interface{}{
		"message": "Module executed successfully",
		"target":  context.Target,
	}
	
	outputSuccess(sampleData)
}
EOF
    
    # Replace placeholder with actual module name
    sed -i "s/MODULE_NAME_PLACEHOLDER/$MODULE_NAME/g" "$file_path"
}

# Function to generate PowerShell template
generate_powershell_template() {
    local file_path=$1
    
    cat > "$file_path" << 'EOF'
# SecV Module: MODULE_NAME_PLACEHOLDER
# This script reads JSON context from stdin and outputs JSON results to stdout

param()

# Function to output success result
function Write-SuccessResult {
    param(
        [Parameter(Mandatory=$true)]
        $Data
    )
    
    $result = @{
        success = $true
        data = $Data
        errors = @()
        execution_time_ms = 0
        module_name = "MODULE_NAME_PLACEHOLDER"
        timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffK")
    }
    
    $result | ConvertTo-Json -Depth 10
}

# Function to output error result
function Write-ErrorResult {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ErrorMessage
    )
    
    $result = @{
        success = $false
        data = @{}
        errors = @($ErrorMessage)
        execution_time_ms = 0
        module_name = "MODULE_NAME_PLACEHOLDER"
        timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffK")
    }
    
    $result | ConvertTo-Json -Depth 10
}

try {
    # Read execution context from stdin
    $inputLines = @()
    while ($null -ne ($line = [Console]::ReadLine())) {
        $inputLines += $line
    }
    $contextJson = $inputLines -join "`n"
    $context = $contextJson | ConvertFrom-Json
    
    # Extract target and parameters
    $target = $context.target
    $parameters = $context.parameters
    
    # Validate that target is provided
    if (-not $target) {
        Write-ErrorResult "Target is required"
        exit 0
    }
    
    # TODO: Implement your module logic here
    # Example:
    # - Parse parameters
    # - Execute security tool/scan
    # - Process results
    # - Return structured data
    
    # For now, return a placeholder success result
    $sampleData = @{
        message = "Module executed successfully"
        target = $target
    }
    
    Write-SuccessResult $sampleData
}
catch {
    Write-ErrorResult "Module execution failed: $($_.Exception.Message)"
}
EOF
    
    # Replace placeholder with actual module name
    sed -i "s/MODULE_NAME_PLACEHOLDER/$MODULE_NAME/g" "$file_path"
}

# Function to generate README documentation
generate_readme() {
    local readme_file="tools/$MODULE_NAME/README.md"
    
    cat > "$readme_file" << EOF
# $MODULE_NAME

**Version:** $MODULE_VERSION  
**Category:** $MODULE_CATEGORY  
**Author:** $MODULE_AUTHOR

## Description

$MODULE_DESCRIPTION

## Usage

This module can be executed using the SecV platform:

\`\`\`bash
secv execute $MODULE_NAME --target <target> --params '<json_params>'
\`\`\`

## Inputs

$(for spec in "${MODULE_INPUTS[@]}"; do
    echo "$spec" | jq -r '"- **" + .name + "** (" + .type + "): " + .description'
done)

## Outputs

$(for spec in "${MODULE_OUTPUTS[@]}"; do
    echo "$spec" | jq -r '"- **" + .name + "** (" + .type + "): " + .description'
done)

## Dependencies

$(printf -- '- %s\n' "${MODULE_DEPENDENCIES[@]}")

## Configuration

- **Timeout:** ${MODULE_TIMEOUT} seconds
- **Concurrent Execution:** $MODULE_CONCURRENT

## Development

To modify this module:

1. Edit the executable file: \`$MODULE_EXECUTABLE_TYPE\`
2. Update the module.json if needed
3. Test with: \`secv execute $MODULE_NAME --target test.example.com\`

## Notes

- This module was generated using the SecV Module Generator
- Follow SecV conventions for input/output JSON formatting
- Ensure proper error handling and timeout management
EOF
    
    print_colored $GREEN "✅ Generated: $readme_file"
}

# Main function to collect all module information
collect_module_info() {
    print_colored $BLUE "📝 Let's gather information about your new module..."
    echo
    
    # Basic module information
    MODULE_NAME=$(get_input "Module name (alphanumeric, hyphens, underscores only)" "validate_module_name" "Module name")
    MODULE_VERSION=$(get_input "Module version (semantic versioning, e.g., 1.0.0)" "validate_version" "Version")
    MODULE_CATEGORY=$(get_input "Module category (e.g., reconnaissance, vulnerability-scanning, exploitation)" "" "")
    MODULE_DESCRIPTION=$(get_input "Module description" "" "")
    MODULE_AUTHOR=$(get_input "Author name/email" "" "")
    
    # Executable type selection
    print_colored $YELLOW "Select executable type:"
    echo "1. Bash script (.sh)"
    echo "2. Python script (.py)"
    echo "3. Go program (.go)"
    echo "4. PowerShell script (.ps1)"
    echo "5. Custom executable"
    
    while true; do
        echo -n "Enter choice (1-5): "
        read choice
        
        case $choice in
            1) MODULE_EXECUTABLE_TYPE="${MODULE_NAME}.sh"; break ;;
            2) MODULE_EXECUTABLE_TYPE="${MODULE_NAME}.py"; break ;;
            3) MODULE_EXECUTABLE_TYPE="${MODULE_NAME}.go"; break ;;
            4) MODULE_EXECUTABLE_TYPE="${MODULE_NAME}.ps1"; break ;;
            5) 
                MODULE_EXECUTABLE_TYPE=$(get_input "Enter executable filename" "" "")
                break
                ;;
            *) print_colored $RED "Please enter a number between 1-5" ;;
        esac
    done
    
    # Advanced configuration
    MODULE_TIMEOUT=$(get_input "Execution timeout in seconds (default: 300)" "" "")
    if [[ -z "$MODULE_TIMEOUT" ]]; then
        MODULE_TIMEOUT=300
    fi
    
    MODULE_CONCURRENT=$(get_yes_no "Can this module run concurrently?" "n")
    
    # Dependencies
    collect_array_input "Dependencies" "Enter any external dependencies or tools this module requires:" MODULE_DEPENDENCIES
    
    # Input specifications
    collect_io_specs "input" MODULE_INPUTS
    
    # Output specifications
    collect_io_specs "output" MODULE_OUTPUTS
}

# Function to display summary and confirm
display_summary() {
    print_colored $CYAN "📋 Module Summary:"
    echo "===================="
    echo "Name: $MODULE_NAME"
    echo "Version: $MODULE_VERSION"
    echo "Category: $MODULE_CATEGORY"
    echo "Description: $MODULE_DESCRIPTION"
    echo "Author: $MODULE_AUTHOR"
    echo "Executable: $MODULE_EXECUTABLE_TYPE"
    echo "Timeout: ${MODULE_TIMEOUT}s"
    echo "Concurrent: $MODULE_CONCURRENT"
    echo "Dependencies: ${#MODULE_DEPENDENCIES[@]} items"
    echo "Inputs: ${#MODULE_INPUTS[@]} specifications"
    echo "Outputs: ${#MODULE_OUTPUTS[@]} specifications"
    echo
    
    local confirm=$(get_yes_no "Generate this module?" "y")
    if [[ "$confirm" == "false" ]]; then
        print_colored $RED "❌ Module generation cancelled"
        exit 1
    fi
}

# Main execution flow
main() {
    print_banner
    
    # Check dependencies
    if ! command -v jq &> /dev/null; then
        print_colored $RED "❌ Error: jq is required but not installed"
        print_colored $YELLOW "Please install jq: https://stedolan.github.io/jq/download/"
        exit 1
    fi
    
    # Ensure tools directory exists
    if [[ ! -d "tools" ]]; then
        print_colored $YELLOW "⚠️  Tools directory doesn't exist. Creating it..."
        mkdir -p tools
    fi
    
    # Collect module information
    collect_module_info
    
    # Display summary and get confirmation
    display_summary
    
    # Generate the module
    print_colored $BLUE "🔧 Generating module..."
    
    create_directory_structure
    generate_module_json
    generate_executable_template
    generate_readme
    
    print_colored $GREEN "🎉 Module '$MODULE_NAME' generated successfully!"
    print_colored $CYAN "📁 Location: tools/$MODULE_NAME/"
    print_colored $YELLOW "💡 Next steps:"
    echo "   1. Implement your logic in tools/$MODULE_NAME/$MODULE_EXECUTABLE_TYPE"
    echo "   2. Test with: secv execute $MODULE_NAME --target test.example.com"
    echo "   3. Update README.md with specific usage examples"
}

# Execute main function
main
