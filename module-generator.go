package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
)

// ModuleTemplate represents the structure we'll generate
type ModuleTemplate struct {
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Category     string                 `json:"category"`
	Description  string                 `json:"description"`
	Author       string                 `json:"author"`
	Executable   string                 `json:"executable"`
	Dependencies []string               `json:"dependencies"`
	Inputs       map[string]InputSpec   `json:"inputs"`
	Outputs      map[string]OutputSpec  `json:"outputs"`
	Timeout      int                    `json:"timeout,omitempty"`
	Concurrent   bool                   `json:"concurrent"`
}

type InputSpec struct {
	Type        string   `json:"type"`
	Required    bool     `json:"required"`
	Description string   `json:"description"`
	Default     string   `json:"default,omitempty"`
	Pattern     string   `json:"pattern,omitempty"`
	Enum        []string `json:"enum,omitempty"`
}

type OutputSpec struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

// ModuleGenerator handles the interactive generation process
type ModuleGenerator struct {
	scanner    *bufio.Scanner
	workingDir string
	template   ModuleTemplate
}

// NewModuleGenerator creates a new generator instance
func NewModuleGenerator() *ModuleGenerator {
	return &ModuleGenerator{
		scanner: bufio.NewScanner(os.Stdin),
		template: ModuleTemplate{
			Inputs:  make(map[string]InputSpec),
			Outputs: make(map[string]OutputSpec),
		},
	}
}

// Helper function to get user input with a default value
func (mg *ModuleGenerator) askWithDefault(question, defaultValue string) string {
	if defaultValue != "" {
		color.Cyan("%s [%s]: ", question, defaultValue)
	} else {
		color.Cyan("%s: ", question)
	}
	
	mg.scanner.Scan()
	response := strings.TrimSpace(mg.scanner.Text())
	
	if response == "" && defaultValue != "" {
		return defaultValue
	}
	return response
}

// Helper function to ask yes/no questions
func (mg *ModuleGenerator) askYesNo(question string, defaultYes bool) bool {
	defaultStr := "y/N"
	if defaultYes {
		defaultStr = "Y/n"
	}
	
	response := mg.askWithDefault(question+" ("+defaultStr+")", "")
	response = strings.ToLower(strings.TrimSpace(response))
	
	if response == "" {
		return defaultYes
	}
	
	return response == "y" || response == "yes"
}

// Helper function to ask for integer input
func (mg *ModuleGenerator) askInt(question string, defaultValue int) int {
	defaultStr := ""
	if defaultValue > 0 {
		defaultStr = strconv.Itoa(defaultValue)
	}
	
	for {
		response := mg.askWithDefault(question, defaultStr)
		
		if response == "" && defaultValue > 0 {
			return defaultValue
		}
		
		if val, err := strconv.Atoi(response); err == nil {
			return val
		}
		
		color.Red("Please enter a valid number.")
	}
}

// Detect the operating system and provide appropriate defaults
func (mg *ModuleGenerator) detectEnvironment() {
	color.Yellow("🔍 Detecting your environment...")
	
	osName := runtime.GOOS
	switch osName {
	case "windows":
		color.Green("✓ Detected Windows environment")
	case "darwin":
		color.Green("✓ Detected macOS environment")
	case "linux":
		color.Green("✓ Detected Linux environment")
	default:
		color.Yellow("⚠️  Unknown operating system: %s", osName)
	}
	
	// Detect current working directory and suggest tools directory
	wd, err := os.Getwd()
	if err != nil {
		mg.workingDir = "."
	} else {
		mg.workingDir = wd
	}
	
	fmt.Printf("Current directory: %s\n", mg.workingDir)
}

// Get basic module information
func (mg *ModuleGenerator) gatherBasicInfo() {
	color.Blue("\n📝 Let's start with basic information about your module...\n")
	
	// Module name with validation
	for {
		mg.template.Name = mg.askWithDefault("What should we call your module? (lowercase, no spaces)", "")
		
		if mg.template.Name == "" {
			color.Red("Module name is required!")
			continue
		}
		
		// Validate module name format
		if matched, _ := regexp.MatchString("^[a-z][a-z0-9_-]*$", mg.template.Name); !matched {
			color.Red("Module name should start with a letter and contain only lowercase letters, numbers, hyphens, and underscores.")
			continue
		}
		
		break
	}
	
	// Version
	mg.template.Version = mg.askWithDefault("What version is this module?", "1.0.0")
	
	// Author
	mg.template.Author = mg.askWithDefault("Who is the author? (your name or organization)", "")
	
	// Description
	mg.template.Description = mg.askWithDefault("Briefly describe what this module does", "")
	
	// Category selection with suggestions
	color.Cyan("\nWhat category best describes your module?")
	color.White("Common categories: reconnaissance, network, exploitation, post-exploitation, forensics, web, wireless, misc")
	mg.template.Category = mg.askWithDefault("Category", "misc")
}

// Get executable information and detect existing files
func (mg *ModuleGenerator) gatherExecutableInfo() {
	color.Blue("\n⚙️  Now let's configure the executable...\n")
	
	// Try to detect existing executables in the current directory
	color.Yellow("🔍 Scanning for potential executables in current directory...")
	
	var detectedFiles []string
	files, err := ioutil.ReadDir(mg.workingDir)
	if err == nil {
		for _, file := range files {
			name := file.Name()
			
			// Look for common executable patterns
			if !file.IsDir() && (
				strings.HasSuffix(name, ".py") ||
				strings.HasSuffix(name, ".sh") ||
				strings.HasSuffix(name, ".ps1") ||
				strings.HasSuffix(name, ".rb") ||
				strings.HasSuffix(name, ".pl") ||
				strings.HasSuffix(name, ".exe") ||
				(file.Mode()&0111 != 0 && !strings.Contains(name, "."))) { // Unix executable
				
				detectedFiles = append(detectedFiles, name)
			}
		}
	}
	
	if len(detectedFiles) > 0 {
		color.Green("Found potential executables:")
		for i, file := range detectedFiles {
			fmt.Printf("  %d) %s\n", i+1, file)
		}
		
		choice := mg.askWithDefault("Select a file by number, or enter a custom path", "")
		
		if choice != "" {
			if num, err := strconv.Atoi(choice); err == nil && num > 0 && num <= len(detectedFiles) {
				mg.template.Executable = "./" + detectedFiles[num-1]
			} else {
				mg.template.Executable = choice
			}
		}
	}
	
	// If no executable was selected, ask for it
	if mg.template.Executable == "" {
		mg.template.Executable = mg.askWithDefault("Path to your executable (relative to module directory)", "./script.py")
	}
	
	// Timeout configuration
	color.Cyan("\nHow long should SecV wait before timing out this module?")
	color.White("Consider how long your tool typically takes to run. Most tools should complete within 5 minutes.")
	mg.template.Timeout = mg.askInt("Timeout in seconds", 300)
	
	// Concurrent execution
	color.Cyan("\nCan this module run safely alongside other modules?")
	color.White("Say 'yes' if your tool doesn't interfere with others (most reconnaissance tools)")
	color.White("Say 'no' if it makes system changes or could conflict (network tools, exploits)")
	mg.template.Concurrent = mg.askYesNo("Allow concurrent execution?", false)
}

// Get dependency information
func (mg *ModuleGenerator) gatherDependencies() {
	color.Blue("\n📦 Let's identify any dependencies...\n")
	
	color.Cyan("Does your module depend on other tools or libraries?")
	color.White("Examples: nmap, python3, curl, jq, etc.")
	
	if mg.askYesNo("Add dependencies?", false) {
		for {
			dep := mg.askWithDefault("Enter a dependency (or press Enter to finish)", "")
			if dep == "" {
				break
			}
			mg.template.Dependencies = append(mg.template.Dependencies, dep)
			color.Green("✓ Added dependency: %s", dep)
		}
	}
}

// Get input parameter definitions
func (mg *ModuleGenerator) gatherInputs() {
	color.Blue("\n📥 Let's define the input parameters your module accepts...\n")
	
	color.Cyan("SecV modules receive parameters as JSON. Let's define what parameters your module needs.")
	color.White("Common examples:")
	color.White("  • target/host: The system to scan or attack")
	color.White("  • port: Network port number")
	color.White("  • username/password: Authentication credentials")
	color.White("  • output_format: How to format results")
	
	// Always suggest a target parameter
	if mg.askYesNo("Does your module work on a target system/host?", true) {
		mg.template.Inputs["target"] = InputSpec{
			Type:        "string",
			Required:    true,
			Description: "Target system (IP address, hostname, or URL)",
		}
		color.Green("✓ Added 'target' parameter")
	}
	
	// Collect additional parameters
	for {
		if !mg.askYesNo("Add another parameter?", false) {
			break
		}
		
		paramName := mg.askWithDefault("Parameter name (lowercase, no spaces)", "")
		if paramName == "" {
			continue
		}
		
		// Validate parameter name
		if matched, _ := regexp.MatchString("^[a-z][a-z0-9_]*$", paramName); !matched {
			color.Red("Parameter name should start with a letter and contain only lowercase letters, numbers, and underscores.")
			continue
		}
		
		paramType := mg.askWithDefault("Parameter type (string/int/bool/array)", "string")
		paramDesc := mg.askWithDefault("Parameter description", "")
		paramRequired := mg.askYesNo("Is this parameter required?", false)
		
		input := InputSpec{
			Type:        paramType,
			Required:    paramRequired,
			Description: paramDesc,
		}
		
		// Optional: default value
		if !paramRequired {
			defaultVal := mg.askWithDefault("Default value (optional)", "")
			if defaultVal != "" {
				input.Default = defaultVal
			}
		}
		
		// Optional: validation pattern for strings
		if paramType == "string" {
			if mg.askYesNo("Add validation pattern (regex)?", false) {
				pattern := mg.askWithDefault("Regex pattern", "")
				if pattern != "" {
					input.Pattern = pattern
				}
			}
		}
		
		mg.template.Inputs[paramName] = input
		color.Green("✓ Added parameter: %s (%s)", paramName, paramType)
	}
}

// Get output definitions
func (mg *ModuleGenerator) gatherOutputs() {
	color.Blue("\n📤 Let's define what your module outputs...\n")
	
	color.Cyan("SecV modules return structured data as JSON. Let's define what your module will return.")
	color.White("Think about what information would be useful to other modules or users.")
	
	// Common outputs
	commonOutputs := map[string]OutputSpec{
		"vulnerabilities": {Type: "array", Description: "List of discovered vulnerabilities"},
		"open_ports":      {Type: "array", Description: "List of open network ports"},
		"services":        {Type: "array", Description: "List of running services"},
		"files":           {Type: "array", Description: "List of discovered files"},
		"credentials":     {Type: "array", Description: "List of discovered credentials"},
		"hosts":           {Type: "array", Description: "List of discovered hosts"},
		"urls":            {Type: "array", Description: "List of discovered URLs"},
		"summary":         {Type: "string", Description: "Summary of findings"},
		"score":           {Type: "int", Description: "Risk or confidence score"},
	}
	
	color.Cyan("Here are some common output types. Select any that apply:")
	for name, spec := range commonOutputs {
		if mg.askYesNo(fmt.Sprintf("Does your module output %s?", name), false) {
			mg.template.Outputs[name] = spec
			color.Green("✓ Added output: %s", name)
		}
	}
	
	// Custom outputs
	for {
		if !mg.askYesNo("Add a custom output field?", false) {
			break
		}
		
		outputName := mg.askWithDefault("Output field name", "")
		if outputName == "" {
			continue
		}
		
		outputType := mg.askWithDefault("Output type (string/int/bool/array/object)", "string")
		outputDesc := mg.askWithDefault("Output description", "")
		
		mg.template.Outputs[outputName] = OutputSpec{
			Type:        outputType,
			Description: outputDesc,
		}
		
		color.Green("✓ Added output: %s (%s)", outputName, outputType)
	}
}

// Suggest and create the module directory structure
func (mg *ModuleGenerator) createModuleStructure() error {
	color.Blue("\n📁 Creating module directory structure...\n")
	
	// Determine the tools directory path
	toolsDir := filepath.Join(mg.workingDir, "..", "tools")
	
	// Check if we're already in a SecV project
	if _, err := os.Stat(filepath.Join(mg.workingDir, "tools")); err == nil {
		toolsDir = filepath.Join(mg.workingDir, "tools")
	} else if _, err := os.Stat(toolsDir); err != nil {
		// Ask user where to create the module
		color.Yellow("⚠️  SecV tools directory not found.")
		customPath := mg.askWithDefault("Where should we create the module directory?", "./tools")
		toolsDir = customPath
	}
	
	// Create the module directory
	moduleDir := filepath.Join(toolsDir, mg.template.Name)
	
	color.Cyan("Module will be created at: %s", moduleDir)
	if !mg.askYesNo("Is this location correct?", true) {
		customDir := mg.askWithDefault("Enter the full path for the module directory", moduleDir)
		moduleDir = customDir
	}
	
	// Create directory structure
	if err := os.MkdirAll(moduleDir, 0755); err != nil {
		return fmt.Errorf("failed to create module directory: %w", err)
	}
	
	// Save the module directory for later use
	mg.workingDir = moduleDir
	
	color.Green("✓ Created module directory: %s", moduleDir)
	return nil
}

// Generate the module.json configuration file
func (mg *ModuleGenerator) generateModuleConfig() error {
	color.Blue("\n⚙️  Generating module configuration...\n")
	
	// Pretty print the JSON configuration
	configJSON, err := json.MarshalIndent(mg.template, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal module config: %w", err)
	}
	
	configPath := filepath.Join(mg.workingDir, "module.json")
	if err := ioutil.WriteFile(configPath, configJSON, 0644); err != nil {
		return fmt.Errorf("failed to write module config: %w", err)
	}
	
	color.Green("✓ Generated module.json")
	return nil
}

// Generate a wrapper script template
func (mg *ModuleGenerator) generateWrapperScript() error {
	color.Blue("\n📜 Generating wrapper script template...\n")
	
	// Detect script type based on executable
	var scriptTemplate string
	var scriptName string
	
	executable := strings.ToLower(mg.template.Executable)
	
	if strings.Contains(executable, ".py") {
		scriptTemplate = mg.generatePythonWrapper()
		scriptName = "wrapper.py"
	} else if strings.Contains(executable, ".sh") {
		scriptTemplate = mg.generateBashWrapper()
		scriptName = "wrapper.sh"
	} else if strings.Contains(executable, ".ps1") {
		scriptTemplate = mg.generatePowerShellWrapper()
		scriptName = "wrapper.ps1"
	} else {
		// Generate a generic bash wrapper
		scriptTemplate = mg.generateBashWrapper()
		scriptName = "wrapper.sh"
	}
	
	wrapperPath := filepath.Join(mg.workingDir, scriptName)
	if err := ioutil.WriteFile(wrapperPath, []byte(scriptTemplate), 0755); err != nil {
		return fmt.Errorf("failed to write wrapper script: %w", err)
	}
	
	color.Green("✓ Generated %s", scriptName)
	color.Yellow("💡 Edit this wrapper to integrate your existing tool with SecV")
	
	return nil
}

// Generate Python wrapper template
func (mg *ModuleGenerator) generatePythonWrapper() string {
	return fmt.Sprintf(`#!/usr/bin/env python3
"""
SecV Module Wrapper for %s
This script adapts your existing tool to work with the SecV platform.
"""

import json
import sys
import subprocess
import os
from pathlib import Path

def log_message(message):
    """Log messages to stderr so they don't interfere with JSON output"""
    print(f"[{os.path.basename(__file__)}] {message}", file=sys.stderr)

def main():
    try:
        # Read JSON input from stdin (SecV passes data this way)
        input_data = json.load(sys.stdin)
        
        # Extract parameters
        target = input_data.get('target', '')
        parameters = input_data.get('parameters', {})
        
        log_message(f"Processing target: {target}")
        
        # TODO: Adapt this section to call your existing tool
        # Example of calling your original script/tool:
        # result = subprocess.run([
        #     'python3', '%s',  # Your original script
        #     target,           # Pass target as argument
        #     '--param1', parameters.get('param1', ''),
        # ], capture_output=True, text=True)
        
        # For now, return a success response
        response = {
            "success": True,
            "data": {
                "target": target,
                "message": "Module executed successfully",
                # TODO: Add your actual results here
            },
            "errors": []
        }
        
        # Output JSON response (this is required by SecV)
        print(json.dumps(response, indent=2))
        
    except Exception as e:
        # Return error response in SecV format
        error_response = {
            "success": False,
            "data": None,
            "errors": [str(e)]
        }
        print(json.dumps(error_response, indent=2))
        sys.exit(1)

if __name__ == "__main__":
    main()
`, mg.template.Name)
}

// Generate Bash wrapper template
func (mg *ModuleGenerator) generateBashWrapper() string {
	return fmt.Sprintf(`#!/bin/bash
# SecV Module Wrapper for %s
# This script adapts your existing tool to work with the SecV platform.

# Function to log messages to stderr
log_message() {
    echo "[$(basename "$0")] $1" >&2
}

# Function to output JSON response
output_json() {
    local success="$1"
    local data="$2"
    local errors="$3"
    
    cat << EOF
{
  "success": $success,
  "data": $data,
  "errors": $errors
}
EOF
}

main() {
    # Read JSON input from stdin
    local input_json=$(cat)
    
    # Parse JSON (requires jq for robust parsing, fallback to basic parsing)
    if command -v jq &> /dev/null; then
        local target=$(echo "$input_json" | jq -r '.target // empty')
        # Add more parameter parsing as needed
        # local param1=$(echo "$input_json" | jq -r '.parameters.param1 // empty')
    else
        # Basic parsing without jq (less robust)
        local target=$(echo "$input_json" | grep -o '"target"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)".*/\1/')
    fi
    
    log_message "Processing target: $target"
    
    # TODO: Call your existing tool here
    # Example:
    # if ./your-original-script.sh "$target"; then
    #     output_json true '{"target":"'$target'","message":"Success"}' '[]'
    # else
    #     output_json false 'null' '["Script execution failed"]'
    #     exit 1
    # fi
    
    # For now, return a success response
    output_json true '{"target":"'$target'","message":"Module executed successfully"}' '[]'
}

# Execute main function
main "$@"
`, mg.template.Name)
}

// Generate PowerShell wrapper template
func (mg *ModuleGenerator) generatePowerShellWrapper() string {
	return fmt.Sprintf(`# SecV Module Wrapper for %s
# This script adapts your existing tool to work with the SecV platform.

function Write-LogMessage {
    param([string]$Message)
    Write-Host "[$(Split-Path $PSCommandPath -Leaf)] $Message" -ForegroundColor Yellow
}

function Write-JsonResponse {
    param(
        [bool]$Success,
        [object]$Data,
        [string[]]$Errors
    )
    
    $response = @{
        success = $Success
        data = $Data
        errors = $Errors
    }
    
    $response | ConvertTo-Json -Depth 10
}

try {
    # Read JSON input from stdin
    $inputJson = [Console]::In.ReadToEnd()
    $inputData = $inputJson | ConvertFrom-Json
    
    # Extract parameters
    $target = $inputData.target
    $parameters = $inputData.parameters
    
    Write-LogMessage "Processing target: $target"
    
    # TODO: Call your existing PowerShell script or tool here
    # Example:
    # $result = & .\your-original-script.ps1 -Target $target -Param1 $parameters.param1
    # if ($LASTEXITCODE -eq 0) {
    #     Write-JsonResponse -Success $true -Data @{target=$target; result=$result} -Errors @()
    # } else {
    #     Write-JsonResponse -Success $false -Data $null -Errors @("Script execution failed")
    # }
    
    # For now, return a success response
    Write-JsonResponse -Success $true -Data @{target=$target; message="Module executed successfully"} -Errors @()
    
} catch {
    Write-JsonResponse -Success $false -Data $null -Errors @($_.Exception.Message)
    exit 1
}
`, mg.template.Name)
}

// Generate documentation
func (mg *ModuleGenerator) generateDocumentation() error {
	color.Blue("\n📚 Generating documentation...\n")
	
	docContent := fmt.Sprintf(`# %s Module

**Version:** %s  
**Author:** %s  
**Category:** %s

## Description

%s

## Usage

### Basic Execution
`+"```bash"+`
secv execute %s -t <target>
`+"```"+`

### With Parameters
`+"```bash"+`
secv execute %s -t <target> -p '{"param1":"value1"}'
`+"```"+`

## Input Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
`, mg.template.Name, mg.template.Version, mg.template.Author, mg.template.Category, 
   mg.template.Description, mg.template.Name, mg.template.Name)
	
	// Add input parameters to documentation
	for name, spec := range mg.template.Inputs {
		required := "No"
		if spec.Required {
			required = "Yes"
		}
		docContent += fmt.Sprintf("| %s | %s | %s | %s |\n", name, spec.Type, required, spec.Description)
	}
	
	docContent += "\n## Output Fields\n\n"
	docContent += "| Field | Type | Description |\n"
	docContent += "|-------|------|-------------|\n"
	
	// Add output fields to documentation
	for name, spec := range mg.template.Outputs {
		docContent += fmt.Sprintf("| %s | %s | %s |\n", name, spec.Type, spec.Description)
	}
	
	// Add dependencies if any
	if len(mg.template.Dependencies) > 0 {
		docContent += "\n## Dependencies\n\n"
		for _, dep := range mg.template.Dependencies {
			docContent += fmt.Sprintf("- %s\n", dep)
		}
	}
	
	docContent += fmt.Sprintf(`
## Configuration

- **Timeout:** %d seconds
- **Concurrent Execution:** %t

## Integration Notes

This module was generated using the SecV module generator. To complete the integration:

1. Edit the wrapper script to call your existing tool
2. Ensure your tool outputs are properly parsed and formatted as JSON
3. Test the module with: `+"```secv execute %s -t localhost```"+`
4. Update this documentation as needed

## Contributing

If you make improvements to this module, consider contributing back to the SecV community!
`, mg.template.Timeout, mg.template.Concurrent, mg.template.Name)
	
	docPath := filepath.Join(mg.workingDir, "README.md")
	if err := ioutil.WriteFile(docPath, []byte(docContent), 0644); err != nil {
		return fmt.Errorf("failed to write documentation: %w", err)
	}
	
	color.Green("✓ Generated README.md")
	return nil
}

// Display final summary and next steps
func (mg *ModuleGenerator) showSummary() {
	color.Blue("\n🎉 Module generation complete!\n")
	
	color.Green("Created files:")
	fmt.Printf("  📄 module.json - Module configuration\n")
	fmt.Printf("  📜 wrapper script - Integration template\n")
	fmt.Printf("  📚 README.md - Documentation\n")
	
	color.Yellow("\nNext steps:")
	fmt.Printf("  1. Copy your existing tool files to: %s\n", mg.workingDir)
	fmt.Printf("  2. Edit the wrapper script to integrate your tool\n")
	fmt.Printf("  3. Test with: secv execute %s -t localhost\n", mg.template.Name)
	fmt.Printf("  4. Share with the community!\n")
	
	color.Cyan("\nModule location: %s", mg.workingDir)
	
	// Offer to show the generated config
	if mg.askYesNo("Would you like to see the generated module.json?", false) {
		configJSON, _ := json.MarshalIndent(mg.template, "", "  ")
		fmt.Printf("\n%s\n", string(configJSON))
	}
}

// Main execution flow
func (mg *ModuleGenerator) Run() error {
	// Welcome and introduction
	color.Blue("🚀 Welcome to the SecV Module Generator!\n")
	color.White("This tool will help you create a properly structured SecV module from your existing security tool.")
	color.White("We'll ask you a series of questions and generate all the necessary configuration files.\n")
	
	// Detect environment
	mg.detectEnvironment()
	
	// Gather information step by step
	mg.gatherBasicInfo()
	mg.gatherExecutableInfo()
	mg.gatherDependencies()
	mg.gatherInputs()
	mg.gatherOutputs()
	
	// Create the module structure
	if err := mg.createModuleStructure(); err != nil {
		return err
	}
	
	// Generate all the files
	if err := mg.generateModuleConfig(); err != nil {
		return err
	}
	
	if err := mg.generateWrapperScript(); err != nil {
		return err
	}
	
	if err := mg.generateDocumentation(); err != nil {
		return err
	}
	
	// Show summary
	mg.showSummary()
	
	return nil
}

// Main function
func main() {
	generator := NewModuleGenerator()
	
	if err := generator.Run(); err != nil {
		color.Red("Error: %v", err)
		os.Exit(1)
	}
}
