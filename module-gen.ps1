#!/usr/bin/env pwsh

<#
.SYNOPSIS
    SecV Module Generator - PowerShell Version
    
.DESCRIPTION
    This script helps contributors create new modules for the SecV platform.
    Compatible with Windows, Linux, and macOS systems running PowerShell Core.
    
.PARAMETER ModuleName
    Name of the module to create
    
.PARAMETER Interactive
    Run in interactive mode (default)
    
.EXAMPLE
    .\New-SecVModule.ps1
    .\New-SecVModule.ps1 -ModuleName "port-scanner" -Interactive
#>

[CmdletBinding()]
param(
    [string]$ModuleName,
    [switch]$Interactive = $true
)

# Global variables for module configuration
$script:ModuleConfig = @{
    Name = ""
    Version = ""
    Category = ""
    Description = ""
    Author = ""
    ExecutableType = ""
    Timeout = 300
    Concurrent = $false
    Dependencies = @()
    Inputs = @()
    Outputs = @()
}

# Color output functions for cross-platform compatibility
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    
    $colorMap = @{
        "Red" = [ConsoleColor]::Red
        "Green" = [ConsoleColor]::Green
        "Yellow" = [ConsoleColor]::Yellow
        "Blue" = [ConsoleColor]::Blue
        "Cyan" = [ConsoleColor]::Cyan
        "White" = [ConsoleColor]::White
        "Gray" = [ConsoleColor]::Gray
    }
    
    if ($colorMap.ContainsKey($Color)) {
        Write-Host $Message -ForegroundColor $colorMap[$Color]
    } else {
        Write-Host $Message
    }
}

function Show-Banner {
    Write-ColorOutput "╔══════════════════════════════════════════════════════════════╗" "Cyan"
    Write-ColorOutput "║                    SecV Module Generator                     ║" "Cyan"
    Write-ColorOutput "║              Create modules for SecV platform               ║" "Cyan"
    Write-ColorOutput "║                   PowerShell Version                        ║" "Cyan"
    Write-ColorOutput "╚══════════════════════════════════════════════════════════════╝" "Cyan"
    Write-Host ""
}

# Input validation functions
function Test-ModuleName {
    param([string]$Name)
    return $Name -match "^[a-zA-Z0-9_-]+$"
}

function Test-SemanticVersion {
    param([string]$Version)
    return $Version -match "^\d+\.\d+\.\d+$"
}

function Get-ValidatedInput {
    param(
        [string]$Prompt,
        [scriptblock]$Validator = $null,
        [string]$ErrorMessage = "Invalid input. Please try again.",
        [bool]$Required = $true
    )
    
    do {
        $input = Read-Host $Prompt
        
        if (-not $Required -and [string]::IsNullOrEmpty($input)) {
            return $input
        }
        
        if ([string]::IsNullOrEmpty($input) -and $Required) {
            Write-ColorOutput "❌ This field is required" "Red"
            continue
        }
        
        if ($Validator -and -not (& $Validator $input)) {
            Write-ColorOutput "❌ $ErrorMessage" "Red"
            continue
        }
        
        return $input
    } while ($true)
}

function Get-YesNoInput {
    param(
        [string]$Prompt,
        [bool]$DefaultValue = $false
    )
    
    $defaultText = if ($DefaultValue) { "Y/n" } else { "y/N" }
    
    do {
        $input = Read-Host "$Prompt [$defaultText]"
        
        if ([string]::IsNullOrEmpty($input)) {
            return $DefaultValue
        }
        
        switch ($input.ToLower()) {
            { $_ -in @("y", "yes", "true", "1") } { return $true }
            { $_ -in @("n", "no", "false", "0") } { return $false }
            default { 
                Write-ColorOutput "Please enter 'y' for yes or 'n' for no" "Yellow"
            }
        }
    } while ($true)
}

function Get-ArrayInput {
    param(
        [string]$Prompt,
        [string]$Description
    )
    
    Write-ColorOutput $Description "Yellow"
    Write-Host "Enter items one by one (press Enter with empty input to finish):"
    
    $items = @()
    $counter = 1
    
    do {
        $input = Read-Host "  $counter. "
        
        if ([string]::IsNullOrEmpty($input)) {
            break
        }
        
        $items += $input
        $counter++
    } while ($true)
    
    return $items
}

function Get-IOSpecifications {
    param(
        [string]$Type  # "input" or "output"
    )
    
    Write-ColorOutput "Define $Type specifications:" "Yellow"
    Write-ColorOutput "Format: name:type:description (e.g., 'target:string:IP address or hostname')" "Blue"
    Write-Host "Enter specifications one by one (press Enter with empty input to finish):"
    
    $specs = @()
    $counter = 1
    
    do {
        $input = Read-Host "  $counter. "
        
        if ([string]::IsNullOrEmpty($input)) {
            break
        }
        
        $parts = $input -split ":", 3
        if ($parts.Count -eq 3) {
            $spec = @{
                name = $parts[0].Trim()
                type = $parts[1].Trim()  
                description = $parts[2].Trim()
            }
            $specs += $spec
            $counter++
        } else {
            Write-ColorOutput "❌ Please use the format: name:type:description" "Red"
        }
    } while ($true)
    
    return $specs
}

function New-DirectoryStructure {
    $baseDir = "tools\$($script:ModuleConfig.Name)"
    
    if (Test-Path $baseDir) {
        Write-ColorOutput "⚠️  Directory $baseDir already exists" "Yellow"
        $overwrite = Get-YesNoInput "Do you want to overwrite it?" $false
        
        if (-not $overwrite) {
            Write-ColorOutput "❌ Module generation cancelled" "Red"
            exit 1
        }
        
        Remove-Item $baseDir -Recurse -Force
    }
    
    New-Item -ItemType Directory -Path $baseDir -Force | Out-Null
    Write-ColorOutput "✅ Created directory: $baseDir" "Green"
}

function New-ModuleJson {
    $jsonPath = "tools\$($script:ModuleConfig.Name)\module.json"
    
    # Build input/output objects
    $inputsObj = @{}
    foreach ($spec in $script:ModuleConfig.Inputs) {
        $inputsObj[$spec.name] = @{
            type = $spec.type
            description = $spec.description
        }
    }
    
    $outputsObj = @{}
    foreach ($spec in $script:ModuleConfig.Outputs) {
        $outputsObj[$spec.name] = @{
            type = $spec.type
            description = $spec.description
        }
    }
    
    # Create module configuration object
    $moduleObj = @{
        name = $script:ModuleConfig.Name
        version = $script:ModuleConfig.Version
        category = $script:ModuleConfig.Category
        description = $script:ModuleConfig.Description
        author = $script:ModuleConfig.Author
        executable = $script:ModuleConfig.ExecutableType
        timeout = $script:ModuleConfig.Timeout
        concurrent = $script:ModuleConfig.Concurrent
        dependencies = $script:ModuleConfig.Dependencies
        inputs = $inputsObj
        outputs = $outputsObj
    }
    
    # Convert to JSON and save
    $jsonContent = $moduleObj | ConvertTo-Json -Depth 10
    Set-Content -Path $jsonPath -Value $jsonContent -Encoding UTF8
    
    Write-ColorOutput "✅ Generated: $jsonPath" "Green"
}

function New-ExecutableTemplate {
    $execPath = "tools\$($script:ModuleConfig.Name)\$($script:ModuleConfig.ExecutableType)"
    
    switch -Regex ($script:ModuleConfig.ExecutableType) {
        "\.sh$" { New-BashTemplate $execPath }
        "\.py$" { New-PythonTemplate $execPath }
        "\.go$" { New-GoTemplate $execPath }
        "\.ps1$" { New-PowerShellTemplate $execPath }
        default { 
            Write-ColorOutput "⚠️  Unknown executable type. Creating basic template." "Yellow"
            New-Item -ItemType File -Path $execPath -Force | Out-Null
        }
    }
    
    Write-ColorOutput "✅ Generated executable template: $execPath" "Green"
}

function New-PowerShellTemplate {
    param([string]$FilePath)
    
    $template = @"
# SecV Module: $($script:ModuleConfig.Name)
# This script reads JSON context from stdin and outputs JSON results to stdout

param()

# Function to output success result
function Write-SuccessResult {
    param([Parameter(Mandatory=`$true)]`$Data)
    
    `$result = @{
        success = `$true
        data = `$Data
        errors = @()
        execution_time_ms = 0
        module_name = "$($script:ModuleConfig.Name)"
        timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffK")
    }
    
    `$result | ConvertTo-Json -Depth 10
}

function Write-ErrorResult {
    param([Parameter(Mandatory=`$true)][string]`$ErrorMessage)
    
    `$result = @{
        success = `$false
        data = @{}
        errors = @(`$ErrorMessage)
        execution_time_ms = 0
        module_name = "$($script:ModuleConfig.Name)"
        timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffK")
    }
    
    `$result | ConvertTo-Json -Depth 10
}

try {
    # Read execution context from stdin
    `$inputLines = @()
    while (`$null -ne (`$line = [Console]::ReadLine())) {
        `$inputLines += `$line
    }
    `$contextJson = `$inputLines -join "`n"
    `$context = `$contextJson | ConvertFrom-Json
    
    # Extract target and parameters
    `$target = `$context.target
    `$parameters = `$context.parameters
    
    # Validate that target is provided
    if (-not `$target) {
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
    `$sampleData = @{
        message = "Module executed successfully"
        target = `$target
    }
    
    Write-SuccessResult `$sampleData
}
catch {
    Write-ErrorResult "Module execution failed: `$(`$_.Exception.Message)"
}
"@
    
    Set-Content -Path $FilePath -Value $template -Encoding UTF8
}

function New-PythonTemplate {
    param([string]$FilePath)
    
    $template = @"
#!/usr/bin/env python3
"""
SecV Module: $($script:ModuleConfig.Name)
This script reads JSON context from stdin and outputs JSON results to stdout
"""

import json
import sys
import datetime

class SecVModule:
    def __init__(self):
        self.module_name = "$($script:ModuleConfig.Name)"
        
    def read_context(self):
        try:
            context = json.loads(sys.stdin.read())
            return context
        except json.JSONDecodeError as e:
            self.output_error(f"Failed to parse input context: {str(e)}")
            sys.exit(0)
    
    def output_success(self, data):
        result = {
            "success": True,
            "data": data,
            "errors": [],
            "execution_time_ms": 0,
            "module_name": self.module_name,
            "timestamp": datetime.datetime.now().isoformat()
        }
        print(json.dumps(result, indent=2))
    
    def output_error(self, error_message):
        result = {
            "success": False,
            "data": {},
            "errors": [error_message],
            "execution_time_ms": 0,
            "module_name": self.module_name,
            "timestamp": datetime.datetime.now().isoformat()
        }
        print(json.dumps(result, indent=2))
    
    def execute(self):
        context = self.read_context()
        target = context.get('target', '')
        parameters = context.get('parameters', {})
        
        if not target:
            self.output_error("Target is required")
            return
        
        # TODO: Implement your module logic here
        sample_data = {"message": "Module executed successfully", "target": target}
        self.output_success(sample_data)

if __name__ == "__main__":
    module = SecVModule()
    module.execute()
"@
    
    Set-Content -Path $FilePath -Value $template -Encoding UTF8
}

function New-BashTemplate {
    param([string]$FilePath)
    
    $template = @"
#!/bin/bash
# SecV Module: $($script:ModuleConfig.Name)

set -e
CONTEXT=`$(cat)
TARGET=`$(echo "`$CONTEXT" | jq -r '.target // empty')

output_success() {
    local data=`$1
    local timestamp=`$(date -Iseconds)
    echo '{"success":true,"data":'"`$data"',"errors":[],"module_name":"$($script:ModuleConfig.Name)","timestamp":"'"`$timestamp"'"}'
}

output_error() {
    local error=`$1
    local timestamp=`$(date -Iseconds)
    echo '{"success":false,"data":{},"errors":["'"`$error"'"],"module_name":"$($script:ModuleConfig.Name)","timestamp":"'"`$timestamp"'"}'
}

if [[ -z "`$TARGET" ]]; then
    output_error "Target is required"
    exit 0
fi

# TODO: Implement module logic
sample_data='{"message":"Module executed successfully","target":"'"`$TARGET"'"}'
output_success "`$sample_data"
"@
    
    Set-Content -Path $FilePath -Value $template -Encoding UTF8
}

function New-GoTemplate {
    param([string]$FilePath)
    
    $template = @"
package main

import (
    "encoding/json"
    "fmt"
    "os"
    "time"
)

type ExecutionContext struct {
    Target     string                 ``json:"target"``
    Parameters map[string]interface{} ``json:"parameters"``
}

type ModuleResult struct {
    Success         bool        ``json:"success"``
    Data            interface{} ``json:"data"``
    Errors          []string    ``json:"errors"``
    ExecutionTimeMs int64       ``json:"execution_time_ms"``
    ModuleName      string      ``json:"module_name"``
    Timestamp       time.Time   ``json:"timestamp"``
}

func outputSuccess(data interface{}) {
    result := ModuleResult{
        Success: true, Data: data, Errors: []string{},
        ModuleName: "$($script:ModuleConfig.Name)", Timestamp: time.Now(),
    }
    output, _ := json.MarshalIndent(result, "", "  ")
    fmt.Println(string(output))
}

func outputError(errorMessage string) {
    result := ModuleResult{
        Success: false, Data: nil, Errors: []string{errorMessage},
        ModuleName: "$($script:ModuleConfig.Name)", Timestamp: time.Now(),
    }
    output, _ := json.MarshalIndent(result, "", "  ")
    fmt.Println(string(output))
}

func main() {
    var context ExecutionContext
    decoder := json.NewDecoder(os.Stdin)
    if err := decoder.Decode(&context); err != nil {
        outputError(fmt.Sprintf("Failed to parse input: %v", err))
        return
    }
    
    if context.Target == "" {
        outputError("Target is required")
        return
    }
    
    // TODO: Implement module logic
    sampleData := map[string]interface{}{
        "message": "Module executed successfully",
        "target": context.Target,
    }
    outputSuccess(sampleData)
}
"@
    
    Set-Content -Path $FilePath -Value $template -Encoding UTF8
}

function New-ReadmeFile {
    $readmePath = "tools\$($script:ModuleConfig.Name)\README.md"
    
    $inputsSection = ""
    foreach ($spec in $script:ModuleConfig.Inputs) {
        $inputsSection += "- **$($spec.name)** ($($spec.type)): $($spec.description)`n"
    }
    
    $outputsSection = ""
    foreach ($spec in $script:ModuleConfig.Outputs) {
        $outputsSection += "- **$($spec.name)** ($($spec.type)): $($spec.description)`n"
    }
    
    $dependenciesSection = ""
    foreach ($dep in $script:ModuleConfig.Dependencies) {
        $dependenciesSection += "- $dep`n"
    }
    
    $readme = @"
# $($script:ModuleConfig.Name)

**Version:** $($script:ModuleConfig.Version)  
**Category:** $($script:ModuleConfig.Category)  
**Author:** $($script:ModuleConfig.Author)

## Description

$($script:ModuleConfig.Description)

## Usage

Execute this module using the SecV platform:

``````bash
secv execute $($script:ModuleConfig.Name) --target <target> --params '<json_params>'
``````

## Inputs

$inputsSection

## Outputs

$outputsSection

## Dependencies

$dependenciesSection

## Configuration

- **Timeout:** $($script:ModuleConfig.Timeout) seconds
- **Concurrent Execution:** $($script:ModuleConfig.Concurrent)

## Development

To modify this module:

1. Edit the executable file: `$($script:ModuleConfig.ExecutableType)`
2. Update the module.json if needed
3. Test with: `secv execute $($script:ModuleConfig.Name) --target test.example.com`

## Notes

- Generated using SecV Module Generator (PowerShell Version)
- Follow SecV conventions for input/output JSON formatting
- Ensure proper error handling and timeout management
"@
    
    Set-Content -Path $readmePath -Value $readme -Encoding UTF8
    Write-ColorOutput "✅ Generated: $readmePath" "Green"
}

function Get-ModuleInformation {
    Write-ColorOutput "📝 Let's gather information about your new module..." "Blue"
    Write-Host ""
    
    # Basic module information
    $script:ModuleConfig.Name = Get-ValidatedInput "Module name (alphanumeric, hyphens, underscores only)" { param($n) Test-ModuleName $n } "Module name can only contain letters, numbers, hyphens, and underscores"
    $script:ModuleConfig.Version = Get-ValidatedInput "Module version (semantic versioning, e.g., 1.0.0)" { param($v) Test-SemanticVersion $v } "Version must follow semantic versioning (e.g., 1.0.0)"
    $script:ModuleConfig.Category = Get-ValidatedInput "Module category (e.g., reconnaissance, vulnerability-scanning, exploitation)"
    $script:ModuleConfig.Description = Get-ValidatedInput "Module description"
    $script:ModuleConfig.Author = Get-ValidatedInput "Author name/email"
    
    # Executable type selection
    Write-ColorOutput "Select executable type:" "Yellow"
    Write-Host "1. PowerShell script (.ps1)"
    Write-Host "2. Python script (.py)"
    Write-Host "3. Bash script (.sh)"
    Write-Host "4. Go program (.go)"
    Write-Host "5. Custom executable"
    
    do {
        $choice = Read-Host "Enter choice (1-5)"
        switch ($choice) {
            "1" { $script:ModuleConfig.ExecutableType = "$($script:ModuleConfig.Name).ps1"; break }
            "2" { $script:ModuleConfig.ExecutableType = "$($script:ModuleConfig.Name).py"; break }
            "3" { $script:ModuleConfig.ExecutableType = "$($script:ModuleConfig.Name).sh"; break }
            "4" { $script:ModuleConfig.ExecutableType = "$($script:ModuleConfig.Name).go"; break }
            "5" { 
                $script:ModuleConfig.ExecutableType = Get-ValidatedInput "Enter executable filename"
                break 
            }
            default { Write-ColorOutput "Please enter a number between 1-5" "Red" }
        }
    } while (-not $script:ModuleConfig.ExecutableType)
    
    # Advanced configuration
    $timeoutInput = Get-ValidatedInput "Execution timeout in seconds (default: 300)" $null "" $false
    if (-not [string]::IsNullOrEmpty($timeoutInput)) {
        $script:ModuleConfig.Timeout = [int]$timeoutInput
    }
    
    $script:ModuleConfig.Concurrent = Get-YesNoInput "Can this module run concurrently?" $false
    
    # Dependencies
    $script:ModuleConfig.Dependencies = Get-ArrayInput "Dependencies" "Enter any external dependencies or tools this module requires:"
    
    # Input/Output specifications
    $script:ModuleConfig.Inputs = Get-IOSpecifications "input"
    $script:ModuleConfig.Outputs = Get-IOSpecifications "output"
}

function Show-Summary {
    Write-ColorOutput "📋 Module Summary:" "Cyan"
    Write-Host "===================="
    Write-Host "Name: $($script:ModuleConfig.Name)"
    Write-Host "Version: $($script:ModuleConfig.Version)"
    Write-Host "Category: $($script:ModuleConfig.Category)"
    Write-Host "Description: $($script:ModuleConfig.Description)"
    Write-Host "Author: $($script:ModuleConfig.Author)"
    Write-Host "Executable: $($script:ModuleConfig.ExecutableType)"
    Write-Host "Timeout: $($script:ModuleConfig.Timeout)s"
    Write-Host "Concurrent: $($script:ModuleConfig.Concurrent)"
    Write-Host "Dependencies: $($script:ModuleConfig.Dependencies.Count) items"
    Write-Host "Inputs: $($script:ModuleConfig.Inputs.Count) specifications"
    Write-Host "Outputs: $($script:ModuleConfig.Outputs.Count) specifications"
    Write-Host ""
    
    $confirm = Get-YesNoInput "Generate this module?" $true
    if (-not $confirm) {
        Write-ColorOutput "❌ Module generation cancelled" "Red"
        exit 1
    }
}

# Main execution function
function Main {
    Show-Banner
    
    # Ensure tools directory exists
    if (-not (Test-Path "tools")) {
        Write-ColorOutput "⚠️  Tools directory doesn't exist. Creating it..." "Yellow"
        New-Item -ItemType Directory -Path "tools" -Force | Out-Null
    }
    
    # Collect module information
    Get-ModuleInformation
    
    # Display summary and get confirmation
    Show-Summary
    
    # Generate the module
    Write-ColorOutput "🔧 Generating module..." "Blue"
    
    New-DirectoryStructure
    New-ModuleJson
    New-ExecutableTemplate
    New-ReadmeFile
    
    Write-ColorOutput "🎉 Module '$($script:ModuleConfig.Name)' generated successfully!" "Green"
    Write-ColorOutput "📁 Location: tools\$($script:ModuleConfig.Name)\" "Cyan"
    Write-ColorOutput "💡 Next steps:" "Yellow"
    Write-Host "   1. Implement your logic in tools\$($script:ModuleConfig.Name)\$($script:ModuleConfig.ExecutableType)"
    Write-Host "   2. Test with: secv execute $($script:ModuleConfig.Name) --target test.example.com"
    Write-Host "   3. Update README.md with specific usage examples"
}

# Execute main function
Main
