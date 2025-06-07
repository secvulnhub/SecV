package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// --- Enhanced Data Structures ---

type ModuleMetadata struct {
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Category     string                 `json:"category"`
	Description  string                 `json:"description"`
	Author       string                 `json:"author"`
	Executable   string                 `json:"executable"`
	Dependencies []string               `json:"dependencies"`
	Inputs       map[string]interface{} `json:"inputs"`
	Outputs      map[string]interface{} `json:"outputs"`
	Timeout      int                    `json:"timeout,omitempty"` // Timeout in seconds
	Concurrent   bool                   `json:"concurrent"`        // Can run concurrently
}

type ExecutionContext struct {
	Target     string                  `json:"target"`
	Parameters map[string]interface{}  `json:"parameters"`
	Results    map[string]ModuleResult `json:"results"`
	WorkflowID string                  `json:"workflow_id,omitempty"`
	StepID     string                  `json:"step_id,omitempty"`
}

type ModuleResult struct {
	Success         bool        `json:"success"`
	Data            interface{} `json:"data"`
	Errors          []string    `json:"errors"`
	ExecutionTimeMs int64       `json:"execution_time_ms"`
	ModuleName      string      `json:"module_name"`
	Timestamp       time.Time   `json:"timestamp"`
}

// --- Enhanced Workflow Support ---

type WorkflowStep struct {
	Name      string                 `json:"name"`
	Module    string                 `json:"module"`
	Inputs    map[string]interface{} `json:"inputs"`
	Condition string                 `json:"condition,omitempty"`
	OnError   string                 `json:"on_error,omitempty"` // "continue", "stop", "retry"
	Timeout   int                    `json:"timeout,omitempty"`
}

type WorkflowDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Version     string         `json:"version"`
	Steps       []WorkflowStep `json:"steps"`
}

type WorkflowExecution struct {
	ID           string                      `json:"id"`
	Definition   WorkflowDefinition          `json:"definition"`
	Target       string                      `json:"target"`
	StartTime    time.Time                   `json:"start_time"`
	EndTime      time.Time                   `json:"end_time"`
	Status       string                      `json:"status"` // "running", "completed", "failed", "cancelled"
	StepResults  map[string]ModuleResult     `json:"step_results"`
	GlobalParams map[string]interface{}      `json:"global_params"`
	mu           sync.RWMutex                `json:"-"`
}

// --- Enhanced Module Loader with Validation ---

type ModuleLoader struct {
	Modules   map[string]ModuleMetadata
	ToolsDir  string
	Logger    *log.Logger
}

func NewModuleLoader(toolsDir string) (*ModuleLoader, error) {
	logger := log.New(os.Stdout, "[ModuleLoader] ", log.LstdFlags)
	loader := &ModuleLoader{
		Modules:  make(map[string]ModuleMetadata),
		ToolsDir: toolsDir,
		Logger:   logger,
	}
	
	if err := loader.loadModules(); err != nil {
		return nil, err
	}
	
	return loader, nil
}

func (m *ModuleLoader) loadModules() error {
	moduleCount := 0
	
	err := filepath.Walk(m.ToolsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			m.Logger.Printf("Warning: Error accessing path %s: %v", path, err)
			return nil // Continue walking despite errors
		}
		
		if info.Name() == "module.json" {
			if err := m.loadSingleModule(path); err != nil {
				color.Yellow("! Failed to load module at %s: %v", path, err)
			} else {
				moduleCount++
			}
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("error discovering modules: %w", err)
	}
	
	color.Green("✓ Successfully loaded %d modules", moduleCount)
	return nil
}

func (m *ModuleLoader) loadSingleModule(configPath string) error {
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("could not read module config: %w", err)
	}

	var meta ModuleMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return fmt.Errorf("could not parse module config: %w", err)
	}

	// Validate required fields
	if meta.Name == "" {
		return fmt.Errorf("module name is required")
	}
	if meta.Executable == "" {
		return fmt.Errorf("executable path is required")
	}

	// Set default timeout if not specified
	if meta.Timeout == 0 {
		meta.Timeout = 300 // 5 minutes default
	}

	// Resolve executable path relative to module directory
	moduleDir := filepath.Dir(configPath)
	if !filepath.IsAbs(meta.Executable) {
		meta.Executable = filepath.Join(moduleDir, meta.Executable)
	}

	// Verify executable exists and is executable
	if _, err := os.Stat(meta.Executable); os.IsNotExist(err) {
		return fmt.Errorf("executable not found: %s", meta.Executable)
	}

	m.Modules[meta.Name] = meta
	color.Cyan("  ✓ Loaded module: %s v%s", meta.Name, meta.Version)
	return nil
}

func (m *ModuleLoader) GetModule(name string) (ModuleMetadata, bool) {
	meta, found := m.Modules[name]
	return meta, found
}

func (m *ModuleLoader) ListModules() []ModuleMetadata {
	modules := make([]ModuleMetadata, 0, len(m.Modules))
	for _, module := range m.Modules {
		modules = append(modules, module)
	}
	return modules
}

func (m *ModuleLoader) GetModulesByCategory(category string) []ModuleMetadata {
	var modules []ModuleMetadata
	for _, module := range m.Modules {
		if strings.EqualFold(module.Category, category) {
			modules = append(modules, module)
		}
	}
	return modules
}

// --- Enhanced Execution Engine ---

type ExecutionEngine struct {
	loader *ModuleLoader
	logger *log.Logger
}

func NewExecutionEngine(loader *ModuleLoader) *ExecutionEngine {
	return &ExecutionEngine{
		loader: loader,
		logger: log.New(os.Stdout, "[ExecutionEngine] ", log.LstdFlags),
	}
}

func (e *ExecutionEngine) ExecuteModule(module ModuleMetadata, execContext ExecutionContext) (ModuleResult, error) {
	start := time.Now()
	
	// Create execution context with timeout
	timeout := time.Duration(module.Timeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	
	// Serialize context to JSON for stdin
	contextJSON, err := json.Marshal(execContext)
	if err != nil {
		return ModuleResult{}, fmt.Errorf("failed to serialize context: %w", err)
	}

	// Parse executable command (handle commands with arguments)
	cmdParts := strings.Fields(module.Executable)
	if len(cmdParts) == 0 {
		return ModuleResult{}, fmt.Errorf("empty executable command")
	}

	// Create command with context for timeout support
	cmd := exec.CommandContext(ctx, cmdParts[0], cmdParts[1:]...)
	cmd.Dir = filepath.Dir(module.Executable)
	cmd.Stdin = bytes.NewReader(contextJSON)
	
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	color.Yellow("⚙️  Executing %s against %s (timeout: %ds)...", 
		module.Name, execContext.Target, module.Timeout)
	
	// Execute the command
	err = cmd.Run()
	executionTime := time.Since(start).Milliseconds()
	
	// Handle different types of errors
	if ctx.Err() == context.DeadlineExceeded {
		return ModuleResult{
			Success:         false,
			Errors:          []string{fmt.Sprintf("Module execution timed out after %d seconds", module.Timeout)},
			ExecutionTimeMs: executionTime,
			ModuleName:      module.Name,
			Timestamp:       start,
		}, nil
	}
	
	if err != nil {
		errorMsg := fmt.Sprintf("Module execution failed: %s", err)
		if stderr.Len() > 0 {
			errorMsg += fmt.Sprintf("\nStderr: %s", stderr.String())
		}
		
		return ModuleResult{
			Success:         false,
			Errors:          []string{errorMsg},
			ExecutionTimeMs: executionTime,
			ModuleName:      module.Name,
			Timestamp:       start,
		}, nil
	}

	// Parse the module output
	var result ModuleResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return ModuleResult{
			Success:         false,
			Errors:          []string{fmt.Sprintf("Failed to parse module output: %v\nOutput: %s", err, stdout.String())},
			ExecutionTimeMs: executionTime,
			ModuleName:      module.Name,
			Timestamp:       start,
		}, nil
	}
	
	// Ensure result metadata is set
	result.ExecutionTimeMs = executionTime
	result.ModuleName = module.Name
	result.Timestamp = start
	
	return result, nil
}

// --- Workflow Engine ---

type WorkflowEngine struct {
	executionEngine *ExecutionEngine
	logger         *log.Logger
	executions     map[string]*WorkflowExecution
	mu             sync.RWMutex
}

func NewWorkflowEngine(executionEngine *ExecutionEngine) *WorkflowEngine {
	return &WorkflowEngine{
		executionEngine: executionEngine,
		logger:         log.New(os.Stdout, "[WorkflowEngine] ", log.LstdFlags),
		executions:     make(map[string]*WorkflowExecution),
	}
}

func (w *WorkflowEngine) LoadWorkflow(filePath string) (WorkflowDefinition, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return WorkflowDefinition{}, fmt.Errorf("failed to read workflow file: %w", err)
	}

	var workflow WorkflowDefinition
	if err := json.Unmarshal(data, &workflow); err != nil {
		return WorkflowDefinition{}, fmt.Errorf("failed to parse workflow: %w", err)
	}

	return workflow, nil
}

func (w *WorkflowEngine) ExecuteWorkflow(workflow WorkflowDefinition, target string, params map[string]interface{}) (*WorkflowExecution, error) {
	executionID := fmt.Sprintf("wf_%d", time.Now().Unix())
	
	execution := &WorkflowExecution{
		ID:           executionID,
		Definition:   workflow,
		Target:       target,
		StartTime:    time.Now(),
		Status:       "running",
		StepResults:  make(map[string]ModuleResult),
		GlobalParams: params,
	}
	
	w.mu.Lock()
	w.executions[executionID] = execution
	w.mu.Unlock()
	
	go w.runWorkflow(execution)
	
	return execution, nil
}

func (w *WorkflowEngine) runWorkflow(execution *WorkflowExecution) {
	defer func() {
		execution.mu.Lock()
		execution.EndTime = time.Now()
		if execution.Status == "running" {
			execution.Status = "completed"
		}
		execution.mu.Unlock()
	}()

	color.Green("🚀 Starting workflow: %s", execution.Definition.Name)
	
	for i, step := range execution.Definition.Steps {
		w.logger.Printf("Executing step %d/%d: %s", i+1, len(execution.Definition.Steps), step.Name)
		
		// Check if step should be executed based on condition
		if step.Condition != "" {
			// Simple condition evaluation (can be enhanced with expression parser)
			shouldExecute := w.evaluateCondition(step.Condition, execution.StepResults)
			if !shouldExecute {
				color.Yellow("⏭️  Skipping step '%s' due to condition", step.Name)
				continue
			}
		}
		
		// Get the module for this step
		module, found := w.executionEngine.loader.GetModule(step.Module)
		if !found {
			errorMsg := fmt.Sprintf("Module '%s' not found", step.Module)
			result := ModuleResult{
				Success:    false,
				Errors:     []string{errorMsg},
				ModuleName: step.Module,
				Timestamp:  time.Now(),
			}
			
			execution.mu.Lock()
			execution.StepResults[step.Name] = result
			execution.mu.Unlock()
			
			if step.OnError != "continue" {
				execution.mu.Lock()
				execution.Status = "failed"
				execution.mu.Unlock()
				color.Red("❌ Workflow failed at step: %s", step.Name)
				return
			}
			continue
		}
		
		// Prepare execution context
		execContext := ExecutionContext{
			Target:     execution.Target,
			Parameters: step.Inputs,
			Results:    execution.StepResults,
			WorkflowID: execution.ID,
			StepID:     step.Name,
		}
		
		// Execute the module
		result, err := w.executionEngine.ExecuteModule(module, execContext)
		if err != nil {
			w.logger.Printf("Error executing step '%s': %v", step.Name, err)
			result = ModuleResult{
				Success:    false,
				Errors:     []string{err.Error()},
				ModuleName: step.Module,
				Timestamp:  time.Now(),
			}
		}
		
		// Store the result
		execution.mu.Lock()
		execution.StepResults[step.Name] = result
		execution.mu.Unlock()
		
		// Handle step failure
		if !result.Success {
			color.Red("❌ Step '%s' failed", step.Name)
			if step.OnError == "continue" {
				color.Yellow("⏭️  Continuing to next step due to on_error policy")
				continue
			} else {
				execution.mu.Lock()
				execution.Status = "failed"
				execution.mu.Unlock()
				color.Red("❌ Workflow failed at step: %s", step.Name)
				return
			}
		} else {
			color.Green("✅ Step '%s' completed successfully", step.Name)
		}
	}
	
	color.Green("🎉 Workflow completed successfully: %s", execution.Definition.Name)
}

func (w *WorkflowEngine) evaluateCondition(condition string, results map[string]ModuleResult) bool {
	// Simple condition evaluation - can be enhanced with a proper expression parser
	// For now, support basic success checks like "results.step_name.success"
	if strings.Contains(condition, ".success") {
		stepName := strings.Split(strings.TrimPrefix(condition, "results."), ".")[0]
		if result, exists := results[stepName]; exists {
			return result.Success
		}
	}
	return true // Default to true if condition can't be evaluated
}

// --- Enhanced CLI Commands ---

func main() {
	var target, params, file string
	var timeout int

	// Initialize color output
	color.NoColor = false

	var rootCmd = &cobra.Command{
		Use:   "secv",
		Short: "SecV - The Polyglot Cybersecurity Orchestration Platform v0.0.2",
		Long: `SecV is a next-generation cybersecurity orchestration platform designed for 
performance, flexibility, and collaboration. Execute security tools and orchestrate 
sophisticated workflows from a unified engine.`,
	}

	// -- Init Command --
	var initCmd = &cobra.Command{
		Use:   "init",
		Short: "Initialize SecV directory structure and example modules",
		Run: func(cmd *cobra.Command, args []string) {
			dirs := []string{"tools", "workflows", "docs", "scripts"}
			for _, dir := range dirs {
				if err := os.MkdirAll(dir, 0755); err != nil {
					color.Red("Error creating directory %s: %v", dir, err)
					return
				}
			}
			color.Green("✅ SecV directories initialized successfully!")
			color.White("📁 Created: tools/, workflows/, docs/, scripts/")
			color.White("🚀 Run 'go run secv.go list' to see available modules")
		},
	}

	// -- List Command --
	var listCmd = &cobra.Command{
		Use:   "list",
		Short: "List all available modules",
		Run: func(cmd *cobra.Command, args []string) {
			loader, err := NewModuleLoader("tools")
			if err != nil {
				color.Red("Failed to load modules: %v", err)
				return
			}

			modules := loader.ListModules()
			if len(modules) == 0 {
				color.Yellow("No modules found. Run 'secv init' to set up the directory structure.")
				return
			}

			color.Green("📋 Available Modules (%d total):\n", len(modules))
			
			// Group by category
			categories := make(map[string][]ModuleMetadata)
			for _, module := range modules {
				category := module.Category
				if category == "" {
					category = "uncategorized"
				}
				categories[category] = append(categories[category], module)
			}

			for category, categoryModules := range categories {
				color.Cyan("📂 %s:", strings.Title(category))
				for _, module := range categoryModules {
					fmt.Printf("  • %s v%s - %s\n", 
						color.WhiteString(module.Name), 
						color.GreenString(module.Version), 
						module.Description)
					if module.Author != "" {
						fmt.Printf("    👤 %s\n", color.CyanString(module.Author))
					}
				}
				fmt.Println()
			}
		},
	}

	// -- Execute Command --
	var executeCmd = &cobra.Command{
		Use:   "execute [module_name]",
		Short: "Execute a single module",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			moduleName := args[0]
			
			loader, err := NewModuleLoader("tools")
			if err != nil {
				color.Red("Failed to load modules: %v", err)
				return
			}

			module, found := loader.GetModule(moduleName)
			if !found {
				color.Red("❌ Module '%s' not found.", moduleName)
				color.Yellow("💡 Run 'secv list' to see available modules")
				return
			}

			// Parse parameters
			var p map[string]interface{}
			if params != "" {
				if err := json.Unmarshal([]byte(params), &p); err != nil {
					color.Red("❌ Invalid parameters JSON: %v", err)
					return
				}
			}

			// Create execution context
			context := ExecutionContext{
				Target:     target,
				Parameters: p,
				Results:    make(map[string]ModuleResult),
			}

			// Execute module
			engine := NewExecutionEngine(loader)
			result, err := engine.ExecuteModule(module, context)
			if err != nil {
				color.Red("❌ Execution Error: %v", err)
				return
			}

			// Display results
			if result.Success {
				color.Green("✅ Execution completed successfully in %dms", result.ExecutionTimeMs)
			} else {
				color.Red("❌ Execution failed in %dms", result.ExecutionTimeMs)
				for _, errMsg := range result.Errors {
					color.Red("   Error: %s", errMsg)
				}
			}

			// Pretty print the result data
			if result.Data != nil {
				prettyResult, _ := json.MarshalIndent(result.Data, "", "  ")
				fmt.Printf("\n📊 Result Data:\n%s\n", string(prettyResult))
			}
		},
	}
	executeCmd.Flags().StringVarP(&target, "target", "t", "", "Primary target (required)")
	executeCmd.Flags().StringVarP(&params, "params", "p", "", "Additional parameters as a JSON string")
	executeCmd.Flags().IntVar(&timeout, "timeout", 300, "Execution timeout in seconds")
	executeCmd.MarkFlagRequired("target")

	// -- Workflow Command --
	var workflowCmd = &cobra.Command{
		Use:   "workflow [workflow_file]",
		Short: "Execute a workflow from a JSON file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			workflowFile := args[0]
			
			loader, err := NewModuleLoader("tools")
			if err != nil {
				color.Red("Failed to load modules: %v", err)
				return
			}

			engine := NewExecutionEngine(loader)
			workflowEngine := NewWorkflowEngine(engine)

			workflow, err := workflowEngine.LoadWorkflow(workflowFile)
			if err != nil {
				color.Red("❌ Failed to load workflow: %v", err)
				return
			}

			// Parse global parameters
			var globalParams map[string]interface{}
			if params != "" {
				if err := json.Unmarshal([]byte(params), &globalParams); err != nil {
					color.Red("❌ Invalid parameters JSON: %v", err)
					return
				}
			}

			color.Blue("🔄 Starting workflow: %s", workflow.Name)
			execution, err := workflowEngine.ExecuteWorkflow(workflow, target, globalParams)
			if err != nil {
				color.Red("❌ Failed to start workflow: %v", err)
				return
			}

			// Wait for completion (simple polling)
			for {
				execution.mu.RLock()
				status := execution.Status
				execution.mu.RUnlock()
				
				if status != "running" {
					break
				}
				time.Sleep(1 * time.Second)
			}

			// Display final results
			execution.mu.RLock()
			finalStatus := execution.Status
			duration := execution.EndTime.Sub(execution.StartTime)
			results := execution.StepResults
			execution.mu.RUnlock()

			if finalStatus == "completed" {
				color.Green("🎉 Workflow completed successfully in %v", duration)
			} else {
				color.Red("❌ Workflow failed after %v", duration)
			}

			// Show step results summary
			fmt.Printf("\n📋 Step Results Summary:\n")
			for stepName, result := range results {
				status := "❌ FAILED"
				if result.Success {
					status = "✅ SUCCESS"
				}
				fmt.Printf("  %s %s (%dms)\n", status, stepName, result.ExecutionTimeMs)
			}
		},
	}
	workflowCmd.Flags().StringVarP(&target, "target", "t", "", "Primary target (required)")
	workflowCmd.Flags().StringVarP(&params, "params", "p", "", "Global parameters as a JSON string")
	workflowCmd.MarkFlagRequired("target")

	// -- Interactive Mode --
	var interactiveCmd = &cobra.Command{
		Use:   "interactive",
		Short: "Start SecV in interactive mode",
		Run: func(cmd *cobra.Command, args []string) {
			loader, err := NewModuleLoader("tools")
			if err != nil {
				color.Red("Failed to load modules: %v", err)
				return
			}

			engine := NewExecutionEngine(loader)
			
			color.Green("🎮 Welcome to SecV Interactive Mode!")
			color.White("Available modules: %d", len(loader.Modules))

			moduleNames := make([]string, 0, len(loader.Modules))
			for name := range loader.Modules {
				moduleNames = append(moduleNames, name)
			}

			for {
				action := ""
				prompt := &survey.Select{
					Message: "Choose an action:",
					Options: []string{"Execute Module", "List Modules", "Module Info", "Exit"},
				}
				if err := survey.AskOne(prompt, &action); err != nil {
					break
				}

				switch action {
				case "Execute Module":
					if len(moduleNames) == 0 {
						color.Yellow("No modules available")
						continue
					}

					moduleName := ""
					target := ""
					
					if err := survey.AskOne(&survey.Select{
						Message: "Select module:", 
						Options: moduleNames,
					}, &moduleName); err != nil {
						continue
					}
					
					if err := survey.AskOne(&survey.Input{
						Message: "Enter target:",
					}, &target); err != nil {
						continue
					}

					module, _ := loader.GetModule(moduleName)
					context := ExecutionContext{
						Target:  target,
						Results: make(map[string]ModuleResult),
					}
					
					result, err := engine.ExecuteModule(module, context)
					if err != nil {
						color.Red("❌ Execution Error: %v", err)
					} else if result.Success {
						color.Green("✅ Success! (%dms)", result.ExecutionTimeMs)
						if result.Data != nil {
							pretty, _ := json.MarshalIndent(result.Data, "", "  ")
							fmt.Printf("\n📊 Result:\n%s\n\n", string(pretty))
						}
					} else {
						color.Red("❌ Module execution failed")
						for _, errMsg := range result.Errors {
							color.Red("   %s", errMsg)
						}
					}

				case "List Modules":
					modules := loader.ListModules()
					fmt.Printf("\n📋 Available Modules (%d):\n", len(modules))
					for _, module := range modules {
						fmt.Printf("  • %s v%s [%s]\n", 
							color.WhiteString(module.Name),
							color.GreenString(module.Version),
							color.CyanString(module.Category))
					}
					fmt.Println()

				case "Module Info":
					if len(moduleNames) == 0 {
						color.Yellow("No modules available")
						continue
					}

					moduleName := ""
					if err := survey.AskOne(&survey.Select{
						Message: "Select module for details:", 
						Options: moduleNames,
					}, &moduleName); err != nil {
						continue
					}

					module, _ := loader.GetModule(moduleName)
					fmt.Printf("\n📄 Module Details: %s\n", color.CyanString(module.Name))
					fmt.Printf("Version: %s\n", module.Version)
					fmt.Printf("Category: %s\n", module.Category)
					fmt.Printf("Description: %s\n", module.Description)
					fmt.Printf("Author: %s\n", module.Author)
					fmt.Printf("Executable: %s\n", module.Executable)
					fmt.Printf("Timeout: %ds\n", module.Timeout)
					if len(module.Dependencies) > 0 {
						fmt.Printf("Dependencies: %s\n", strings.Join(module.Dependencies, ", "))
					}
					fmt.Println()

				case "Exit":
					color.Green("👋 Thanks for using SecV!")
					return
				}
			}
		},
	}

	// Add all commands to root
	rootCmd.AddCommand(initCmd, listCmd, executeCmd, workflowCmd, interactiveCmd)
	
	// Execute the CLI
	if err := rootCmd.Execute(); err != nil {
		color.Red("Error: %v", err)
		os.Exit(1)
	}
}
