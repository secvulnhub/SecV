package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

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

type RepositoryInfo struct {
	URL         string    `json:"url"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	LastSync    time.Time `json:"last_sync"`
	Enabled     bool      `json:"enabled"`
	LocalPath   string    `json:"local_path"`
}

type RepositoryManager struct {
	repositories map[string]RepositoryInfo
	cacheDir     string
	logger       *log.Logger
	mu           sync.RWMutex
}

func NewRepositoryManager(cacheDir string) (*RepositoryManager, error) {
	logger := log.New(os.Stdout, "[RepoManager] ", log.LstdFlags)

	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	rm := &RepositoryManager{
		repositories: make(map[string]RepositoryInfo),
		cacheDir:     cacheDir,
		logger:       logger,
	}

	// Load existing repository configuration
	if err := rm.loadRepositoryConfig(); err != nil {
		rm.logger.Printf("Warning: Could not load repository config: %v", err)
	}

	// Add default SecV tools repository
	defaultRepo := RepositoryInfo{
		URL:         "https://github.com/secvulnhub/SecV",
		Name:        "secvulnhub-secv",
		Description: "Official SecV Tools Repository",
		Enabled:     true,
		LocalPath:   filepath.Join(cacheDir, "secvulnhub-secv"),
	}
	rm.repositories[defaultRepo.Name] = defaultRepo

	return rm, nil
}

func (rm *RepositoryManager) loadRepositoryConfig() error {
	configPath := filepath.Join(rm.cacheDir, "repositories.json")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil // No config file exists yet, which is fine
	}

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &rm.repositories)
}

func (rm *RepositoryManager) saveRepositoryConfig() error {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	configPath := filepath.Join(rm.cacheDir, "repositories.json")
	data, err := json.MarshalIndent(rm.repositories, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(configPath, data, 0644)
}

func (rm *RepositoryManager) AddRepository(url, name, description string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if name == "" {
		// Generate name from URL
		parts := strings.Split(strings.TrimSuffix(url, ".git"), "/")
		if len(parts) >= 2 {
			name = fmt.Sprintf("%s-%s", parts[len(parts)-2], parts[len(parts)-1])
		} else {
			name = fmt.Sprintf("repo-%d", time.Now().Unix())
		}
	}

	repo := RepositoryInfo{
		URL:         url,
		Name:        name,
		Description: description,
		Enabled:     true,
		LocalPath:   filepath.Join(rm.cacheDir, name),
	}

	rm.repositories[name] = repo
	return rm.saveRepositoryConfig()
}

func (rm *RepositoryManager) SyncRepository(name string) error {
	rm.mu.RLock()
	repo, exists := rm.repositories[name]
	rm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("repository '%s' not found", name)
	}

	if !repo.Enabled {
		return fmt.Errorf("repository '%s' is disabled", name)
	}

	color.Yellow("🔄 Syncing repository: %s", repo.Name)

	// Download the repository as a ZIP file
	zipURL := strings.TrimSuffix(repo.URL, ".git") + "/archive/refs/heads/main.zip"
	if !strings.Contains(zipURL, "/archive/") {
		zipURL = strings.TrimSuffix(repo.URL, ".git") + "/archive/refs/heads/master.zip"
	}

	resp, err := http.Get(zipURL)
	if err != nil {
		return fmt.Errorf("failed to download repository: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download repository: HTTP %d", resp.StatusCode)
	}

	// Read the ZIP content
	zipData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read repository data: %w", err)
	}

	// Extract the ZIP file
	if err := rm.extractZip(zipData, repo.LocalPath); err != nil {
		return fmt.Errorf("failed to extract repository: %w", err)
	}

	// Update sync time
	rm.mu.Lock()
	repo.LastSync = time.Now()
	rm.repositories[name] = repo
	rm.mu.Unlock()

	rm.saveRepositoryConfig()
	color.Green("✅ Repository synced successfully: %s", repo.Name)
	return nil
}

func (rm *RepositoryManager) extractZip(data []byte, destPath string) error {
	// Remove existing directory
	if err := os.RemoveAll(destPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	// Create destination directory
	if err := os.MkdirAll(destPath, 0755); err != nil {
		return err
	}

	// Read ZIP archive
	zipReader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}

	// Extract files
	for _, file := range zipReader.File {
		// Skip the root directory created by GitHub
		pathParts := strings.Split(file.Name, "/")
		if len(pathParts) > 1 {
			relativePath := strings.Join(pathParts[1:], "/")
			if relativePath == "" {
				continue
			}

			destFile := filepath.Join(destPath, relativePath)

			if file.FileInfo().IsDir() {
				os.MkdirAll(destFile, file.FileInfo().Mode())
				continue
			}

			// Create parent directories
			if err := os.MkdirAll(filepath.Dir(destFile), 0755); err != nil {
				return err
			}

			// Extract file
			rc, err := file.Open()
			if err != nil {
				return err
			}

			outFile, err := os.OpenFile(destFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.FileInfo().Mode())
			if err != nil {
				rc.Close()
				return err
			}

			_, err = io.Copy(outFile, rc)
			rc.Close()
			outFile.Close()

			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (rm *RepositoryManager) SyncAllRepositories() error {
	rm.mu.RLock()
	repoNames := make([]string, 0, len(rm.repositories))
	for name, repo := range rm.repositories {
		if repo.Enabled {
			repoNames = append(repoNames, name)
		}
	}
	rm.mu.RUnlock()

	var errors []string
	for _, name := range repoNames {
		if err := rm.SyncRepository(name); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", name, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to sync some repositories: %s", strings.Join(errors, "; "))
	}

	return nil
}

func (rm *RepositoryManager) GetToolsPaths() []string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	var paths []string

	// Add local tools directory first
	paths = append(paths, "tools")

	// Add paths from enabled repositories
	for _, repo := range rm.repositories {
		if repo.Enabled && repo.LocalPath != "" {
			toolsPath := filepath.Join(repo.LocalPath, "tools")
			if _, err := os.Stat(toolsPath); err == nil {
				paths = append(paths, toolsPath)
			}
		}
	}

	return paths
}

// --- Enhanced Module Loader with Repository Support ---

type ModuleLoader struct {
	Modules   map[string]ModuleMetadata
	RepoMgr   *RepositoryManager
	Logger    *log.Logger
}

func NewModuleLoader(repoMgr *RepositoryManager) (*ModuleLoader, error) {
	logger := log.New(os.Stdout, "[ModuleLoader] ", log.LstdFlags)
	loader := &ModuleLoader{
		Modules: make(map[string]ModuleMetadata),
		RepoMgr: repoMgr,
		Logger:  logger,
	}

	if err := loader.loadModules(); err != nil {
		return nil, err
	}

	return loader, nil
}

func (m *ModuleLoader) loadModules() error {
	moduleCount := 0
	toolsPaths := m.RepoMgr.GetToolsPaths()

	for _, toolsPath := range toolsPaths {
		if _, err := os.Stat(toolsPath); os.IsNotExist(err) {
			m.Logger.Printf("Tools directory not found: %s", toolsPath)
			continue
		}

		err := filepath.Walk(toolsPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				m.Logger.Printf("Warning: Error accessing path %s: %v", path, err)
				return nil
			}

			if info.Name() == "module.json" {
				if err := m.loadSingleModule(path, toolsPath); err != nil {
					color.Yellow("! Failed to load module at %s: %v", path, err)
				} else {
					moduleCount++
				}
			}
			return nil
		})

		if err != nil {
			m.Logger.Printf("Error walking tools directory %s: %v", toolsPath, err)
		}
	}

	color.Green("✓ Successfully loaded %d modules from %d paths", moduleCount, len(toolsPaths))
	return nil
}

func (m *ModuleLoader) loadSingleModule(configPath, basePath string) error {
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
	if meta.Executable == "" && len(meta.ExecutablesByOS) == 0 {
		return fmt.Errorf("module '%s' must have an 'executable' or 'executablesByOS' field", meta.Name)
	}

	// Set default timeout if not specified
	if meta.Timeout == 0 {
		meta.Timeout = 300 // 5 minutes default
	}

	// Store the module's directory for the execution engine
	meta.ModuleDir = filepath.Dir(configPath)

	// Determine source (local vs GitHub)
	if strings.Contains(basePath, m.RepoMgr.cacheDir) {
		meta.Source = "github"
		// Find which repository this module belongs to
		for _, repo := range m.RepoMgr.repositories {
			if strings.Contains(basePath, repo.LocalPath) {
				meta.RepoURL = repo.URL
				break
			}
		}
	} else {
		meta.Source = "local"
	}

	// Handle potential name conflicts by prefixing with source
	originalName := meta.Name
	if existing, exists := m.Modules[meta.Name]; exists {
		if existing.Source != meta.Source {
			// Rename to avoid conflicts
			meta.Name = fmt.Sprintf("%s-%s", meta.Source, originalName)
			m.Logger.Printf("Renamed module %s to %s to avoid conflict", originalName, meta.Name)
		}
	}

	m.Modules[meta.Name] = meta
	sourceIcon := "🏠"
	if meta.Source == "github" {
		sourceIcon = "🌐"
	}
	color.Cyan("  ✓ %s Loaded module: %s v%s", sourceIcon, meta.Name, meta.Version)
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

func (m *ModuleLoader) RefreshModules() error {
	// Clear existing modules
	m.Modules = make(map[string]ModuleMetadata)

	// Reload all modules
	return m.loadModules()
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

	// Determine the correct executable for the current OS
	executable := module.Executable
	if osExecutable, ok := module.ExecutablesByOS[runtime.GOOS]; ok {
		executable = osExecutable
	}

	if executable == "" {
		return ModuleResult{}, fmt.Errorf("no suitable executable found for module '%s' on OS '%s'", module.Name, runtime.GOOS)
	}

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
	cmdParts := strings.Fields(executable)
	if len(cmdParts) == 0 {
		return ModuleResult{}, fmt.Errorf("empty executable command")
	}

	// Create command with context for timeout support
	cmd := exec.CommandContext(ctx, cmdParts[0], cmdParts[1:]...)
	cmd.Dir = module.ModuleDir // Execute the command from the module's directory
	cmd.Stdin = bytes.NewReader(contextJSON)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	sourceIcon := "🏠"
	if module.Source == "github" {
		sourceIcon = "🌐"
	}
	color.Yellow("⚙️  %s Executing %s against %s (timeout: %ds)...",
		sourceIcon, module.Name, execContext.Target, module.Timeout)

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

// --- Enhanced CLI with Repository Management ---

func main() {
	var target, params string
	var timeout int

	// Initialize color output
	color.NoColor = false

	var rootCmd = &cobra.Command{
		Use:   "secv",
		Short: "SecV - The Polyglot Cybersecurity Orchestration Platform v0.1.0",
		Long: `SecV is a next-generation cybersecurity orchestration platform designed for 
performance, flexibility, and collaboration. Execute security tools and orchestrate 
sophisticated workflows from a unified engine with GitHub integration.`,
	}

	// -- Sync Command --
	var syncCmd = &cobra.Command{
		Use:   "sync [repository_name]",
		Short: "Sync tools from GitHub repositories",
		Long:  "Sync tools from configured GitHub repositories. If no repository name is provided, syncs all enabled repositories.",
		Run: func(cmd *cobra.Command, args []string) {
			repoMgr, err := NewRepositoryManager(".secv/cache")
			if err != nil {
				color.Red("Failed to initialize repository manager: %v", err)
				return
			}

			if len(args) == 0 {
				// Sync all repositories
				color.Blue("🔄 Syncing all repositories...")
				if err := repoMgr.SyncAllRepositories(); err != nil {
					color.Red("❌ Failed to sync repositories: %v", err)
					return
				}
			} else {
				// Sync specific repository
				repoName := args[0]
				if err := repoMgr.SyncRepository(repoName); err != nil {
					color.Red("❌ Failed to sync repository '%s': %v", repoName, err)
					return
				}
			}

			color.Green("🎉 Repository sync completed!")
		},
	}

	// -- Repository Management Command --
	var repoCmd = &cobra.Command{
		Use:   "repo",
		Short: "Manage GitHub repositories",
	}

	var repoAddCmd = &cobra.Command{
		Use:   "add [github_url]",
		Short: "Add a new GitHub repository",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			repoURL := args[0]
			name, _ := cmd.Flags().GetString("name")
			description, _ := cmd.Flags().GetString("description")

			repoMgr, err := NewRepositoryManager(".secv/cache")
			if err != nil {
				color.Red("Failed to initialize repository manager: %v", err)
				return
			}

			if err := repoMgr.AddRepository(repoURL, name, description); err != nil {
				color.Red("❌ Failed to add repository: %v", err)
				return
			}

			color.Green("✅ Repository added successfully!")
			color.White("💡 Run 'secv sync' to download tools from this repository")
		},
	}
	repoAddCmd.Flags().String("name", "", "Custom name for the repository")
	repoAddCmd.Flags().String("description", "", "Description of the repository")

	repoCmd.AddCommand(repoAddCmd)

	// -- Enhanced List Command --
	var listCmd = &cobra.Command{
		Use:   "list",
		Short: "List all available modules",
		Run: func(cmd *cobra.Command, args []string) {
			repoMgr, err := NewRepositoryManager(".secv/cache")
			if err != nil {
				color.Red("Failed to initialize repository manager: %v", err)
				return
			}

			loader, err := NewModuleLoader(repoMgr)
			if err != nil {
				color.Red("Failed to load modules: %v", err)
				return
			}

			modules := loader.ListModules()
			if len(modules) == 0 {
				color.Yellow("No modules found.")
				color.White("💡 Run 'secv sync' to download tools from GitHub repositories")
				color.White("💡 Run 'secv init' to set up local directory structure")
				return
			}

			color.Green("📋 Available Modules (%d total):\n", len(modules))

			// Group by category and source
			categories := make(map[string]map[string][]ModuleMetadata)
			for _, module := range modules {
				category := module.Category
				if category == "" {
					category = "uncategorized"
				}
				if categories[category] == nil {
					categories[category] = make(map[string][]ModuleMetadata)
				}
				categories[category][module.Source] = append(categories[category][module.Source], module)
			}

			for category, sources := range categories {
				color.Cyan("📂 %s:", strings.Title(category))

				for source, sourceModules := range sources {
					sourceIcon := "🏠 Local"
					if source == "github" {
						sourceIcon = "🌐 GitHub"
					}
					fmt.Printf("  %s:\n", sourceIcon)

					for _, module := range sourceModules {
						fmt.Printf("    • %s v%s - %s\n",
							color.WhiteString(module.Name),
							color.GreenString(module.Version),
							module.Description)
						if module.Author != "" {
							fmt.Printf("      👤 %s", color.CyanString(module.Author))
						}
						if module.RepoURL != "" {
							fmt.Printf(" 🔗 %s", color.BlueString(module.RepoURL))
						}
						fmt.Println()
					}
				}
				fmt.Println()
			}
		},
	}

	// Add all commands to root
	rootCmd.AddCommand(syncCmd, repoCmd, listCmd) // Note: initCmd, executeCmd, workflowCmd, interactiveCmd are missing in the snippet

	// Execute the CLI
	if err := rootCmd.Execute(); err != nil {
		color.Red("Error: %v", err)
		os.Exit(1)
	}
}
