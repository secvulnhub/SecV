package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const VERSION = "2.3.1"

// ANSI Colors
const (
	RED     = "\033[0;31m"
	GREEN   = "\033[0;32m"
	YELLOW  = "\033[1;33m"
	BLUE    = "\033[0;34m"
	CYAN    = "\033[0;36m"
	MAGENTA = "\033[0;35m"
	WHITE   = "\033[0;97m"
	BOLD    = "\033[1m"
	DIM     = "\033[2m"
	RESET   = "\033[0m"
)

// Symbols
const (
	CHECK   = "✓"
	CROSS   = "✗"
	ARROW   = "➤"
	BULLET  = "•"
	WARNING = "⚠"
	GEAR    = "⚙"
)

// Module represents a SecV module
type Module struct {
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Category    string                 `json:"category"`
	Description string                 `json:"description"`
	Author      string                 `json:"author"`
	Executable  string                 `json:"executable"`
	Dependencies []string              `json:"dependencies"`
	OptionalDeps map[string]string     `json:"optional_dependencies"`
	Help        *ModuleHelp            `json:"help"`
	Inputs      map[string]interface{} `json:"inputs"`
	Outputs     map[string]interface{} `json:"outputs"`
	Timeout     int                    `json:"timeout"`
	Path        string                 `json:"-"`
}

// ModuleHelp contains help documentation
type ModuleHelp struct {
	Description      string                       `json:"description"`
	Parameters       map[string]ParameterHelp     `json:"parameters"`
	Examples         []ExampleHelp                `json:"examples"`
	Features         []string                     `json:"features"`
	InstallationTiers map[string]string            `json:"installation_tiers"`
	Notes            []string                     `json:"notes"`
}

// ParameterHelp contains parameter documentation
type ParameterHelp struct {
	Description string        `json:"description"`
	Type        string        `json:"type"`
	Required    bool          `json:"required"`
	Default     interface{}   `json:"default"`
	Examples    []interface{} `json:"examples"`
	Options     []string      `json:"options"`
}

// ExampleHelp contains usage examples
type ExampleHelp struct {
	Description string   `json:"description"`
	Commands    []string `json:"commands"`
}

// SecV represents the main application state
type SecV struct {
	modules        []*Module
	currentModule  *Module
	params         map[string]string
	secvHome       string
	toolsDir       string
	cacheDir       string
}

// NewSecV creates a new SecV instance
func NewSecV() *SecV {
	home, _ := os.Getwd()
	return &SecV{
		modules:   []*Module{},
		params:    make(map[string]string),
		secvHome:  home,
		toolsDir:  filepath.Join(home, "tools"),
		cacheDir:  filepath.Join(home, ".cache"),
	}
}

// ScanModules discovers all modules in tools directory
func (s *SecV) ScanModules() error {
	s.modules = []*Module{}
	
	if _, err := os.Stat(s.toolsDir); os.IsNotExist(err) {
		return fmt.Errorf("tools directory not found: %s", s.toolsDir)
	}

	err := filepath.Walk(s.toolsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		
		if info.Name() == "module.json" {
			module, err := s.loadModule(filepath.Dir(path))
			if err == nil {
				s.modules = append(s.modules, module)
			}
		}
		return nil
	})

	return err
}

// loadModule loads a module from its directory
func (s *SecV) loadModule(dir string) (*Module, error) {
	jsonPath := filepath.Join(dir, "module.json")
	data, err := ioutil.ReadFile(jsonPath)
	if err != nil {
		return nil, err
	}

	var module Module
	if err := json.Unmarshal(data, &module); err != nil {
		return nil, err
	}

	module.Path = dir
	return &module, nil
}

// FindModule finds a module by name
func (s *SecV) FindModule(name string) *Module {
	for _, m := range s.modules {
		if m.Name == name {
			return m
		}
	}
	return nil
}

// UseModule loads a module
func (s *SecV) UseModule(name string) error {
	module := s.FindModule(name)
	if module == nil {
		return fmt.Errorf("module '%s' not found", name)
	}

	s.currentModule = module
	s.params = make(map[string]string)

	fmt.Printf("%s%s%s Loaded: %s%s%s\n", GREEN, CHECK, RESET, BOLD, name, RESET)
	fmt.Printf("  %sCategory:%s %s%s%s\n", DIM, RESET, YELLOW, module.Category, RESET)
	fmt.Printf("  %sVersion:%s %s%s%s\n", DIM, RESET, CYAN, module.Version, RESET)
	fmt.Printf("  %sPath:%s %s%s%s\n", DIM, RESET, BLUE, module.Path, RESET)
	fmt.Printf("\n%s%sType 'help module' for detailed usage%s\n", CYAN, DIM, RESET)

	return nil
}

// Back unloads current module
func (s *SecV) Back() {
	if s.currentModule == nil {
		fmt.Printf("%s%s No module loaded%s\n", YELLOW, WARNING, RESET)
		return
	}

	s.currentModule = nil
	s.params = make(map[string]string)
	fmt.Printf("%s%s Module unloaded%s\n", BLUE, ARROW, RESET)
}

// SetParam sets a parameter
func (s *SecV) SetParam(key, value string) {
	if s.currentModule == nil {
		fmt.Printf("%s%s No module loaded%s\n", YELLOW, WARNING, RESET)
		return
	}

	s.params[key] = value
	fmt.Printf("%s%s%s%s %s→%s %s%s%s\n", GREEN, BOLD, key, RESET, DIM, RESET, CYAN, value, RESET)
}

// UnsetParam removes a parameter
func (s *SecV) UnsetParam(key string) {
	if s.currentModule == nil {
		fmt.Printf("%s%s No module loaded%s\n", YELLOW, WARNING, RESET)
		return
	}

	if _, exists := s.params[key]; exists {
		delete(s.params, key)
		fmt.Printf("%s%s Unset: %s%s\n", GREEN, CHECK, key, RESET)
	} else {
		fmt.Printf("%s%s Parameter '%s' not set%s\n", YELLOW, WARNING, key, RESET)
	}
}

// Run executes the current module
func (s *SecV) Run(target string) error {
	if s.currentModule == nil {
		return fmt.Errorf("no module loaded")
	}

	if target == "" {
		return fmt.Errorf("usage: run <target>")
	}

	// Build JSON context
	context := map[string]interface{}{
		"target": target,
		"params": s.params,
	}

	jsonData, err := json.Marshal(context)
	if err != nil {
		return err
	}

	// Display execution info
	fmt.Printf("\n%s%s%s Executing %s%s%s against %s%s%s...%s\n",
		BOLD, CYAN, GEAR, WHITE, s.currentModule.Name, CYAN, YELLOW, target, CYAN, RESET)

	if len(s.params) > 0 {
		fmt.Printf("%sParameters:%s\n", DIM, RESET)
		for k, v := range s.params {
			fmt.Printf("  %s%s:%s %s\n", DIM, k, RESET, v)
		}
	}
	fmt.Println()

	// Execute module
	start := time.Now()

	cmd := exec.Command("bash", "-c", s.currentModule.Executable)
	cmd.Dir = s.currentModule.Path
	cmd.Stdin = strings.NewReader(string(jsonData))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	elapsed := time.Since(start)

	if err != nil {
		fmt.Printf("\n%s%s Failed after %s (error: %v)%s\n",
			RED, CROSS, elapsed, err, RESET)
		return err
	}

	fmt.Printf("\n%s%s Completed in %s%s\n",
		GREEN, CHECK, elapsed, RESET)

	return nil
}

// ShowModules displays all available modules
func (s *SecV) ShowModules() {
	printHeader("Available Modules")

	if len(s.modules) == 0 {
		fmt.Printf("%s%s No modules found%s\n", YELLOW, WARNING, RESET)
		return
	}

	// Group by category
	categories := make(map[string][]*Module)
	for _, m := range s.modules {
		cat := m.Category
		if cat == "" {
			cat = "uncategorized"
		}
		categories[cat] = append(categories[cat], m)
	}

	// Display by category
	for cat, mods := range categories {
		fmt.Printf("\n%s%s%s%s\n", BOLD, YELLOW, cat, RESET)
		fmt.Printf("%s%s%s\n", DIM, strings.Repeat("─", 67), RESET)

		for _, m := range mods {
			desc := m.Description
			if len(desc) > 35 {
				desc = desc[:32] + "..."
			}
			fmt.Printf("  %s%s%-20s%s %sv%-8s%s %s\n",
				BOLD, CYAN, m.Name, RESET,
				DIM, m.Version, RESET, desc)
		}
	}

	fmt.Printf("\n%sTotal: %d modules%s\n", DIM, len(s.modules), RESET)
	fmt.Printf("%sUse 'use <module>' to load a module%s\n\n", DIM, RESET)
}

// ShowOptions displays current module options
func (s *SecV) ShowOptions() {
	if s.currentModule == nil {
		fmt.Printf("%s%s No module loaded%s\n", YELLOW, WARNING, RESET)
		return
	}

	printHeader(fmt.Sprintf("Module Options: %s", s.currentModule.Name))

	// Module info
	fmt.Printf("\n%sDescription:%s %s\n", DIM, RESET, s.currentModule.Description)
	fmt.Printf("%sCategory:%s %s%s%s\n", DIM, RESET, YELLOW, s.currentModule.Category, RESET)
	fmt.Printf("%sVersion:%s %s%s%s\n", DIM, RESET, CYAN, s.currentModule.Version, RESET)

	// Current parameters
	printSection("Current Parameters")
	if len(s.params) == 0 {
		fmt.Printf("%sNo parameters set%s\n", DIM, RESET)
	} else {
		for k, v := range s.params {
			fmt.Printf("  %s%-20s%s %s%s%s\n", BOLD, k, RESET, CYAN, v, RESET)
		}
	}

	// Available parameters from inputs
	if len(s.currentModule.Inputs) > 0 {
		printSection("Available Parameters")
		for name, info := range s.currentModule.Inputs {
			infoMap, ok := info.(map[string]interface{})
			if !ok {
				continue
			}

			paramType := "string"
			if t, ok := infoMap["type"].(string); ok {
				paramType = t
			}

			desc := ""
			if d, ok := infoMap["description"].(string); ok {
				desc = d
			}

			required := ""
			if r, ok := infoMap["required"].(bool); ok && r {
				required = " [REQUIRED]"
			}

			fmt.Printf("  %s%s%s %s(%s)%s%s\n",
				BOLD, name, RESET, DIM, paramType, required, RESET)
			if desc != "" {
				fmt.Printf("    %s\n", desc)
			}
		}
	}

	fmt.Printf("\n%sUse 'set <param> <value>' to configure parameters%s\n\n", DIM, RESET)
}

// ShowInfo displays detailed module information
func (s *SecV) ShowInfo(moduleName string) {
	var module *Module
	if moduleName == "" && s.currentModule != nil {
		module = s.currentModule
	} else {
		module = s.FindModule(moduleName)
	}

	if module == nil {
		fmt.Printf("%s%s Module not found%s\n", RED, CROSS, RESET)
		return
	}

	printHeader(fmt.Sprintf("Module: %s", module.Name))

	fmt.Printf("\n%s%sName:%s %s%s%s%s\n", BOLD, DIM, RESET, BOLD, CYAN, module.Name, RESET)
	fmt.Printf("%s%sVersion:%s %s%s%s\n", BOLD, DIM, RESET, CYAN, module.Version, RESET)
	fmt.Printf("%s%sCategory:%s %s%s%s\n", BOLD, DIM, RESET, YELLOW, module.Category, RESET)
	fmt.Printf("%s%sDescription:%s %s\n", BOLD, DIM, RESET, module.Description)
	fmt.Printf("%s%sPath:%s %s%s%s\n", BOLD, DIM, RESET, BLUE, module.Path, RESET)

	if module.Author != "" {
		fmt.Printf("%s%sAuthor:%s %s%s%s\n", BOLD, DIM, RESET, MAGENTA, module.Author, RESET)
	}

	if len(module.Dependencies) > 0 {
		fmt.Printf("\n%s%sDependencies:%s\n", BOLD, DIM, RESET)
		for _, dep := range module.Dependencies {
			fmt.Printf("  %s %s\n", BULLET, dep)
		}
	}

	readmePath := filepath.Join(module.Path, "README.md")
	if _, err := os.Stat(readmePath); err == nil {
		fmt.Printf("\n%s📖 Detailed documentation: %s%s%s\n",
			DIM, BLUE, readmePath, RESET)
	}

	fmt.Println()
}

// ShowHelp displays help based on context
func (s *SecV) ShowHelp(topic string) {
	if topic == "module" {
		if s.currentModule == nil {
			fmt.Printf("%s%s No module loaded%s\n", YELLOW, WARNING, RESET)
			return
		}
		s.ShowModuleHelp()
		return
	}

	printHeader("SecV Command Reference")

	sections := []struct {
		title string
		cmds  [][]string
	}{
		{"MODULE SELECTION", [][]string{
			{"use <module>", "Load a module"},
			{"back", "Unload current module"},
			{"reload", "Rescan modules directory"},
		}},
		{"CONFIGURATION", [][]string{
			{"set <param> <value>", "Set module parameter"},
			{"unset <param>", "Remove parameter"},
			{"show options", "Show module parameters"},
		}},
		{"EXECUTION", [][]string{
			{"run <target>", "Execute loaded module"},
		}},
		{"INFORMATION", [][]string{
			{"show modules", "List all modules"},
			{"info [module]", "Show module details"},
			{"search <keyword>", "Search modules"},
			{"help module", "Show current module help"},
		}},
		{"UTILITIES", [][]string{
			{"update", "Update SecV"},
			{"clear", "Clear screen"},
			{"exit", "Exit SecV"},
		}},
	}

	for _, section := range sections {
		fmt.Printf("\n%s%s%s%s\n", BOLD, YELLOW, section.title, RESET)
		for _, cmd := range section.cmds {
			fmt.Printf("  %s%s%s%-22s%s%s\n",
				CYAN, cmd[0], RESET,
				strings.Repeat(" ", 22-len(cmd[0])),
				cmd[1], "")
		}
	}

	fmt.Printf("\n%sType 'help module' for current module help%s\n\n", DIM, RESET)
}

// ShowModuleHelp displays comprehensive module help
func (s *SecV) ShowModuleHelp() {
	if s.currentModule == nil {
		return
	}

	// Try built-in --help first
	cmd := exec.Command("bash", "-c", s.currentModule.Executable+" --help")
	cmd.Dir = s.currentModule.Path
	output, err := cmd.Output()
	
	if err == nil && strings.Contains(string(output), "╔") {
		fmt.Print(string(output))
		return
	}

	// Parse help from module.json
	if s.currentModule.Help == nil {
		s.ShowInfo(s.currentModule.Name)
		return
	}

	help := s.currentModule.Help
	name := s.currentModule.Name

	// Header
	fmt.Printf("\n%s%s╔%s╗%s\n", BOLD, CYAN, strings.Repeat("═", 67), RESET)
	fmt.Printf("%s%s║%s %s%s%s - Help%s%s║%s\n",
		BOLD, CYAN, RESET, BOLD, WHITE, strings.ToUpper(name), RESET,
		strings.Repeat(" ", 67-len(name)-8), BOLD+CYAN, RESET)
	fmt.Printf("%s%s╚%s╝%s\n\n", BOLD, CYAN, strings.Repeat("═", 67), RESET)

	// Description
	if help.Description != "" {
		fmt.Printf("%s%sDESCRIPTION:%s\n  %s\n\n", BOLD, YELLOW, RESET, help.Description)
	}

	// Usage
	fmt.Printf("%s%sUSAGE:%s\n", BOLD, YELLOW, RESET)
	fmt.Printf("  secV > use %s\n", name)
	fmt.Printf("  secV (%s) > show options\n", name)
	fmt.Printf("  secV (%s) > run <target>\n\n", name)

	// Parameters
	if len(help.Parameters) > 0 {
		fmt.Printf("%s%sPARAMETERS:%s\n", BOLD, YELLOW, RESET)
		for pname, pinfo := range help.Parameters {
			req := ""
			if pinfo.Required {
				req = " [REQUIRED]"
			}
			fmt.Printf("  %s%s%s%s %s(%s)%s%s\n",
				BOLD, CYAN, pname, RESET, DIM, pinfo.Type, req, RESET)

			if pinfo.Description != "" {
				fmt.Printf("    %s\n", pinfo.Description)
			}
			if pinfo.Default != nil {
				fmt.Printf("    %sDefault: %v%s\n", DIM, pinfo.Default, RESET)
			}
			if len(pinfo.Examples) > 0 {
				examples := make([]string, len(pinfo.Examples))
				for i, e := range pinfo.Examples {
					examples[i] = fmt.Sprintf("%v", e)
				}
				fmt.Printf("    %sExamples: %s%s\n", DIM, strings.Join(examples, ", "), RESET)
			}
			fmt.Println()
		}
	}

	// Examples
	if len(help.Examples) > 0 {
		fmt.Printf("%s%sEXAMPLES:%s\n", BOLD, YELLOW, RESET)
		for i, ex := range help.Examples {
			fmt.Printf("  %d. %s\n", i+1, ex.Description)
			for _, cmd := range ex.Commands {
				fmt.Printf("     %s%s%s\n", CYAN, cmd, RESET)
			}
			fmt.Println()
		}
	}

	// Features
	if len(help.Features) > 0 {
		fmt.Printf("%s%sFEATURES:%s\n", BOLD, YELLOW, RESET)
		for _, feature := range help.Features {
			fmt.Printf("  %s %s\n", BULLET, feature)
		}
		fmt.Println()
	}

	// Installation Tiers
	if len(help.InstallationTiers) > 0 {
		fmt.Printf("%s%sINSTALLATION TIERS:%s\n", BOLD, YELLOW, RESET)
		for tier, desc := range help.InstallationTiers {
			fmt.Printf("  %s%s:%s %s\n", BOLD, strings.Title(tier), RESET, desc)
		}
		fmt.Println()
	}

	// Notes
	if len(help.Notes) > 0 {
		fmt.Printf("%s%sNOTES:%s\n", BOLD, YELLOW, RESET)
		for _, note := range help.Notes {
			fmt.Printf("  %s %s\n", BULLET, note)
		}
		fmt.Println()
	}
}

// Search searches for modules
func (s *SecV) Search(query string) {
	printHeader(fmt.Sprintf("Search Results: %s", query))

	found := 0
	query = strings.ToLower(query)

	for _, m := range s.modules {
		if strings.Contains(strings.ToLower(m.Name), query) ||
			strings.Contains(strings.ToLower(m.Description), query) ||
			strings.Contains(strings.ToLower(m.Category), query) {
			found++
			fmt.Printf("\n%s%s%s%s %s[%s]%s\n",
				BOLD, CYAN, m.Name, RESET, DIM, m.Category, RESET)
			fmt.Printf("  %s\n", m.Description)
		}
	}

	if found == 0 {
		fmt.Printf("\n%sNo modules found matching '%s'%s\n", DIM, query, RESET)
	} else {
		fmt.Printf("\n%sFound %d module(s)%s\n", DIM, found, RESET)
	}
	fmt.Println()
}

// Utility functions

func printHeader(title string) {
	fmt.Printf("\n%s%s╔%s╗%s\n", BOLD, CYAN, strings.Repeat("═", 67), RESET)
	fmt.Printf("%s%s║%s %s%s%s║%s\n",
		BOLD, CYAN, RESET, title,
		strings.Repeat(" ", 67-len(title)-1),
		BOLD+CYAN, RESET)
	fmt.Printf("%s%s╚%s╝%s\n", BOLD, CYAN, strings.Repeat("═", 67), RESET)
}

func printSection(title string) {
	fmt.Printf("\n%s%s%s:%s\n", BOLD, CYAN, title, RESET)
	fmt.Printf("%s%s%s\n", DIM, strings.Repeat("─", 67), RESET)
}

func printBanner() {
	fmt.Print(BOLD + CYAN)
	fmt.Println("╔═══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║   ███████╗███████╗ ██████╗██╗   ██╗                             ║")
	fmt.Println("║   ██╔════╝██╔════╝██╔════╝██║   ██║                             ║")
	fmt.Println("║   ███████╗█████╗  ██║     ██║   ██║                             ║")
	fmt.Println("║   ╚════██║██╔══╝  ██║     ╚██╗ ██╔╝                             ║")
	fmt.Println("║   ███████║███████╗╚██████╗ ╚████╔╝                              ║")
	fmt.Println("║   ╚══════╝╚══════╝ ╚═════╝  ╚═══╝                               ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════════╝")
	fmt.Print(RESET)
	fmt.Printf("%s   SecV v%s - Compiled Edition%s\n", DIM, VERSION, RESET)
	fmt.Printf("%s   The Polyglot Cybersecurity Orchestration Platform%s\n\n", DIM, RESET)
}

func main() {
	// Clear screen and show banner
	fmt.Print("\033[H\033[2J")
	printBanner()

	// Initialize SecV
	secv := NewSecV()

	// Scan modules
	fmt.Printf("%sScanning modules...%s\n", DIM, RESET)
	if err := secv.ScanModules(); err != nil {
		fmt.Printf("%s%s Error: %v%s\n", RED, CROSS, err, RESET)
	}

	fmt.Printf("%s%s Loaded %d modules%s\n", GREEN, CHECK, len(secv.modules), RESET)
	fmt.Printf("%sType 'help' for commands%s\n\n", DIM, RESET)

	// Command loop
	scanner := bufio.NewScanner(os.Stdin)
	for {
		// Prompt
		if secv.currentModule != nil {
			fmt.Printf("%s%ssecV%s %s%s(%s)%s %s%s%s ",
				BOLD, GREEN, RESET, BOLD, RED, secv.currentModule.Name, RESET,
				CYAN, ARROW, RESET)
		} else {
			fmt.Printf("%s%ssecV%s %s%s%s ", BOLD, GREEN, RESET, CYAN, ARROW, RESET)
		}

		if !scanner.Scan() {
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := parts[0]
		args := parts[1:]

		switch cmd {
		case "use":
			if len(args) == 0 {
				fmt.Printf("%s%s Usage: use <module>%s\n", RED, CROSS, RESET)
			} else {
				secv.UseModule(args[0])
			}

		case "back":
			secv.Back()

		case "set":
			if len(args) < 2 {
				fmt.Printf("%s%s Usage: set <parameter> <value>%s\n", RED, CROSS, RESET)
			} else {
				secv.SetParam(args[0], strings.Join(args[1:], " "))
			}

		case "unset":
			if len(args) == 0 {
				fmt.Printf("%s%s Usage: unset <parameter>%s\n", RED, CROSS, RESET)
			} else {
				secv.UnsetParam(args[0])
			}

		case "run":
			if len(args) == 0 {
				fmt.Printf("%s%s Usage: run <target>%s\n", RED, CROSS, RESET)
			} else {
				secv.Run(args[0])
			}

		case "show":
			if len(args) == 0 {
				fmt.Printf("%s%s Usage: show {modules|options}%s\n", RED, CROSS, RESET)
			} else {
				switch args[0] {
				case "modules":
					secv.ShowModules()
				case "options":
					secv.ShowOptions()
				default:
					fmt.Printf("%s%s Unknown show command%s\n", RED, CROSS, RESET)
				}
			}

		case "info":
			moduleName := ""
			if len(args) > 0 {
				moduleName = args[0]
			}
			secv.ShowInfo(moduleName)

		case "search":
			if len(args) == 0 {
				fmt.Printf("%s%s Usage: search <keyword>%s\n", RED, CROSS, RESET)
			} else {
				secv.Search(args[0])
			}

		case "help":
			topic := ""
			if len(args) > 0 {
				topic = args[0]
			}
			secv.ShowHelp(topic)

		case "reload":
			fmt.Printf("%sScanning modules...%s\n", DIM, RESET)
			if err := secv.ScanModules(); err != nil {
				fmt.Printf("%s%s Error: %v%s\n", RED, CROSS, err, RESET)
			}
			fmt.Printf("%s%s Loaded %d modules%s\n", GREEN, CHECK, len(secv.modules), RESET)

		case "clear":
			fmt.Print("\033[H\033[2J")
			fmt.Printf("%s%sSecV v%s%s - %sCleared%s\n\n",
				BOLD, CYAN, VERSION, RESET, DIM, RESET)

		case "exit", "quit":
			fmt.Printf("\n%s%sThanks for using SecV! ★%s\n\n", CYAN, BOLD, RESET)
			return

		default:
			fmt.Printf("%s%s Unknown command: %s %s(type 'help')%s\n",
				YELLOW, WARNING, cmd, DIM, RESET)
		}
	}
}
