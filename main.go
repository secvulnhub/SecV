package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/chzyer/readline"
)

const VERSION = "2.4.0"

// ANSI colors
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

const (
	CHECK   = "✓"
	CROSS   = "✗"
	BULLET  = "•"
	WARNING = "⚠"
)

// ============================================================================
// OS / package manager detection
// ============================================================================

type distroInfo struct {
	id      string // arch, debian, ubuntu, fedora, …
	pkgMgr  string // pacman, apt, dnf, …
	aurHelper string // yay, paru, trizen — Arch only
}

func detectDistro() distroInfo {
	info := distroInfo{}

	// Read /etc/os-release
	data, err := os.ReadFile("/etc/os-release")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "ID=") {
				info.id = strings.Trim(strings.TrimPrefix(line, "ID="), `"'`)
			}
		}
	}
	if info.id == "" {
		if _, e := os.Stat("/etc/arch-release"); e == nil {
			info.id = "arch"
		}
	}

	switch info.id {
	case "arch", "archcraft", "manjaro", "endeavouros", "cachyos":
		info.pkgMgr = "pacman"
		for _, aur := range []string{"yay", "paru", "trizen"} {
			if path, _ := exec.LookPath(aur); path != "" {
				info.aurHelper = aur
				break
			}
		}
	case "ubuntu", "debian", "kali", "parrot", "linuxmint", "pop":
		info.pkgMgr = "apt"
	case "fedora":
		info.pkgMgr = "dnf"
	case "rhel", "centos", "rocky", "alma":
		info.pkgMgr = "dnf"
	case "opensuse-leap", "opensuse-tumbleweed", "sles":
		info.pkgMgr = "zypper"
	case "alpine":
		info.pkgMgr = "apk"
	case "void":
		info.pkgMgr = "xbps-install"
	default:
		if runtime.GOOS == "darwin" {
			info.pkgMgr = "brew"
		}
	}
	return info
}

// installPackage installs a single system package using the detected pkg manager.
// Returns the error output if installation fails.
func installPackage(pkg string, d distroInfo) error {
	var cmd *exec.Cmd
	switch d.pkgMgr {
	case "pacman":
		if d.aurHelper != "" {
			cmd = exec.Command(d.aurHelper, "-S", "--noconfirm", "--needed", pkg)
		} else {
			cmd = exec.Command("sudo", "pacman", "-S", "--noconfirm", "--needed", pkg)
		}
	case "apt":
		cmd = exec.Command("sudo", "apt-get", "install", "-y", pkg)
	case "dnf":
		cmd = exec.Command("sudo", "dnf", "install", "-y", pkg)
	case "zypper":
		cmd = exec.Command("sudo", "zypper", "install", "-y", pkg)
	case "apk":
		cmd = exec.Command("sudo", "apk", "add", pkg)
	case "xbps-install":
		cmd = exec.Command("sudo", "xbps-install", "-Sy", pkg)
	case "brew":
		cmd = exec.Command("brew", "install", pkg)
	default:
		return fmt.Errorf("unknown package manager for distro '%s'", d.id)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// binToPackage maps binary names (as listed in module.json dependencies) to the
// correct system package name for each package manager. Binary name = what
// exec.LookPath checks; package name = what pacman/apt/dnf installs.
var binToPackage = map[string]map[string]string{
	// binary      pkgmgr   package
	"adb":         {"pacman": "android-tools", "apt": "adb",         "dnf": "android-tools",   "brew": "android-platform-tools"},
	"fastboot":    {"pacman": "android-tools", "apt": "fastboot",    "dnf": "android-tools"},
	"nmap":        {"pacman": "nmap",          "apt": "nmap",        "dnf": "nmap",             "brew": "nmap"},
	"masscan":     {"pacman": "masscan",       "apt": "masscan",     "dnf": "masscan"},
	"rustscan":    {"pacman": "rustscan",      "apt": "rustscan",    "brew": "rustscan"},
	"tcpdump":     {"pacman": "tcpdump",       "apt": "tcpdump",     "dnf": "tcpdump",          "brew": "tcpdump"},
	"wireshark":   {"pacman": "wireshark-qt",  "apt": "wireshark",   "dnf": "wireshark"},
	"apktool":     {"pacman": "apktool",       "apt": "apktool",     "brew": "apktool"},
	"jadx":        {"pacman": "jadx",          "apt": "jadx"},
	"aapt":        {"pacman": "aapt",          "apt": "aapt"},
	"ideviceinfo": {"pacman": "libimobiledevice", "apt": "libimobiledevice-utils", "dnf": "libimobiledevice-utils", "brew": "libimobiledevice"},
	"ideviceinstaller": {"pacman": "ideviceinstaller", "apt": "ideviceinstaller", "brew": "ideviceinstaller"},
	"python3":     {"pacman": "python",        "apt": "python3",     "dnf": "python3",          "brew": "python@3"},
	"jq":          {"pacman": "jq",            "apt": "jq",          "dnf": "jq",               "brew": "jq"},
	"curl":        {"pacman": "curl",          "apt": "curl",        "dnf": "curl",             "brew": "curl"},
	"git":         {"pacman": "git",           "apt": "git",         "dnf": "git",              "brew": "git"},
	"go":          {"pacman": "go",            "apt": "golang",      "dnf": "golang",           "brew": "go"},
	"avahi-browse":{"pacman": "avahi",         "apt": "avahi-utils", "dnf": "avahi-tools"},
	"arp-scan":    {"pacman": "arp-scan",      "apt": "arp-scan",    "dnf": "arp-scan"},
}

// resolvePackageName returns the correct package name for installing a given
// binary using the detected package manager. Falls back to the binary name
// itself if no mapping is found.
func resolvePackageName(binary string, d distroInfo) string {
	if pkgMap, ok := binToPackage[binary]; ok {
		if pkg, ok := pkgMap[d.pkgMgr]; ok {
			return pkg
		}
	}
	return binary
}

// ensureModuleDeps checks a module's dependency list and offers to install any
// missing ones using the system package manager.
func ensureModuleDeps(module *Module, d distroInfo) {
	if len(module.Dependencies) == 0 {
		return
	}
	var missing []string
	for _, dep := range module.Dependencies {
		if _, err := exec.LookPath(dep); err != nil {
			missing = append(missing, dep)
		}
	}
	if len(missing) == 0 {
		return
	}
	fmt.Printf("%s%s missing: %s%s\n", YELLOW, WARNING, strings.Join(missing, ", "), RESET)
	if d.pkgMgr == "" {
		fmt.Printf("%sCannot auto-install — unknown package manager. Install manually.%s\n", DIM, RESET)
		return
	}
	fmt.Printf("%sInstall with %s? [y/N] %s", CYAN, d.pkgMgr, RESET)
	var ans string
	fmt.Scanln(&ans)
	if strings.ToLower(strings.TrimSpace(ans)) == "y" {
		for _, bin := range missing {
			pkg := resolvePackageName(bin, d)
			fmt.Printf("%s  installing %s...%s\n", DIM, pkg, RESET)
			if err := installPackage(pkg, d); err != nil {
				fmt.Printf("%s%s  %s failed%s\n", RED, CROSS, pkg, RESET)
			} else {
				fmt.Printf("%s%s  %s%s\n", GREEN, CHECK, bin, RESET)
			}
		}
	}
}

// ============================================================================
// Module structs
// ============================================================================

type Module struct {
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Category     string                 `json:"category"`
	Description  string                 `json:"description"`
	Author       string                 `json:"author"`
	Executable   string                 `json:"executable"`
	Dependencies []string               `json:"dependencies"`
	OptionalDeps map[string]string      `json:"optional_dependencies"`
	Help         *ModuleHelp            `json:"help"`
	Inputs       map[string]interface{} `json:"inputs"`
	Outputs      map[string]interface{} `json:"outputs"`
	Timeout      int                    `json:"timeout"`
	Path         string                 `json:"-"`
}

type ModuleHelp struct {
	Description       string                   `json:"description"`
	Parameters        map[string]ParameterHelp `json:"parameters"`
	Examples          []ExampleHelp            `json:"examples"`
	Features          []string                 `json:"features"`
	InstallationTiers map[string]string        `json:"installation_tiers"`
	Notes             []string                 `json:"notes"`
}

type ParameterHelp struct {
	Description string        `json:"description"`
	Type        string        `json:"type"`
	Required    bool          `json:"required"`
	Default     interface{}   `json:"default"`
	Examples    []interface{} `json:"examples"`
	Options     []string      `json:"options"`
}

type ExampleHelp struct {
	Description string   `json:"description"`
	Commands    []string `json:"commands"`
}

// ============================================================================
// SecV app state
// ============================================================================

// msfRPCConfig is written by android_pentest msf_handler operation
type msfRPCConfig struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Pass    string `json:"pass"`
	Payload string `json:"payload"`
	LHost   string `json:"lhost"`
	LPort   string `json:"lport"`
}

type SecV struct {
	modules       []*Module
	currentModule *Module
	params        map[string]string
	secvHome      string
	toolsDir      string
	cacheDir      string
	workDir       string
	distro        distroInfo
	msfToken      string        // authenticated MSF RPC token
	msfCfg        *msfRPCConfig // loaded from ~/.secv/msf_rpc.json
}

func NewSecV() *SecV {
	home, _ := os.Getwd()
	return &SecV{
		modules:  []*Module{},
		params:   make(map[string]string),
		secvHome: home,
		toolsDir: filepath.Join(home, "tools"),
		cacheDir: filepath.Join(home, ".cache"),
		workDir:  home,
		distro:   detectDistro(),
	}
}

func (s *SecV) ScanModules() error {
	s.modules = []*Module{}
	if _, err := os.Stat(s.toolsDir); os.IsNotExist(err) {
		return fmt.Errorf("tools directory not found: %s", s.toolsDir)
	}
	return filepath.WalkDir(s.toolsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Name() == "module.json" {
			if m, e := s.loadModule(filepath.Dir(path)); e == nil {
				s.modules = append(s.modules, m)
			}
		}
		return nil
	})
}

func (s *SecV) loadModule(dir string) (*Module, error) {
	data, err := os.ReadFile(filepath.Join(dir, "module.json"))
	if err != nil {
		return nil, err
	}
	var m Module
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	m.Path = dir
	return &m, nil
}

func (s *SecV) FindModule(name string) *Module {
	name = strings.ToLower(name)
	for _, m := range s.modules {
		if strings.ToLower(m.Name) == name {
			return m
		}
	}
	return nil
}

func (s *SecV) moduleNames() []string {
	names := make([]string, len(s.modules))
	for i, m := range s.modules {
		names[i] = m.Name
	}
	return names
}

// ============================================================================
// Commands
// ============================================================================

func (s *SecV) UseModule(name string) error {
	m := s.FindModule(name)
	if m == nil {
		return fmt.Errorf("'%s' not found", name)
	}
	s.currentModule = m
	s.params = make(map[string]string)

	fmt.Printf("%s%s%s %s%s%s\n", GREEN, CHECK, RESET, BOLD, m.Name, RESET)
	fmt.Printf("  %scategory%s  %s%s%s\n", DIM, RESET, YELLOW, m.Category, RESET)
	fmt.Printf("  %sversion%s   %s%s%s\n", DIM, RESET, CYAN, m.Version, RESET)

	ensureModuleDeps(m, s.distro)
	return nil
}

func (s *SecV) Back() {
	if s.currentModule == nil {
		fmt.Printf("%s%s no module loaded%s\n", YELLOW, WARNING, RESET)
		return
	}
	s.currentModule = nil
	s.params = make(map[string]string)
}

func (s *SecV) SetParam(key, value string) {
	if s.currentModule == nil {
		fmt.Printf("%s%s no module loaded%s\n", YELLOW, WARNING, RESET)
		return
	}
	s.params[key] = value
	fmt.Printf("  %s%s%s → %s%s%s\n", BOLD, key, RESET, CYAN, value, RESET)
}

func (s *SecV) UnsetParam(key string) {
	if s.currentModule == nil {
		fmt.Printf("%s%s no module loaded%s\n", YELLOW, WARNING, RESET)
		return
	}
	if _, ok := s.params[key]; ok {
		delete(s.params, key)
		fmt.Printf("%s%s %s%s\n", GREEN, CHECK, key, RESET)
	} else {
		fmt.Printf("%s%s '%s' not set%s\n", YELLOW, WARNING, key, RESET)
	}
}

func (s *SecV) Run(target string) error {
	if s.currentModule == nil {
		return fmt.Errorf("no module loaded")
	}
	if target == "" {
		return fmt.Errorf("usage: run <target>")
	}

	ctx := map[string]interface{}{
		"target": target,
		"params": s.params,
	}
	jsonData, err := json.Marshal(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("\n%s%s%s → %s%s%s\n\n", BOLD, s.currentModule.Name, RESET, YELLOW, target, RESET)

	start := time.Now()
	cmd := exec.Command("bash", "-c", s.currentModule.Executable)
	cmd.Dir = s.currentModule.Path
	cmd.Stdin = strings.NewReader(string(jsonData))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	elapsed := time.Since(start)

	if err != nil {
		fmt.Printf("\n%s%s %s (%v)%s\n", RED, CROSS, elapsed.Round(time.Millisecond), err, RESET)
		return err
	}
	fmt.Printf("\n%s%s %s%s\n", GREEN, CHECK, elapsed.Round(time.Millisecond), RESET)
	return nil
}

func (s *SecV) ShowModules() {
	printHeader("modules")
	if len(s.modules) == 0 {
		fmt.Printf("%sno modules found%s\n", DIM, RESET)
		return
	}

	categories := make(map[string][]*Module)
	order := []string{}
	for _, m := range s.modules {
		cat := m.Category
		if cat == "" {
			cat = "misc"
		}
		if _, seen := categories[cat]; !seen {
			order = append(order, cat)
		}
		categories[cat] = append(categories[cat], m)
	}

	for _, cat := range order {
		mods := categories[cat]
		fmt.Printf("\n%s%s%s%s\n", BOLD, YELLOW, cat, RESET)
		fmt.Printf("%s%s%s\n", DIM, strings.Repeat("─", 60), RESET)
		for _, m := range mods {
			desc := m.Description
			if len(desc) > 40 {
				desc = desc[:37] + "..."
			}
			fmt.Printf("  %s%-22s%s %s%s\n", CYAN, m.Name, RESET, DIM+desc, RESET)
		}
	}
	fmt.Printf("\n%s%d modules%s\n\n", DIM, len(s.modules), RESET)
}

func (s *SecV) ShowOptions() {
	if s.currentModule == nil {
		fmt.Printf("%s%s no module loaded%s\n", YELLOW, WARNING, RESET)
		return
	}
	m := s.currentModule
	printHeader(m.Name + " · options")
	fmt.Printf("\n  %s%s%s\n", DIM, m.Description, RESET)
	if m.Author != "" {
		fmt.Printf("  %sauthor%s  %s%s%s\n", DIM, RESET, MAGENTA, m.Author, RESET)
	}
	fmt.Printf("  %sversion%s %s%s%s\n\n", DIM, RESET, CYAN, m.Version, RESET)

	if m.Help != nil && len(m.Help.Parameters) > 0 {
		printSection("parameters")
		fmt.Printf("  %s%-22s %-10s %-5s %s%s\n", BOLD, "PARAM", "TYPE", "REQ", "CURRENT VALUE", RESET)
		fmt.Printf("  %s%s%s\n", DIM, strings.Repeat("─", 70), RESET)
		for pname, pi := range m.Help.Parameters {
			val, isSet := s.params[pname]

			reqStr := "no"
			reqColor := DIM
			if pi.Required {
				if isSet {
					reqStr = "YES"
					reqColor = GREEN
				} else {
					reqStr = "YES"
					reqColor = RED
				}
			}

			var valStr string
			if isSet {
				valStr = fmt.Sprintf("%s%s%s", CYAN, val, RESET)
			} else if pi.Default != nil && fmt.Sprintf("%v", pi.Default) != "" && fmt.Sprintf("%v", pi.Default) != "false" && fmt.Sprintf("%v", pi.Default) != "<nil>" {
				valStr = fmt.Sprintf("%s(default: %v)%s", DIM, pi.Default, RESET)
			} else {
				valStr = fmt.Sprintf("%snot set%s", DIM, RESET)
			}

			nameStr := fmt.Sprintf("%s%s%s", BOLD, pname, RESET)
			fmt.Printf("  %-30s %-10s %s%-5s%s %s\n",
				nameStr, pi.Type, reqColor, reqStr, RESET, valStr)
			if pi.Description != "" {
				fmt.Printf("    %s%s%s\n", DIM, pi.Description, RESET)
			}
			if len(pi.Options) > 0 {
				fmt.Printf("    %soptions: %s%s\n", DIM, strings.Join(pi.Options, " | "), RESET)
			}
			if len(pi.Examples) > 0 {
				ex := make([]string, 0, len(pi.Examples))
				for _, e := range pi.Examples {
					ex = append(ex, fmt.Sprintf("%v", e))
				}
				fmt.Printf("    %se.g. %s%s\n", DIM, strings.Join(ex, ", "), RESET)
			}
		}
	} else if len(m.Inputs) > 0 {
		printSection("inputs")
		for name, info := range m.Inputs {
			inf, ok := info.(map[string]interface{})
			if !ok {
				continue
			}
			ptype, _ := inf["type"].(string)
			desc, _ := inf["description"].(string)
			req := ""
			if r, _ := inf["required"].(bool); r {
				req = fmt.Sprintf(" %s*%s", RED, RESET)
			}
			val, isSet := s.params[name]
			valStr := fmt.Sprintf("%snot set%s", DIM, RESET)
			if isSet {
				valStr = fmt.Sprintf("%s%s%s", CYAN, val, RESET)
			}
			fmt.Printf("  %s%s%s%s  %s(%s)%s  →  %s\n", BOLD, name, req, RESET, DIM, ptype, RESET, valStr)
			if desc != "" {
				fmt.Printf("    %s%s%s\n", DIM, desc, RESET)
			}
		}
	} else {
		printSection("params set")
		if len(s.params) == 0 {
			fmt.Printf("  %s(none)%s\n", DIM, RESET)
		} else {
			for k, v := range s.params {
				fmt.Printf("  %s%-20s%s %s%s%s\n", BOLD, k, RESET, CYAN, v, RESET)
			}
		}
	}

	// Always summarise what's currently set
	if len(s.params) > 0 {
		printSection("set")
		for k, v := range s.params {
			fmt.Printf("  %s%-20s%s %s%s%s\n", BOLD, k, RESET, CYAN, v, RESET)
		}
	}

	fmt.Printf("\n%s  set <param> <value>  ·  run <target>  ·  help module%s\n\n", DIM, RESET)
}

func (s *SecV) ShowInfo(moduleName string) {
	var m *Module
	if moduleName == "" && s.currentModule != nil {
		m = s.currentModule
	} else {
		m = s.FindModule(moduleName)
	}
	if m == nil {
		fmt.Printf("%s%s not found%s\n", RED, CROSS, RESET)
		return
	}

	printHeader(m.Name)

	// Core metadata
	fmt.Printf("\n  %s%-10s%s %s%s%s\n", DIM, "category", RESET, YELLOW, m.Category, RESET)
	fmt.Printf("  %s%-10s%s %s%s%s\n", DIM, "version", RESET, CYAN, m.Version, RESET)
	fmt.Printf("  %s%-10s%s %s%s%s\n", DIM, "path", RESET, BLUE, m.Path, RESET)
	if m.Author != "" {
		fmt.Printf("  %s%-10s%s %s%s%s\n", DIM, "author", RESET, MAGENTA, m.Author, RESET)
	}
	if m.Timeout > 0 {
		fmt.Printf("  %s%-10s%s %ds\n", DIM, "timeout", RESET, m.Timeout)
	}

	// Description
	fmt.Printf("\n  %s\n", m.Description)

	// Dependencies
	if len(m.Dependencies) > 0 {
		fmt.Printf("\n  %srequired%s  %s\n", DIM, RESET, strings.Join(m.Dependencies, ", "))
	}
	var missing []string
	for _, dep := range m.Dependencies {
		if _, err := exec.LookPath(dep); err != nil {
			missing = append(missing, dep)
		}
	}
	if len(missing) > 0 {
		fmt.Printf("  %s%s missing: %s%s\n", YELLOW, WARNING, strings.Join(missing, ", "), RESET)
	}
	if len(m.OptionalDeps) > 0 {
		fmt.Printf("  %soptional%s", DIM, RESET)
		for bin := range m.OptionalDeps {
			fmt.Printf("  %s", bin)
		}
		fmt.Println()
	}

	// Operations (from help.parameters["operation"].options)
	if m.Help != nil {
		if opParam, ok := m.Help.Parameters["operation"]; ok && len(opParam.Options) > 0 {
			printSection("operations")
			cols := 4
			for i, op := range opParam.Options {
				if i%cols == 0 {
					fmt.Printf("    ")
				}
				fmt.Printf("%s%-22s%s", CYAN, op, RESET)
				if (i+1)%cols == 0 || i == len(opParam.Options)-1 {
					fmt.Println()
				}
			}
		}

		// Examples
		if len(m.Help.Examples) > 0 {
			printSection("examples")
			limit := 3
			if len(m.Help.Examples) < limit {
				limit = len(m.Help.Examples)
			}
			for _, ex := range m.Help.Examples[:limit] {
				fmt.Printf("  %s%s%s\n", DIM, ex.Description, RESET)
				for _, cmd := range ex.Commands {
					fmt.Printf("    %s%s%s\n", CYAN, cmd, RESET)
				}
				fmt.Println()
			}
		}

		// Notes (first 3)
		if len(m.Help.Notes) > 0 {
			printSection("notes")
			limit := 3
			if len(m.Help.Notes) < limit {
				limit = len(m.Help.Notes)
			}
			for _, note := range m.Help.Notes[:limit] {
				fmt.Printf("  %s%s%s\n", DIM, note, RESET)
			}
		}
	}

	// Inputs (from module.json inputs block)
	if len(m.Inputs) > 0 {
		printSection("inputs")
		fmt.Printf("  %s%-20s %-10s %s%s\n", BOLD, "PARAM", "TYPE", "DESCRIPTION", RESET)
		fmt.Printf("  %s%s%s\n", DIM, strings.Repeat("─", 60), RESET)
		for k, v := range m.Inputs {
			if vm, ok := v.(map[string]interface{}); ok {
				typ := fmt.Sprintf("%v", vm["type"])
				desc := ""
				if d, ok := vm["description"].(string); ok {
					if len(d) > 40 {
						d = d[:37] + "..."
					}
					desc = d
				}
				def := ""
				if dv, ok := vm["default"]; ok && dv != nil && fmt.Sprintf("%v", dv) != "" && fmt.Sprintf("%v", dv) != "false" {
					def = fmt.Sprintf(" %s(default: %v)%s", DIM, dv, RESET)
				}
				fmt.Printf("  %s%-20s%s %-10s %s%s\n", CYAN, k, RESET, typ, desc, def)
			}
		}
	}

	fmt.Println()
}

func (s *SecV) ShowHelp(topic string) {
	if topic == "module" {
		if s.currentModule == nil {
			fmt.Printf("%s%s no module loaded%s\n", YELLOW, WARNING, RESET)
			return
		}
		s.ShowModuleHelp()
		return
	}

	printHeader("help")

	sections := []struct {
		title string
		cmds  [][]string
	}{
		{"modules", [][]string{
			{"use <module>", "load a module by name"},
			{"back  /  cd ..", "unload current module (cd .. = back)"},
			{"reload", "rescan tools directory for modules"},
		}},
		{"config", [][]string{
			{"set <param> <value>", "set a module parameter"},
			{"unset <param>", "clear a parameter"},
			{"show options", "list all params (required marked in red)"},
		}},
		{"run", [][]string{
			{"run <target>", "execute the loaded module against target"},
		}},
		{"info", [][]string{
			{"show modules", "list all available modules by category"},
			{"info [module]", "module details and dependency status"},
			{"search <keyword>", "search modules by name/description"},
			{"help module", "full help for the loaded module"},
		}},
		{"navigation", [][]string{
			{"cd <dir>", "change working directory"},
			{"cd ..  /  cd ../", "go up one directory (or back from module)"},
			{"pwd", "print current working directory"},
			{"ls [path]", "list directory contents"},
			{"mkdir <dir>", "create directory"},
			{"mv <src> <dst>", "move / rename file"},
			{"cp <src> <dst>", "copy file"},
			{"rm <file>", "remove file"},
			{"cat <file>", "print file contents"},
			{"find / grep / chmod", "standard Linux commands — all pass through"},
		}},
		{"system", [][]string{
			{"sessions [list|interact|kill]", "manage Meterpreter sessions"},
			{"update", "pull latest version from git"},
			{"clear", "clear the terminal"},
			{"exit / quit", "exit secV"},
		}},
	}

	for _, sec := range sections {
		fmt.Printf("\n%s%s%s%s\n", BOLD, YELLOW, sec.title, RESET)
		for _, c := range sec.cmds {
			pad := 32 - len(c[0])
			if pad < 1 {
				pad = 1
			}
			fmt.Printf("  %s%s%s%s%s\n", CYAN, c[0], RESET,
				strings.Repeat(" ", pad), c[1])
		}
	}
	fmt.Printf("\n%stab completion active — press Tab | any Linux command works natively%s\n\n", DIM, RESET)
}

func (s *SecV) ShowModuleHelp() {
	if s.currentModule == nil {
		return
	}
	// Try built-in --help first
	cmd := exec.Command("bash", "-c", s.currentModule.Executable+" --help")
	cmd.Dir = s.currentModule.Path
	out, err := cmd.Output()
	if err == nil && strings.Contains(string(out), "╔") {
		fmt.Print(string(out))
		return
	}

	if s.currentModule.Help == nil {
		s.ShowInfo(s.currentModule.Name)
		return
	}
	h := s.currentModule.Help
	name := s.currentModule.Name

	printHeader(name + " help")

	if h.Description != "" {
		fmt.Printf("\n%sdescription%s\n  %s\n", DIM, RESET, h.Description)
	}

	fmt.Printf("\n%susage%s\n", DIM, RESET)
	fmt.Printf("  use %s\n  show options\n  run <target>\n", name)

	if len(h.Parameters) > 0 {
		fmt.Printf("\n%sparameters%s\n", DIM, RESET)
		for pname, pi := range h.Parameters {
			req := ""
			if pi.Required {
				req = " *"
			}
			fmt.Printf("  %s%s%s%s  %s(%s)%s\n", BOLD, pname, req, RESET, DIM, pi.Type, RESET)
			if pi.Description != "" {
				fmt.Printf("    %s\n", pi.Description)
			}
		}
	}

	if len(h.Examples) > 0 {
		fmt.Printf("\n%sexamples%s\n", DIM, RESET)
		for _, ex := range h.Examples {
			fmt.Printf("  %s\n", ex.Description)
			for _, c := range ex.Commands {
				fmt.Printf("    %s%s%s\n", CYAN, c, RESET)
			}
		}
	}

	if len(h.Notes) > 0 {
		fmt.Printf("\n%snotes%s\n", DIM, RESET)
		for _, n := range h.Notes {
			fmt.Printf("  %s %s\n", BULLET, n)
		}
	}
	fmt.Println()
}

func (s *SecV) Search(query string) {
	query = strings.ToLower(query)
	found := 0
	for _, m := range s.modules {
		if strings.Contains(strings.ToLower(m.Name), query) ||
			strings.Contains(strings.ToLower(m.Description), query) ||
			strings.Contains(strings.ToLower(m.Category), query) {
			found++
			fmt.Printf("  %s%s%s  %s[%s]%s\n", CYAN, m.Name, RESET, DIM, m.Category, RESET)
			fmt.Printf("    %s\n", m.Description)
		}
	}
	if found == 0 {
		fmt.Printf("%sno results for '%s'%s\n", DIM, query, RESET)
	}
}

func (s *SecV) Update() {
	updateScript := filepath.Join(s.secvHome, "update.py")
	if _, err := os.Stat(updateScript); os.IsNotExist(err) {
		fmt.Printf("%s%s update.py not found%s\n", RED, CROSS, RESET)
		return
	}
	cmd := exec.Command("python3", updateScript)
	cmd.Dir = s.secvHome
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok && e.ExitCode() == 2 {
			fmt.Printf("\n%s%s restart to apply%s\n", YELLOW, WARNING, RESET)
		}
	}
}

// ============================================================================
// MSF RPC session management
// ============================================================================

func (s *SecV) loadMSFConfig() bool {
	home, _ := os.UserHomeDir()
	cfgPath := filepath.Join(home, ".secv", "msf_rpc.json")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return false
	}
	cfg := &msfRPCConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return false
	}
	s.msfCfg = cfg
	return true
}

// msfRPC sends a JSON-RPC call to msfrpcd and returns the response map.
func (s *SecV) msfRPC(method string, params []interface{}) (map[string]interface{}, error) {
	if s.msfCfg == nil {
		if !s.loadMSFConfig() {
			return nil, fmt.Errorf("no MSF RPC config — run android_pentest with operation=msf_handler first")
		}
	}

	// Authenticate if we don't have a token yet
	if s.msfToken == "" {
		body := []interface{}{"auth.login", s.msfCfg.Pass}
		resp, err := s.msfRPCRaw(body)
		if err != nil {
			return nil, fmt.Errorf("MSF RPC auth failed: %v", err)
		}
		if result, ok := resp["result"].(string); ok && result == "success" {
			s.msfToken, _ = resp["token"].(string)
		} else {
			return nil, fmt.Errorf("MSF RPC auth rejected")
		}
	}

	call := append([]interface{}{method, s.msfToken}, params...)
	return s.msfRPCRaw(call)
}

func (s *SecV) msfRPCRaw(payload []interface{}) (map[string]interface{}, error) {
	url := fmt.Sprintf("http://%s:%d/api/", s.msfCfg.Host, s.msfCfg.Port)
	body, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("bad RPC response: %s", raw[:min(200, len(raw))])
	}
	return result, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Sessions lists all active Meterpreter / shell sessions from msfrpcd.
func (s *SecV) Sessions() {
	resp, err := s.msfRPC("session.list", nil)
	if err != nil {
		fmt.Printf("%s%s %v%s\n", RED, CROSS, err, RESET)
		return
	}

	sessions, ok := resp["sessions"].(map[string]interface{})
	if !ok || len(sessions) == 0 {
		fmt.Printf("%s  no active sessions%s\n", DIM, RESET)
		return
	}

	fmt.Printf("\n%s%-6s %-12s %-18s %-20s %s%s\n",
		BOLD, "ID", "TYPE", "VIA", "TUNNEL", "INFO", RESET)
	fmt.Printf("%s%s%s\n", DIM, strings.Repeat("─", 72), RESET)
	for id, raw := range sessions {
		sess, _ := raw.(map[string]interface{})
		stype, _ := sess["type"].(string)
		via, _    := sess["via_exploit"].(string)
		tunnel, _ := sess["tunnel_local"].(string)
		info, _   := sess["info"].(string)
		fmt.Printf("%-6s %-12s %-18s %-20s %s\n",
			id, stype, via, tunnel, info)
	}
	fmt.Println()
}

// SessionInteract drops into an interactive msfconsole session.
func (s *SecV) SessionInteract(id string) {
	if !CAPS_HAS("msfconsole") {
		fmt.Printf("%s%s msfconsole not found%s\n", RED, CROSS, RESET)
		return
	}
	fmt.Printf("%s  attaching to session %s (ctrl+z to background)%s\n", DIM, id, RESET)
	cmd := exec.Command("msfconsole", "-q", "-x",
		fmt.Sprintf("sessions -i %s", id))
	cmd.Stdin  = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}

// SessionKill terminates a session.
func (s *SecV) SessionKill(id string) {
	resp, err := s.msfRPC("session.stop", []interface{}{id})
	if err != nil {
		fmt.Printf("%s%s %v%s\n", RED, CROSS, err, RESET)
		return
	}
	if result, _ := resp["result"].(string); result == "success" {
		fmt.Printf("%s%s session %s killed%s\n", GREEN, CHECK, id, RESET)
	} else {
		fmt.Printf("%s%s failed: %v%s\n", RED, CROSS, resp, RESET)
	}
}

func CAPS_HAS(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}

// ============================================================================
// Linux shell passthrough
// ============================================================================

var shellPassthroughCmds = map[string]bool{
	"ls": true, "ll": true, "la": true, "dir": true,
	"mkdir": true, "rmdir": true, "mv": true, "cp": true, "rm": true,
	"cat": true, "less": true, "more": true, "head": true, "tail": true,
	"echo": true, "touch": true, "pwd": true,
	"find": true, "grep": true, "egrep": true, "rg": true,
	"chmod": true, "chown": true, "ln": true,
	"whoami": true, "id": true, "which": true, "whereis": true,
	"file": true, "stat": true, "df": true, "du": true,
	"ps": true, "kill": true, "killall": true,
	"sort": true, "wc": true, "uniq": true, "diff": true,
	"tar": true, "gzip": true, "unzip": true,
	"curl": true, "wget": true,
	"python3": true, "python": true, "bash": true, "sh": true,
	"git": true, "nano": true, "vim": true, "vi": true,
	"env": true, "export": true, "printenv": true,
	"uname": true, "hostname": true, "uptime": true, "date": true,
}

func (s *SecV) execShellCmd(line string) {
	cmd := exec.Command("bash", "-c", line)
	cmd.Dir = s.workDir
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}

func (s *SecV) changeDir(target string) {
	var newDir string
	switch target {
	case "", "~":
		home, _ := os.UserHomeDir()
		newDir = home
	case "-":
		// Go to previous dir — just stay if no history
		newDir = s.workDir
	default:
		if filepath.IsAbs(target) {
			newDir = target
		} else {
			newDir = filepath.Join(s.workDir, target)
		}
	}
	// Resolve symlinks / clean path
	resolved, err := filepath.EvalSymlinks(newDir)
	if err != nil {
		fmt.Printf("%scd: %s: No such file or directory%s\n", RED, target, RESET)
		return
	}
	fi, err := os.Stat(resolved)
	if err != nil || !fi.IsDir() {
		fmt.Printf("%scd: %s: Not a directory%s\n", RED, target, RESET)
		return
	}
	s.workDir = resolved
	// Keep OS process cwd in sync so child commands (ls, find…) see the same dir
	_ = os.Chdir(resolved)
}

// ============================================================================
// Tab completion
// ============================================================================

func (s *SecV) buildCompleter() *readline.PrefixCompleter {
	topCmds := []readline.PrefixCompleterInterface{
		// secV commands
		readline.PcItem("use",
			readline.PcItemDynamic(func(_ string) []string { return s.moduleNames() }),
		),
		readline.PcItem("back"),
		readline.PcItem("reload"),
		readline.PcItem("set"),
		readline.PcItem("unset"),
		readline.PcItem("run"),
		readline.PcItem("show",
			readline.PcItem("modules"),
			readline.PcItem("options"),
		),
		readline.PcItem("info",
			readline.PcItemDynamic(func(_ string) []string { return s.moduleNames() }),
		),
		readline.PcItem("search"),
		readline.PcItem("sessions",
			readline.PcItem("list"),
			readline.PcItem("interact"),
			readline.PcItem("kill"),
		),
		readline.PcItem("help",
			readline.PcItem("module"),
		),
		readline.PcItem("update"),
		readline.PcItem("clear"),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
		// Linux navigation / filesystem
		readline.PcItem("cd"),
		readline.PcItem("pwd"),
		readline.PcItem("ls"),
		readline.PcItem("ll"),
		readline.PcItem("la"),
		readline.PcItem("mkdir"),
		readline.PcItem("rmdir"),
		readline.PcItem("mv"),
		readline.PcItem("cp"),
		readline.PcItem("rm"),
		readline.PcItem("cat"),
		readline.PcItem("less"),
		readline.PcItem("head"),
		readline.PcItem("tail"),
		readline.PcItem("find"),
		readline.PcItem("grep"),
		readline.PcItem("chmod"),
		readline.PcItem("chown"),
		readline.PcItem("touch"),
		readline.PcItem("file"),
		readline.PcItem("stat"),
		readline.PcItem("whoami"),
		readline.PcItem("which"),
		readline.PcItem("git"),
	}
	return readline.NewPrefixCompleter(topCmds...)
}

func (s *SecV) prompt() string {
	base := fmt.Sprintf("%s%ssecV%s", BOLD, GREEN, RESET)
	if s.currentModule != nil {
		modPart := fmt.Sprintf(" %s%s%s", CYAN, s.currentModule.Name, RESET)
		opPart := ""
		if op, ok := s.params["operation"]; ok {
			opPart = fmt.Sprintf(" %s›%s %s%s%s", DIM, RESET, YELLOW, op, RESET)
		}
		paramPart := ""
		if n := len(s.params); n > 0 {
			paramPart = fmt.Sprintf(" %s[%d params]%s", DIM, n, RESET)
		}
		return fmt.Sprintf("%s%s%s%s ❯ ", base, modPart, opPart, paramPart)
	}
	return fmt.Sprintf("%s ❯ ", base)
}

// ============================================================================
// Banner + startup
// ============================================================================

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
	fmt.Printf("%s   v%s%s\n\n", DIM, VERSION, RESET)
}

func printHeader(title string) {
	bar := strings.Repeat("─", 60)
	fmt.Printf("\n%s%s%s%s\n", BOLD, CYAN, bar, RESET)
	fmt.Printf(" %s%s%s\n", BOLD, title, RESET)
	fmt.Printf("%s%s%s\n", DIM, bar, RESET)
}

func printSection(title string) {
	fmt.Printf("\n%s%s%s\n", DIM, title, RESET)
}

// ============================================================================
// main
// ============================================================================

func main() {
	fmt.Print("\033[H\033[2J")
	printBanner()

	secv := NewSecV()

	// Show detected distro info once
	if secv.distro.id != "" {
		line := secv.distro.id
		if secv.distro.aurHelper != "" {
			line += " (" + secv.distro.aurHelper + ")"
		}
		fmt.Printf("%s  os   %s %s\n", DIM, RESET, line)
	}
	fmt.Printf("%s  path %s %s\n\n", DIM, RESET, secv.secvHome)

	// Load modules
	if err := secv.ScanModules(); err != nil {
		fmt.Printf("%s%s %v%s\n", RED, CROSS, err, RESET)
	}
	fmt.Printf("%s%s %d modules%s  %stype 'help' for commands%s\n\n",
		GREEN, CHECK, len(secv.modules), RESET, DIM, RESET)

	// Build readline instance with tab completion
	completer := secv.buildCompleter()
	rl, err := readline.NewEx(&readline.Config{
		Prompt:              secv.prompt(),
		HistoryFile:         filepath.Join(secv.cacheDir, ".history"),
		AutoComplete:        completer,
		InterruptPrompt:     "^C",
		EOFPrompt:           "exit",
		HistorySearchFold:   true,
	})
	if err != nil {
		panic(err)
	}
	defer rl.Close()

	for {
		rl.SetPrompt(secv.prompt())
		line, err := rl.Readline()
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := parts[0]
		args := parts[1:]

		switch cmd {
		case "use":
			if len(args) == 0 {
				fmt.Printf("%suse <module>%s\n", DIM, RESET)
			} else {
				if err := secv.UseModule(args[0]); err != nil {
					fmt.Printf("%s%s %v%s\n", RED, CROSS, err, RESET)
				}
			}

		case "back":
			secv.Back()

		case "set":
			if len(args) < 2 {
				fmt.Printf("%sset <param> <value>%s\n", DIM, RESET)
			} else {
				secv.SetParam(args[0], strings.Join(args[1:], " "))
			}

		case "unset":
			if len(args) == 0 {
				fmt.Printf("%sunset <param>%s\n", DIM, RESET)
			} else {
				secv.UnsetParam(args[0])
			}

		case "run":
			if len(args) == 0 {
				fmt.Printf("%srun <target>%s\n", DIM, RESET)
			} else if err := secv.Run(args[0]); err != nil {
				// error already printed inside Run
			}

		case "show":
			if len(args) == 0 {
				fmt.Printf("%sshow modules | options%s\n", DIM, RESET)
			} else {
				switch args[0] {
				case "modules":
					secv.ShowModules()
				case "options":
					secv.ShowOptions()
				default:
					fmt.Printf("%sunknown: show %s%s\n", DIM, args[0], RESET)
				}
			}

		case "info":
			name := ""
			if len(args) > 0 {
				name = args[0]
			}
			secv.ShowInfo(name)

		case "search":
			if len(args) == 0 {
				fmt.Printf("%ssearch <keyword>%s\n", DIM, RESET)
			} else {
				secv.Search(strings.Join(args, " "))
			}

		case "help":
			topic := ""
			if len(args) > 0 {
				topic = args[0]
			}
			secv.ShowHelp(topic)

		case "reload":
			if err := secv.ScanModules(); err != nil {
				fmt.Printf("%s%s %v%s\n", RED, CROSS, err, RESET)
			} else {
				fmt.Printf("%s%s %d modules%s\n", GREEN, CHECK, len(secv.modules), RESET)
			}
			// Rebuild completer after reload so new module names appear in tab
			completer = secv.buildCompleter()
			rl.Config.AutoComplete = completer

		case "sessions":
			sub := ""
			if len(args) > 0 {
				sub = args[0]
			}
			switch sub {
			case "list", "":
				secv.Sessions()
			case "interact":
				if len(args) < 2 {
					fmt.Printf("%ssessions interact <id>%s\n", DIM, RESET)
				} else {
					secv.SessionInteract(args[1])
				}
			case "kill":
				if len(args) < 2 {
					fmt.Printf("%ssessions kill <id>%s\n", DIM, RESET)
				} else {
					secv.SessionKill(args[1])
				}
			default:
				fmt.Printf("%s? sessions list | interact <id> | kill <id>%s\n", DIM, RESET)
			}

		case "update":
			secv.Update()

		case "clear":
			fmt.Print("\033[H\033[2J")

		case "exit", "quit":
			fmt.Println()
			return

		// ── Linux navigation ────────────────────────────────────────────────
		case "cd":
			target := ""
			if len(args) > 0 {
				target = strings.Join(args, " ")
			}
			// cd .. / cd ../ → back (unload module), then go up in filesystem
			if target == ".." || target == "../" || target == "-" {
				if secv.currentModule != nil {
					secv.Back()
				} else {
					secv.changeDir("..")
				}
			} else {
				secv.changeDir(target)
				fmt.Printf("%s%s%s\n", DIM, secv.workDir, RESET)
			}

		case "pwd":
			fmt.Printf("%s%s%s\n", DIM, secv.workDir, RESET)

		default:
			// Transparent passthrough for standard Linux commands
			if shellPassthroughCmds[cmd] {
				secv.execShellCmd(line)
			} else {
				fmt.Printf("%s? %s  (type 'help')%s\n", YELLOW, cmd, RESET)
			}
		}
	}
}
