package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/chzyer/readline"
)

const VERSION = "2.4.3"
const CODENAME = "tauri"

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
	case "arch", "archcraft", "manjaro", "endeavouros", "cachyos", "artix", "garuda":
		info.pkgMgr = "pacman"
		for _, aur := range []string{"yay", "paru", "trizen"} {
			if path, _ := exec.LookPath(aur); path != "" {
				info.aurHelper = aur
				break
			}
		}
	case "ubuntu", "debian", "kali", "parrot", "linuxmint", "pop", "elementary", "zorin", "mx":
		info.pkgMgr = "apt"
	case "fedora", "nobara":
		info.pkgMgr = "dnf"
	case "rhel", "centos", "rocky", "alma", "oracle":
		info.pkgMgr = "dnf"
	case "opensuse-leap", "opensuse-tumbleweed", "sles", "opensuse":
		info.pkgMgr = "zypper"
	case "alpine":
		info.pkgMgr = "apk"
	case "void":
		info.pkgMgr = "xbps-install"
	case "gentoo":
		info.pkgMgr = "emerge"
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
	case "emerge":
		cmd = exec.Command("sudo", "emerge", "--ask=n", pkg)
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
	// binary              pacman                   apt                          dnf                    zypper              apk                  brew
	"adb":           {"pacman": "android-tools", "apt": "adb",                "dnf": "android-tools",                                          "brew": "android-platform-tools"},
	"fastboot":      {"pacman": "android-tools", "apt": "fastboot",           "dnf": "android-tools"},
	"nmap":          {"pacman": "nmap",          "apt": "nmap",               "dnf": "nmap",          "zypper": "nmap",    "apk": "nmap",       "brew": "nmap"},
	"masscan":       {"pacman": "masscan",       "apt": "masscan",            "dnf": "masscan"},
	"rustscan":      {"pacman": "rustscan",      "apt": "rustscan",                                                                             "brew": "rustscan"},
	"tcpdump":       {"pacman": "tcpdump",       "apt": "tcpdump",            "dnf": "tcpdump",       "zypper": "tcpdump", "apk": "tcpdump",    "brew": "tcpdump"},
	"wireshark":     {"pacman": "wireshark-qt",  "apt": "wireshark",          "dnf": "wireshark"},
	"apktool":       {"pacman": "apktool",       "apt": "apktool",                                                                             "brew": "apktool"},
	"jadx":          {"pacman": "jadx",          "apt": "jadx"},
	"aapt":          {"pacman": "aapt",          "apt": "aapt"},
	"ideviceinfo":   {"pacman": "libimobiledevice", "apt": "libimobiledevice-utils", "dnf": "libimobiledevice-utils",                         "brew": "libimobiledevice"},
	"ideviceinstaller": {"pacman": "ideviceinstaller", "apt": "ideviceinstaller",                                                             "brew": "ideviceinstaller"},
	"python3":       {"pacman": "python",        "apt": "python3",            "dnf": "python3",       "zypper": "python3", "apk": "python3",   "brew": "python@3"},
	"jq":            {"pacman": "jq",            "apt": "jq",                 "dnf": "jq",            "zypper": "jq",      "apk": "jq",        "brew": "jq"},
	"curl":          {"pacman": "curl",          "apt": "curl",               "dnf": "curl",          "zypper": "curl",    "apk": "curl",      "brew": "curl"},
	"wget":          {"pacman": "wget",          "apt": "wget",               "dnf": "wget",          "zypper": "wget",    "apk": "wget",      "brew": "wget"},
	"git":           {"pacman": "git",           "apt": "git",                "dnf": "git",           "zypper": "git",     "apk": "git",       "brew": "git"},
	"go":            {"pacman": "go",            "apt": "golang-go",          "dnf": "golang",        "zypper": "go",      "apk": "go",        "brew": "go"},
	"avahi-browse":  {"pacman": "avahi",         "apt": "avahi-utils",        "dnf": "avahi-tools"},
	"arp-scan":      {"pacman": "arp-scan",      "apt": "arp-scan",           "dnf": "arp-scan"},
	"smbclient":     {"pacman": "smbclient",     "apt": "smbclient",          "dnf": "samba-client",  "zypper": "samba-client", "apk": "samba-client"},
	"rpcclient":     {"pacman": "smbclient",     "apt": "smbclient",          "dnf": "samba-client"},
	"xorriso":       {"pacman": "xorriso",       "apt": "xorriso",            "dnf": "xorriso",       "zypper": "xorriso"},
	"hashcat":       {"pacman": "hashcat",       "apt": "hashcat",            "dnf": "hashcat",                                                "brew": "hashcat"},
	"john":          {"pacman": "john",          "apt": "john",               "dnf": "john"},
	"nc":            {"pacman": "nmap-ncat",     "apt": "netcat-traditional", "dnf": "nmap-ncat",                          "apk": "netcat-openbsd"},
	"ncat":          {"pacman": "nmap-ncat",     "apt": "ncat",               "dnf": "nmap-ncat"},
	"ssh":           {"pacman": "openssh",       "apt": "openssh-client",     "dnf": "openssh-clients", "zypper": "openssh", "apk": "openssh-client", "brew": "openssh"},
	"ip":            {"pacman": "iproute2",      "apt": "iproute2",           "dnf": "iproute",       "zypper": "iproute2", "apk": "iproute2"},
	"whois":         {"pacman": "whois",         "apt": "whois",              "dnf": "whois",         "zypper": "whois",   "apk": "whois",     "brew": "whois"},
	"msfconsole":    {"pacman": "metasploit",    "apt": "metasploit-framework"},
	"msfvenom":      {"pacman": "metasploit",    "apt": "metasploit-framework"},
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
	Operations   map[string]string      `json:"operations"`
	Concurrent   bool                   `json:"concurrent"`
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
	globalParams  map[string]string // survive back/use — set with setg
	lastTarget    string            // reused by bare `run` with no arg
	secvHome      string
	toolsDir      string
	cacheDir      string
	workDir       string
	distro        distroInfo
	msfToken      string        // authenticated MSF RPC token
	msfCfg        *msfRPCConfig // loaded from ~/.secv/msf_rpc.json
}

// resolveSecvHome returns the directory that contains tools/ and update.py.
// Resolution order:
//  1. $SECV_HOME env var (explicit override, always wins)
//  2. Directory of the real binary after following any symlinks
//     — works for ./secV (dev) and ln -sf … /usr/local/bin/secV
//     — only accepted if tools/ exists there (guards against bare /usr/local/bin)
//  3. /var/lib/secv — standard system-install location copied by install.sh
//  4. Current working directory — last-resort for ad-hoc / portable use
func resolveSecvHome() string {
	if env := os.Getenv("SECV_HOME"); env != "" {
		return env
	}
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			dir := filepath.Dir(real)
			if _, e := os.Stat(filepath.Join(dir, "tools")); e == nil {
				return dir
			}
		}
	}
	if _, err := os.Stat("/var/lib/secv/tools"); err == nil {
		return "/var/lib/secv"
	}
	wd, _ := os.Getwd()
	return wd
}

func NewSecV() *SecV {
	home := resolveSecvHome()
	userHome, _ := os.UserHomeDir()
	cacheDir := filepath.Join(userHome, ".secv", "cache")
	_ = os.MkdirAll(cacheDir, 0750)
	wd, _ := os.Getwd()
	return &SecV{
		modules:      []*Module{},
		params:       make(map[string]string),
		globalParams: make(map[string]string),
		secvHome:     home,
		toolsDir:     filepath.Join(home, "tools"),
		cacheDir:     cacheDir,
		workDir:      wd,
		distro:       detectDistro(),
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

func (s *SecV) SetGlobal(key, value string) {
	s.globalParams[key] = value
	fmt.Printf("  %s%s%s -> %s%s%s %s(global)%s\n", BOLD, key, RESET, CYAN, value, RESET, DIM, RESET)
}

func (s *SecV) UnsetGlobal(key string) {
	if _, ok := s.globalParams[key]; ok {
		delete(s.globalParams, key)
		fmt.Printf("%s%s %s (global)%s\n", GREEN, CHECK, key, RESET)
	} else {
		fmt.Printf("%s%s '%s' not set globally%s\n", YELLOW, WARNING, key, RESET)
	}
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

// renderFindings parses the captured stdout of a module run and renders a
// structured findings table if the JSON output contains a "findings" array.
func renderFindings(output []byte) {
	// Attempt to find a JSON object in the output (modules may print non-JSON
	// lines before the final JSON blob).
	start := bytes.IndexByte(output, '{')
	if start == -1 {
		return
	}
	var result map[string]interface{}
	if err := json.Unmarshal(output[start:], &result); err != nil {
		// Try scanning line by line for the first parseable JSON object
		for _, line := range bytes.Split(output, []byte("\n")) {
			line = bytes.TrimSpace(line)
			if len(line) == 0 || line[0] != '{' {
				continue
			}
			if err2 := json.Unmarshal(line, &result); err2 == nil {
				break
			}
		}
		if result == nil {
			return
		}
	}

	// ── Errors ────────────────────────────────────────────────────────────────
	if errs, ok := result["errors"].([]interface{}); ok && len(errs) > 0 {
		fmt.Printf("\n%s%s errors%s\n", RED, BOLD, RESET)
		for _, e := range errs {
			fmt.Printf("  %s%s %v%s\n", RED, CROSS, e, RESET)
		}
	}

	// ── Findings ──────────────────────────────────────────────────────────────
	findings, ok := result["findings"].([]interface{})
	if !ok || len(findings) == 0 {
		return
	}

	severityColor := func(sev string) string {
		switch strings.ToLower(sev) {
		case "critical":
			return RED + BOLD
		case "high":
			return RED
		case "medium":
			return YELLOW
		case "low":
			return CYAN
		default: // info, unknown
			return DIM
		}
	}

	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

	fmt.Printf("\n%s%s findings%s\n", BOLD, CYAN, RESET)
	fmt.Printf("%s%s%s\n", DIM, strings.Repeat("─", 72), RESET)
	fmt.Printf("%s%-12s %-18s %s%s\n", BOLD, "SEVERITY", "CATEGORY", "DESCRIPTION", RESET)
	fmt.Printf("%s%s%s\n", DIM, strings.Repeat("─", 72), RESET)

	for _, raw := range findings {
		f, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		sev, _ := f["severity"].(string)
		if sev == "" {
			sev = "info"
		}
		cat, _ := f["category"].(string)
		desc, _ := f["description"].(string)
		if desc == "" {
			desc, _ = f["title"].(string)
		}
		if desc == "" {
			desc, _ = f["message"].(string)
		}
		if len(desc) > 46 {
			desc = desc[:43] + "..."
		}

		col := severityColor(sev)
		sevLower := strings.ToLower(sev)
		if _, tracked := counts[sevLower]; tracked {
			counts[sevLower]++
		} else {
			counts["info"]++
		}

		badge := fmt.Sprintf("%s[%s]%s", col, strings.ToUpper(sev), RESET)
		fmt.Printf("%-22s %-18s %s\n", badge, cat, desc)
	}

	fmt.Printf("%s%s%s\n", DIM, strings.Repeat("─", 72), RESET)

	// Summary line
	total := len(findings)
	summary := fmt.Sprintf("%s%d finding(s):%s", BOLD, total, RESET)
	if counts["critical"] > 0 {
		summary += fmt.Sprintf("  %s%d critical%s", RED+BOLD, counts["critical"], RESET)
	}
	if counts["high"] > 0 {
		summary += fmt.Sprintf("  %s%d high%s", RED, counts["high"], RESET)
	}
	if counts["medium"] > 0 {
		summary += fmt.Sprintf("  %s%d medium%s", YELLOW, counts["medium"], RESET)
	}
	if counts["low"] > 0 {
		summary += fmt.Sprintf("  %s%d low%s", CYAN, counts["low"], RESET)
	}
	if counts["info"] > 0 {
		summary += fmt.Sprintf("  %s%d info%s", DIM, counts["info"], RESET)
	}
	fmt.Printf("\n  %s\n", summary)
}

func (s *SecV) currentModuleParamNames() []string {
	if s.currentModule == nil {
		return nil
	}
	m := s.currentModule
	var names []string
	if m.Help != nil {
		for pname := range m.Help.Parameters {
			names = append(names, pname)
		}
	} else {
		for k := range m.Inputs {
			names = append(names, k)
		}
	}
	return names
}

func (s *SecV) Run(target string) error {
	if s.currentModule == nil {
		return fmt.Errorf("no module loaded")
	}
	if target == "" {
		if s.lastTarget != "" {
			target = s.lastTarget
			fmt.Printf("%s  reusing target: %s%s\n", DIM, target, RESET)
		} else {
			return fmt.Errorf("usage: run <target>")
		}
	}
	s.lastTarget = target

	// Module params override global params
	merged := make(map[string]string)
	for k, v := range s.globalParams {
		merged[k] = v
	}
	for k, v := range s.params {
		merged[k] = v
	}

	ctx := map[string]interface{}{
		"target": target,
		"params": merged,
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

	// Capture stdout into a buffer while simultaneously streaming to terminal.
	var outBuf bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &outBuf)
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	elapsed := time.Since(start)

	// Render structured findings table from captured output.
	renderFindings(outBuf.Bytes())

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
		fmt.Printf("%s%-22s %-9s %-5s %s%s\n", DIM, "NAME", "VERSION", "OPS", "DESCRIPTION", RESET)
		fmt.Printf("%s%s%s\n", DIM, strings.Repeat("─", 70), RESET)
		for _, m := range mods {
			desc := m.Description
			if len(desc) > 36 {
				desc = desc[:33] + "..."
			}
			ver := m.Version
			if ver == "" {
				ver = "—"
			}
			opCount := "—"
			if m.Help != nil {
				if opParam, ok := m.Help.Parameters["operation"]; ok && len(opParam.Options) > 0 {
					opCount = fmt.Sprintf("%d", len(opParam.Options))
				}
			}
			if opCount == "—" && len(m.Operations) > 0 {
				opCount = fmt.Sprintf("%d", len(m.Operations))
			}
			fmt.Printf("  %s%-20s%s %s%-9s%s %-5s %s%s%s\n",
				CYAN, m.Name, RESET,
				DIM, ver, RESET,
				opCount,
				DIM, desc, RESET)
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
		fmt.Printf("  %s%-24s %-10s %-5s %-14s %s%s\n", BOLD, "PARAM", "TYPE", "REQ", "CURRENT/DEFAULT", "DESCRIPTION", RESET)
		fmt.Printf("  %s%s%s\n", DIM, strings.Repeat("─", 72), RESET)
		// Sort for stable display
		keys := make([]string, 0, len(m.Inputs))
		for k := range m.Inputs {
			keys = append(keys, k)
		}
		for i := 0; i < len(keys)-1; i++ {
			for j := i + 1; j < len(keys); j++ {
				if keys[i] > keys[j] {
					keys[i], keys[j] = keys[j], keys[i]
				}
			}
		}
		for _, name := range keys {
			info := m.Inputs[name]
			inf, ok := info.(map[string]interface{})
			if !ok {
				continue
			}
			ptype, _ := inf["type"].(string)
			reqStr := "no"
			reqCol := DIM
			if r, _ := inf["required"].(bool); r {
				reqStr = "YES"
				reqCol = RED
			}
			val, isSet := s.params[name]
			var valStr string
			if isSet {
				v := val
				if len(v) > 20 {
					v = v[:17] + "..."
				}
				valStr = fmt.Sprintf("%s%s%s", CYAN, v, RESET)
			} else if dv, ok := inf["default"]; ok && dv != nil {
				dvs := fmt.Sprintf("%v", dv)
				if dvs != "" && dvs != "false" && dvs != "<nil>" {
					if len(dvs) > 14 {
						dvs = dvs[:11] + "..."
					}
					valStr = fmt.Sprintf("%s(default: %s)%s", DIM, dvs, RESET)
				} else {
					valStr = fmt.Sprintf("%snot set%s", DIM, RESET)
				}
			} else {
				valStr = fmt.Sprintf("%snot set%s", DIM, RESET)
			}
			nameStr := fmt.Sprintf("%s%s%s", BOLD, name, RESET)
			fmt.Printf("  %-32s %-10s %s%-5s%s %s\n", nameStr, ptype, reqCol, reqStr, RESET, valStr)
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

	// Global params
	if len(s.globalParams) > 0 {
		printSection("global (setg)")
		for k, v := range s.globalParams {
			fmt.Printf("  %s%-20s%s %s%s%s\n", BOLD, k, RESET, CYAN, v, RESET)
		}
	}

	fmt.Printf("\n%s  set <param> <value>  |  setg <param> <value>  |  run <target>  |  help module%s\n\n", DIM, RESET)
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

	// Operations display — from help.parameters["operation"].options or module.json "operations" map
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
	} else if len(m.Operations) > 0 {
		printSection("operations")
		ops := make([]string, 0, len(m.Operations))
		for op := range m.Operations {
			ops = append(ops, op)
		}
		for i := 0; i < len(ops)-1; i++ {
			for j := i + 1; j < len(ops); j++ {
				if ops[i] > ops[j] {
					ops[i], ops[j] = ops[j], ops[i]
				}
			}
		}
		for _, op := range ops {
			desc := m.Operations[op]
			if len(desc) > 52 {
				desc = desc[:49] + "..."
			}
			fmt.Printf("  %s%-24s%s %s%s%s\n", CYAN, op, RESET, DIM, desc, RESET)
		}
	}

	// Help-driven display: parameters, examples, features, notes, tiers
	if m.Help != nil {
		// Full parameters table
		if len(m.Help.Parameters) > 0 {
			printSection("parameters")
			fmt.Printf("  %s%-22s %-10s %-5s %-12s %s%s\n", BOLD, "PARAM", "TYPE", "REQ", "DEFAULT", "DESCRIPTION", RESET)
			fmt.Printf("  %s%s%s\n", DIM, strings.Repeat("─", 80), RESET)
			for pname, pi := range m.Help.Parameters {
				if pname == "operation" {
					continue
				}
				reqStr := "no"
				reqCol := DIM
				if pi.Required {
					reqStr = "YES"
					reqCol = RED
				}
				defStr := ""
				if pi.Default != nil {
					dv := fmt.Sprintf("%v", pi.Default)
					if dv != "" && dv != "false" && dv != "<nil>" {
						defStr = dv
					}
				}
				if len(defStr) > 12 {
					defStr = defStr[:9] + "..."
				}
				desc := pi.Description
				if len(desc) > 34 {
					desc = desc[:31] + "..."
				}
				nameStr := fmt.Sprintf("%s%s%s", CYAN, pname, RESET)
				fmt.Printf("  %-30s %-10s %s%-5s%s %-12s %s%s%s\n",
					nameStr, pi.Type, reqCol, reqStr, RESET, defStr, DIM, desc, RESET)
				if len(pi.Options) > 0 {
					fmt.Printf("    %soptions: %s%s\n", DIM, strings.Join(pi.Options, " | "), RESET)
				}
			}
		}

		// Examples
		if len(m.Help.Examples) > 0 {
			printSection("examples")
			for _, ex := range m.Help.Examples {
				fmt.Printf("  %s%s%s\n", DIM, ex.Description, RESET)
				for _, cmd := range ex.Commands {
					fmt.Printf("    %s%s%s\n", CYAN, cmd, RESET)
				}
				fmt.Println()
			}
		}

		// Features
		if len(m.Help.Features) > 0 {
			printSection("features")
			for _, feat := range m.Help.Features {
				fmt.Printf("  %s%s %s%s\n", GREEN, CHECK, feat, RESET)
			}
		}

		// Notes
		if len(m.Help.Notes) > 0 {
			printSection("notes")
			for _, note := range m.Help.Notes {
				fmt.Printf("  %s%s %s%s\n", DIM, BULLET, note, RESET)
			}
		}

		// Vulnerability coverage / installation tiers
		if len(m.Help.InstallationTiers) > 0 {
			printSection("vulnerability coverage")
			for tier, desc := range m.Help.InstallationTiers {
				fmt.Printf("  %s%-16s%s %s\n", YELLOW, tier, RESET, desc)
			}
		}
	}

	// Inputs (from module.json inputs block — used by modules without a help section)
	if len(m.Inputs) > 0 && m.Help == nil {
		printSection("inputs")
		fmt.Printf("  %s%-24s %-10s %-12s %s%s\n", BOLD, "PARAM", "TYPE", "DEFAULT", "DESCRIPTION", RESET)
		fmt.Printf("  %s%s%s\n", DIM, strings.Repeat("─", 72), RESET)
		// Sort param names for stable output
		keys := make([]string, 0, len(m.Inputs))
		for k := range m.Inputs {
			keys = append(keys, k)
		}
		for i := 0; i < len(keys)-1; i++ {
			for j := i + 1; j < len(keys); j++ {
				if keys[i] > keys[j] {
					keys[i], keys[j] = keys[j], keys[i]
				}
			}
		}
		for _, k := range keys {
			v := m.Inputs[k]
			if vm, ok := v.(map[string]interface{}); ok {
				typ := fmt.Sprintf("%v", vm["type"])
				reqStr := ""
				reqCol := DIM
				if r, _ := vm["required"].(bool); r {
					reqStr = "*"
					reqCol = RED
				}
				defStr := ""
				if dv, ok := vm["default"]; ok && dv != nil {
					dv_s := fmt.Sprintf("%v", dv)
					if dv_s != "" && dv_s != "false" && dv_s != "<nil>" {
						if len(dv_s) > 12 {
							dv_s = dv_s[:9] + "..."
						}
						defStr = dv_s
					}
				}
				nameStr := fmt.Sprintf("%s%s%s%s%s", CYAN, k, RESET, reqCol, reqStr)
				fmt.Printf("  %-32s %-10s %-12s\n", nameStr+RESET, typ, defStr)
			}
		}
		if m.Concurrent {
			fmt.Printf("\n  %sconcurrent%s  parallel operations supported\n", DIM, RESET)
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
			{"setg <param> <value>", "set a global param (survives back/use)"},
			{"unsetg <param>", "clear a global param"},
			{"show options  /  options", "list all params (required marked in red)"},
			{"show global", "list all global params"},
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
		{"filesystem", [][]string{
			{"cd <dir>", "change working directory"},
			{"cd ..  /  cd ../", "go up one directory (or back from module)"},
			{"pwd", "print current working directory"},
			{"ls / find / stat / file", "directory and file inspection"},
			{"mkdir / mv / cp / rm", "file management"},
			{"cat / head / tail / less", "file content"},
			{"chmod / chown / ln", "permissions and links"},
			{"tar / unzip / zip", "archives"},
		}},
		{"data", [][]string{
			{"grep / egrep / rg", "search file contents"},
			{"awk / sed / cut / sort", "text processing and extraction"},
			{"jq", "parse JSON output from tools"},
			{"base64 / xxd / strings", "encoding and binary inspection"},
			{"tee / wc / uniq / diff", "output capture and comparison"},
		}},
		{"network", [][]string{
			{"curl / wget", "HTTP requests and file download"},
			{"ssh / scp", "remote access and file transfer"},
			{"nc / ncat", "raw TCP/UDP connections"},
			{"ip / ping", "interface and connectivity checks"},
		}},
		{"pentest", [][]string{
			{"nmap <target>", "port scan — passthrough to system nmap"},
			{"smbclient / rpcclient", "SMB and RPC queries"},
			{"hashcat / john", "offline hash cracking"},
			{"msfconsole / msfvenom", "Metasploit console and payload gen"},
			{"nxc / netexec", "network exploitation framework"},
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
	fmt.Printf("\n%stab completion active — press Tab | pentest tools (nmap, hashcat, nxc…) pass through%s\n\n", DIM, RESET)
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
	// Filesystem
	"ls": true, "mkdir": true, "rmdir": true, "mv": true, "cp": true, "rm": true,
	"cat": true, "less": true, "head": true, "tail": true, "touch": true,
	"find": true, "file": true, "stat": true, "ln": true,
	// Text processing — essential for parsing tool output
	"grep": true, "egrep": true, "rg": true,
	"awk": true, "sed": true, "cut": true, "tee": true,
	"sort": true, "wc": true, "uniq": true, "diff": true,
	"jq": true, "xargs": true, "strings": true,
	// Encoding / conversion
	"base64": true, "xxd": true,
	// Archives
	"tar": true, "unzip": true, "zip": true,
	// File permissions / ownership
	"chmod": true, "chown": true,
	// Disk / process
	"df": true, "du": true, "ps": true, "kill": true, "killall": true,
	// Identity / path resolution
	"whoami": true, "id": true, "which": true, "whereis": true,
	// Network fetch
	"curl": true, "wget": true,
	// Network — useful for toolkit: quick connectivity checks, raw connections
	"ssh": true, "scp": true, "ip": true, "nc": true, "ncat": true, "ping": true,
	// Pentest tools — passthrough so operators can run them alongside modules
	"nmap": true, "nxc": true, "netexec": true, "crackmapexec": true,
	"smbclient": true, "rpcclient": true, "ldapsearch": true,
	"kerbrute": true, "hashcat": true, "john": true,
	"msfconsole": true, "msfvenom": true,
	"python3": true, "git": true,
	// Editors — useful for reviewing loot / editing configs mid-session
	"vim": true, "vi": true, "nano": true,
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
		readline.PcItem("set",
			readline.PcItemDynamic(func(_ string) []string { return s.currentModuleParamNames() }),
		),
		readline.PcItem("unset",
			readline.PcItemDynamic(func(_ string) []string { return s.currentModuleParamNames() }),
		),
		readline.PcItem("setg",
			readline.PcItemDynamic(func(_ string) []string { return s.currentModuleParamNames() }),
		),
		readline.PcItem("unsetg",
			readline.PcItemDynamic(func(_ string) []string {
				names := make([]string, 0, len(s.globalParams))
				for k := range s.globalParams {
					names = append(names, k)
				}
				return names
			}),
		),
		readline.PcItem("run"),
		readline.PcItem("options"),
		readline.PcItem("modules"),
		readline.PcItem("show",
			readline.PcItem("modules"),
			readline.PcItem("options"),
			readline.PcItem("global"),
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
		// Filesystem
		readline.PcItem("cd"),
		readline.PcItem("pwd"),
		readline.PcItem("ls"),
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
		readline.PcItem("egrep"),
		readline.PcItem("chmod"),
		readline.PcItem("chown"),
		readline.PcItem("touch"),
		readline.PcItem("file"),
		readline.PcItem("stat"),
		readline.PcItem("ln"),
		readline.PcItem("tar"),
		readline.PcItem("unzip"),
		readline.PcItem("zip"),
		// Data processing
		readline.PcItem("awk"),
		readline.PcItem("sed"),
		readline.PcItem("cut"),
		readline.PcItem("jq"),
		readline.PcItem("tee"),
		readline.PcItem("sort"),
		readline.PcItem("wc"),
		readline.PcItem("base64"),
		readline.PcItem("xxd"),
		readline.PcItem("strings"),
		// Identity / path
		readline.PcItem("whoami"),
		readline.PcItem("id"),
		readline.PcItem("which"),
		readline.PcItem("whereis"),
		// Network
		readline.PcItem("curl"),
		readline.PcItem("wget"),
		readline.PcItem("ssh"),
		readline.PcItem("scp"),
		readline.PcItem("nc"),
		readline.PcItem("ncat"),
		readline.PcItem("ip"),
		readline.PcItem("ping"),
		// Pentest tools
		readline.PcItem("nmap"),
		readline.PcItem("nxc"),
		readline.PcItem("netexec"),
		readline.PcItem("smbclient"),
		readline.PcItem("rpcclient"),
		readline.PcItem("hashcat"),
		readline.PcItem("john"),
		readline.PcItem("msfconsole"),
		readline.PcItem("msfvenom"),
		readline.PcItem("kerbrute"),
		// Dev
		readline.PcItem("python3"),
		readline.PcItem("git"),
		readline.PcItem("vim"),
		readline.PcItem("vi"),
		readline.PcItem("nano"),
	}
	return readline.NewPrefixCompleter(topCmds...)
}

// promptHint prints a brief status line above the prompt showing which params
// are currently set, so the user can see context at a glance without running
// "show options". Only printed when a module is loaded and params are set.
func (s *SecV) promptHint() {
	if s.currentModule == nil || len(s.params) == 0 {
		return
	}

	// Build a compact list of key=value pairs, truncated if too wide.
	parts := make([]string, 0, len(s.params))
	for k, v := range s.params {
		if len(v) > 20 {
			v = v[:17] + "..."
		}
		parts = append(parts, fmt.Sprintf("%s%s%s=%s%s%s", BOLD, k, RESET+DIM, RESET+CYAN, v, RESET))
	}
	hint := strings.Join(parts, fmt.Sprintf("  %s·%s  ", DIM, RESET))

	// Count required params that are still missing (red warning).
	missingReq := 0
	if s.currentModule.Help != nil {
		for pname, pi := range s.currentModule.Help.Parameters {
			if pi.Required {
				if _, ok := s.params[pname]; !ok {
					missingReq++
				}
			}
		}
	}

	statusIcon := GREEN + CHECK + RESET
	statusMsg := ""
	if missingReq > 0 {
		statusIcon = YELLOW + WARNING + RESET
		statusMsg = fmt.Sprintf("  %s%d required unset%s", YELLOW, missingReq, RESET)
	}

	fmt.Printf("%s  %d params:%s  %s%s\n",
		DIM, len(s.params), RESET, hint, statusMsg)
	_ = statusIcon // included in hint line above via icon choice
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
			paramPart = fmt.Sprintf(" %s[%d]%s", DIM, n, RESET)
		}
		return fmt.Sprintf("%s%s%s%s ❯ ", base, modPart, opPart, paramPart)
	}
	return fmt.Sprintf("%s ❯ ", base)
}

// ============================================================================
// Banner + startup
// ============================================================================

// vpnIP returns the IPv4 address of tun0 if the interface is up, else "".
func vpnIP() string {
	iface, err := net.InterfaceByName("tun0")
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil && ip.To4() != nil {
			return ip.String()
		}
	}
	return ""
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
	fmt.Printf("%s   v%s  %s%s%s\n", DIM, VERSION, YELLOW, CODENAME, RESET)

	// VPN indicator
	if ip := vpnIP(); ip != "" {
		fmt.Printf("  %s vpn%s  %s%s%s\n\n", GREEN+BOLD, RESET, GREEN, ip, RESET)
	} else {
		fmt.Printf("  %s vpn%s  %snot connected%s\n\n", YELLOW+BOLD, RESET, YELLOW, RESET)
	}
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
	fmt.Printf("%s  home %s %s\n", DIM, RESET, secv.secvHome)
	if secv.workDir != secv.secvHome {
		fmt.Printf("%s  cwd  %s %s\n", DIM, RESET, secv.workDir)
	}

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
		secv.promptHint()
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
				} else {
					// Rebuild completer so `set <Tab>` shows this module's params
					completer = secv.buildCompleter()
					rl.Config.AutoComplete = completer
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
			target := ""
			if len(args) > 0 {
				target = args[0]
			}
			if err := secv.Run(target); err != nil {
				fmt.Printf("%s%s %v%s\n", RED, CROSS, err, RESET)
			}

		case "setg":
			if len(args) < 2 {
				fmt.Printf("%ssetg <param> <value>%s\n", DIM, RESET)
			} else {
				secv.SetGlobal(args[0], strings.Join(args[1:], " "))
			}

		case "unsetg":
			if len(args) == 0 {
				fmt.Printf("%sunsetg <param>%s\n", DIM, RESET)
			} else {
				secv.UnsetGlobal(args[0])
			}

		case "options":
			secv.ShowOptions()

		case "modules":
			secv.ShowModules()

		case "show":
			if len(args) == 0 {
				fmt.Printf("%sshow modules | options | global%s\n", DIM, RESET)
			} else {
				switch args[0] {
				case "modules":
					secv.ShowModules()
				case "options":
					secv.ShowOptions()
				case "global":
					if len(secv.globalParams) == 0 {
						fmt.Printf("%s  no global params set%s\n", DIM, RESET)
					} else {
						fmt.Printf("\n%sglobal params%s\n", BOLD, RESET)
						for k, v := range secv.globalParams {
							fmt.Printf("  %s%-20s%s %s%s%s\n", BOLD, k, RESET, CYAN, v, RESET)
						}
					}
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
