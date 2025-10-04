#!/usr/bin/env python3
"""
SecV - The Polyglot Cybersecurity Orchestration Platform
A Metasploit-style interactive shell for security module orchestration

Usage:
    ./secV              # Run from current directory
    secV                # If installed system-wide
    
Installation:
    chmod +x secV
    ./install.sh        # Install dependencies and optionally deploy system-wide
"""

import cmd2
import json
import subprocess
import sys
import time
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
import platform
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich import box
from cmd2 import Cmd

# Initialize rich console for beautiful output
console = Console()

# Determine SecV installation path
SECV_DIR = Path(__file__).parent.resolve()
TOOLS_DIR = SECV_DIR / "tools"


@dataclass
class ModuleMetadata:
    """Represents a security module's metadata"""
    name: str
    version: str
    category: str
    description: str
    author: str
    executable: str = ""
    executables_by_os: Dict[str, str] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    inputs: Dict[str, Any] = field(default_factory=dict)
    outputs: Dict[str, Any] = field(default_factory=dict)
    concurrent: bool = False
    timeout: int = 300
    module_dir: Path = None

    @classmethod
    def from_json(cls, data: dict, module_dir: Path):
        """Create ModuleMetadata from JSON data"""
        return cls(
            name=data.get('name', ''),
            version=data.get('version', '1.0.0'),
            category=data.get('category', 'misc'),
            description=data.get('description', ''),
            author=data.get('author', ''),
            executable=data.get('executable', ''),
            executables_by_os=data.get('executablesByOS', {}),
            dependencies=data.get('dependencies', []),
            inputs=data.get('inputs', {}),
            outputs=data.get('outputs', {}),
            concurrent=data.get('concurrent', False),
            timeout=data.get('timeout', 300),
            module_dir=module_dir
        )

    def get_executable(self) -> str:
        """Get the appropriate executable for current OS"""
        os_name = platform.system().lower()
        if os_name == 'darwin':
            os_name = 'darwin'
        elif os_name == 'windows':
            os_name = 'windows'
        else:
            os_name = 'linux'
        
        return self.executables_by_os.get(os_name, self.executable)


@dataclass
class ModuleResult:
    """Represents the result of module execution"""
    success: bool
    data: Any
    errors: List[str]
    execution_time_ms: int
    module_name: str
    timestamp: datetime

    def to_dict(self):
        return {
            'success': self.success,
            'data': self.data,
            'errors': self.errors,
            'execution_time_ms': self.execution_time_ms,
            'module_name': self.module_name,
            'timestamp': self.timestamp.isoformat()
        }


class ModuleLoader:
    """Loads and manages security modules"""
    
    def __init__(self, tools_paths: List[Path]):
        self.modules: Dict[str, ModuleMetadata] = {}
        self.modules_by_category: Dict[str, List[str]] = {}
        self.tools_paths = tools_paths
        self.load_all_modules()

    def load_all_modules(self):
        """Load all modules from tools directories"""
        module_count = 0
        
        for tools_path in self.tools_paths:
            if not tools_path.exists():
                console.print(f"[yellow]Warning: Tools path not found: {tools_path}[/yellow]")
                continue
            
            # Walk through directory structure
            for module_json in tools_path.rglob('module.json'):
                try:
                    self._load_module(module_json)
                    module_count += 1
                except Exception as e:
                    console.print(f"[yellow]Failed to load {module_json}: {e}[/yellow]")
        
        console.print(f"[green]✓ Loaded {module_count} modules across {len(self.modules_by_category)} categories[/green]")

    def _load_module(self, config_path: Path):
        """Load a single module from its config file"""
        with open(config_path, 'r') as f:
            data = json.load(f)
        
        module_dir = config_path.parent
        meta = ModuleMetadata.from_json(data, module_dir)
        
        # Validation
        if not meta.name:
            raise ValueError("Module name is required")
        if not meta.executable and not meta.executables_by_os:
            raise ValueError(f"Module '{meta.name}' must have an executable")
        
        # Store module
        self.modules[meta.name] = meta
        
        # Organize by category
        category = meta.category.lower()
        if category not in self.modules_by_category:
            self.modules_by_category[category] = []
        self.modules_by_category[category].append(meta.name)
        
        console.print(f"[cyan]  ✓ Loaded: {meta.name} v{meta.version} [{meta.category}][/cyan]")

    def get_module(self, name: str) -> Optional[ModuleMetadata]:
        """Get a module by name"""
        return self.modules.get(name)

    def search_modules(self, query: str) -> List[ModuleMetadata]:
        """Search modules by name, description, or category"""
        query_lower = query.lower()
        results = []
        
        for module in self.modules.values():
            if (query_lower in module.name.lower() or 
                query_lower in module.description.lower() or
                query_lower in module.category.lower()):
                results.append(module)
        
        return results

    def get_categories(self) -> List[str]:
        """Get all available categories"""
        return sorted(self.modules_by_category.keys())

    def get_modules_by_category(self, category: str) -> List[ModuleMetadata]:
        """Get all modules in a category"""
        category = category.lower()
        module_names = self.modules_by_category.get(category, [])
        return [self.modules[name] for name in module_names]


class ExecutionEngine:
    """Executes security modules"""
    
    def execute(self, module: ModuleMetadata, target: str, params: Dict[str, Any]) -> ModuleResult:
        """Execute a module against a target"""
        start_time = time.time()
        
        # Get executable for current OS
        executable = module.get_executable()
        if not executable:
            return ModuleResult(
                success=False,
                data=None,
                errors=[f"No executable found for OS: {platform.system()}"],
                execution_time_ms=0,
                module_name=module.name,
                timestamp=datetime.now()
            )
        
        # Prepare execution context
        exec_context = {
            'target': target,
            'params': params,
            'results': {},
            'workflow_id': None,
            'step_id': None
        }
        
        # Serialize context to JSON
        context_json = json.dumps(exec_context)
        
        console.print(f"[yellow]⚙️  Executing {module.name} against {target} (timeout: {module.timeout}s)...[/yellow]")
        
        try:
            # Execute the module
            result = subprocess.run(
                executable.split(),
                input=context_json.encode(),
                capture_output=True,
                timeout=module.timeout,
                cwd=module.module_dir
            )
            
            execution_time = int((time.time() - start_time) * 1000)
            
            # Parse output
            if result.returncode != 0:
                stderr = result.stderr.decode('utf-8', errors='ignore')
                return ModuleResult(
                    success=False,
                    data=None,
                    errors=[f"Execution failed: {stderr}"],
                    execution_time_ms=execution_time,
                    module_name=module.name,
                    timestamp=datetime.now()
                )
            
            # Parse JSON output
            stdout = result.stdout.decode('utf-8', errors='ignore')
            output_data = json.loads(stdout)
            
            return ModuleResult(
                success=output_data.get('success', False),
                data=output_data.get('data'),
                errors=output_data.get('errors', []),
                execution_time_ms=execution_time,
                module_name=module.name,
                timestamp=datetime.now()
            )
            
        except subprocess.TimeoutExpired:
            execution_time = int((time.time() - start_time) * 1000)
            return ModuleResult(
                success=False,
                data=None,
                errors=[f"Execution timed out after {module.timeout} seconds"],
                execution_time_ms=execution_time,
                module_name=module.name,
                timestamp=datetime.now()
            )
        except json.JSONDecodeError as e:
            execution_time = int((time.time() - start_time) * 1000)
            return ModuleResult(
                success=False,
                data=None,
                errors=[f"Failed to parse module output: {e}"],
                execution_time_ms=execution_time,
                module_name=module.name,
                timestamp=datetime.now()
            )
        except Exception as e:
            execution_time = int((time.time() - start_time) * 1000)
            return ModuleResult(
                success=False,
                data=None,
                errors=[f"Unexpected error: {e}"],
                execution_time_ms=execution_time,
                module_name=module.name,
                timestamp=datetime.now()
            )


class SecVShell(Cmd):
    """SecV Interactive Shell - Metasploit-style interface"""
    
    def __init__(self):
        super().__init__()
        
        # Show dramatic welcome sequence
        self._show_welcome_sequence()
        
        # Shell configuration
        self.intro = self._get_banner()
        self.prompt = self._build_prompt()
        
        # Rich shell features
        self.allow_cli_args = False
        self.shortcuts = {
            '?': 'help',
            'q': 'exit',
        }
        
        # Initialize components
        console.print("\n[cyan]Loading SecV components...[/cyan]")
        time.sleep(0.3)
        
        console.print("[yellow]⚙  Initializing module loader...[/yellow]")
        time.sleep(0.2)
        self.loader = ModuleLoader([TOOLS_DIR])
        
        console.print("[yellow]⚙  Starting execution engine...[/yellow]")
        time.sleep(0.2)
        self.executor = ExecutionEngine()
        
        console.print("[green]✓ All systems operational[/green]\n")
        time.sleep(0.3)
        
        # Shell state
        self.current_module: Optional[ModuleMetadata] = None
        self.module_params: Dict[str, Any] = {}
        
        # Disable built-in commands we don't need
        self.hidden_commands.extend(['alias', 'edit', 'macro', 'run_pyscript', 'run_script', 'shell'])

    def _get_banner(self) -> str:
        """Get the SecV banner"""
        banner = """
[cyan]╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ███████╗███████╗ ██████╗██╗   ██╗                             ║
║   ██╔════╝██╔════╝██╔════╝██║   ██║                             ║
║   ███████╗█████╗  ██║     ██║   ██║                             ║
║   ╚════██║██╔══╝  ██║     ╚██╗ ██╔╝                             ║
║   ███████║███████╗╚██████╗ ╚████╔╝                              ║
║   ╚══════╝╚══════╝ ╚═════╝  ╚═══╝                               ║
║                                                                   ║
║   The Polyglot Cybersecurity Orchestration Platform v0.2.0       ║
║   Type 'help' or '?' for available commands                      ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝[/cyan]
"""
        return banner

    def _build_prompt(self) -> str:
        """Build the shell prompt"""
        if self.current_module:
            return f"[bold green]secV[/bold green] [bold red]({self.current_module.name})[/bold red] > "
        return "[bold green]secV[/bold green] > "

    def do_show(self, args):
        """
        Show various information
        Usage: show [modules|categories|options]
        """
        if not args:
            console.print("[yellow]Usage: show [modules|categories|options][/yellow]")
            return
        
        parts = args.split()
        target = parts[0].lower()
        
        if target == 'modules':
            self._show_modules()
        elif target == 'categories':
            self._show_categories()
        elif target == 'options':
            self._show_options()
        else:
            console.print(f"[yellow]Unknown show target: {target}[/yellow]")

    def _show_modules(self):
        """Display all available modules"""
        categories = self.loader.get_categories()
        
        table = Table(title=f"Available Modules ({len(self.loader.modules)} total)", 
                     box=box.ROUNDED)
        table.add_column("Module", style="cyan", no_wrap=True)
        table.add_column("Version", style="yellow")
        table.add_column("Category", style="green")
        table.add_column("Description", style="white")
        
        for category in categories:
            modules = self.loader.get_modules_by_category(category)
            for module in modules:
                table.add_row(
                    module.name,
                    module.version,
                    module.category,
                    module.description
                )
        
        console.print(table)

    def _show_categories(self):
        """Display all categories"""
        categories = self.loader.get_categories()
        
        table = Table(title="Module Categories", box=box.ROUNDED)
        table.add_column("Category", style="green")
        table.add_column("Module Count", style="cyan")
        
        for category in categories:
            count = len(self.loader.modules_by_category[category])
            table.add_row(category.upper(), str(count))
        
        console.print(table)

    def _show_options(self):
        """Display current module options"""
        if not self.current_module:
            console.print("[yellow]No module loaded. Use 'use <module>' first[/yellow]")
            return
        
        if not self.current_module.inputs:
            console.print("[yellow]This module has no configurable options[/yellow]")
            return
        
        table = Table(title=f"Module Options: {self.current_module.name}", box=box.ROUNDED)
        table.add_column("Option", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Required", style="red")
        table.add_column("Description", style="white")
        table.add_column("Current Value", style="green")
        
        for name, spec in self.current_module.inputs.items():
            required = "Yes" if spec.get('required', False) else "No"
            current = self.module_params.get(name, "")
            
            table.add_row(
                name,
                str(spec.get('type', 'string')),
                required,
                spec.get('description', ''),
                str(current)
            )
        
        console.print(table)

    def do_use(self, args):
        """
        Load a module for execution
        Usage: use <module_name>
        """
        if not args:
            console.print("[yellow]Usage: use <module_name>[/yellow]")
            return
        
        module_name = args.strip()
        module = self.loader.get_module(module_name)
        
        if not module:
            console.print(f"[red]Module '{module_name}' not found[/red]")
            return
        
        self.current_module = module
        self.module_params = {}
        self.prompt = self._build_prompt()
        
        console.print(f"[green]✓ Loaded module: {module.name} v{module.version}[/green]")
        console.print(f"  Category: {module.category}")
        console.print(f"  Author: {module.author}")
        console.print("\n[cyan]Type 'show options' to see configuration[/cyan]")
        console.print("[cyan]Type 'info' for detailed information[/cyan]")
        console.print("[cyan]Type 'run' to execute[/cyan]")

    def do_info(self, args):
        """
        Display detailed module information
        Usage: info [module_name]
        """
        if args:
            module = self.loader.get_module(args.strip())
            if not module:
                console.print(f"[red]Module '{args}' not found[/red]")
                return
        elif self.current_module:
            module = self.current_module
        else:
            console.print("[yellow]No module selected. Usage: info <module_name>[/yellow]")
            return
        
        # Create info panel
        info_text = f"""
[bold cyan]Name:[/bold cyan] {module.name}
[bold cyan]Version:[/bold cyan] {module.version}
[bold cyan]Category:[/bold cyan] {module.category}
[bold cyan]Author:[/bold cyan] {module.author}
[bold cyan]Description:[/bold cyan] {module.description}
[bold cyan]Timeout:[/bold cyan] {module.timeout} seconds
[bold cyan]Concurrent:[/bold cyan] {module.concurrent}
"""
        
        if module.dependencies:
            info_text += f"[bold cyan]Dependencies:[/bold cyan] {', '.join(module.dependencies)}\n"
        
        panel = Panel(info_text, title=f"Module: {module.name}", border_style="cyan")
        console.print(panel)
        
        # Show inputs if available
        if module.inputs:
            self.current_module = module
            self._show_options()

    def do_search(self, args):
        """
        Search for modules
        Usage: search <query>
        """
        if not args:
            console.print("[yellow]Usage: search <query>[/yellow]")
            return
        
        results = self.loader.search_modules(args)
        
        if not results:
            console.print(f"[yellow]No modules found matching: {args}[/yellow]")
            return
        
        table = Table(title=f"Search Results: '{args}' ({len(results)} matches)", box=box.ROUNDED)
        table.add_column("Module", style="cyan")
        table.add_column("Category", style="green")
        table.add_column("Description", style="white")
        
        for module in results:
            table.add_row(module.name, module.category, module.description)
        
        console.print(table)

    def do_set(self, args):
        """
        Set a module parameter
        Usage: set <option> <value>
        """
        if not self.current_module:
            console.print("[yellow]No module loaded. Use 'use <module>' first[/yellow]")
            return
        
        parts = args.split(maxsplit=1)
        if len(parts) < 2:
            console.print("[yellow]Usage: set <option> <value>[/yellow]")
            return
        
        option, value = parts
        
        if option not in self.current_module.inputs:
            console.print(f"[red]Unknown option: {option}[/red]")
            return
        
        self.module_params[option] = value
        console.print(f"[green]{option} => {value}[/green]")

    def do_run(self, args):
        """
        Execute the currently loaded module
        Usage: run [target]
        """
        if not self.current_module:
            console.print("[yellow]No module loaded. Use 'use <module>' first[/yellow]")
            return
        
        # Get target
        target = args.strip() if args else None
        if not target:
            target = input(console.render_str("[yellow]Target: [/yellow]")).strip()
        
        if not target:
            console.print("[red]Target is required[/red]")
            return
        
        # Execute module
        result = self.executor.execute(self.current_module, target, self.module_params)
        
        # Display result
        self._display_result(result)

    def _display_result(self, result: ModuleResult):
        """Display module execution result"""
        status_color = "green" if result.success else "red"
        status_text = "SUCCESS" if result.success else "FAILED"
        
        result_text = f"""
[bold]Status:[/bold] [{status_color}]{status_text}[/{status_color}]
[bold]Execution Time:[/bold] {result.execution_time_ms}ms
[bold]Timestamp:[/bold] {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        if result.errors:
            result_text += "\n[bold red]Errors:[/bold red]\n"
            for error in result.errors:
                result_text += f"  • {error}\n"
        
        panel = Panel(result_text, title="Execution Result", border_style=status_color)
        console.print(panel)
        
        if result.data:
            console.print("\n[bold yellow]Data:[/bold yellow]")
            syntax = Syntax(json.dumps(result.data, indent=2), "json", theme="monokai")
            console.print(syntax)

    def do_back(self, args):
        """
        Unload the current module
        Usage: back
        """
        if self.current_module:
            console.print(f"[green]Unloaded module: {self.current_module.name}[/green]")
            self.current_module = None
            self.module_params = {}
            self.prompt = self._build_prompt()
        else:
            console.print("[yellow]No module loaded[/yellow]")

    def do_exit(self, args):
        """
        Exit SecV shell
        Usage: exit
        """
        console.print("[cyan]Goodbye![/cyan]")
        return True

    def do_clear(self, args):
        """Clear the screen"""
        console.clear()


def main():
    """Main entry point"""
    try:
        shell = SecVShell()
        shell.cmdloop()
    except KeyboardInterrupt:
        console.print("\n[cyan]Goodbye![/cyan]")
        sys.exit(0)


if __name__ == '__main__':
    main()
