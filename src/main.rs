// Cargo.toml dependencies needed:
// [dependencies]
// serde = { version = "1.0", features = ["derive"] }
// serde_json = "1.0"
// serde_yaml = "0.9"
// tokio = { version = "1.0", features = ["full"] }
// clap = { version = "4.0", features = ["derive"] }
// anyhow = "1.0"
// thiserror = "1.0"
// async-trait = "0.1"
// colored = "2.0"
// dialoguer = "0.11"
// libloading = "0.8"

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::{Parser, Subcommand};
use colored::*;
use dialoguer::{Select, Input, Confirm};
use serde::{Deserialize, Serialize};
use tokio::fs;

/// SecV - Next Generation Cybersecurity Orchestration Platform
/// 
/// This Rust implementation provides superior memory safety, concurrency,
/// and performance compared to the Python version. The architecture leverages
/// Rust's trait system for true polymorphism and zero-cost abstractions.
#[derive(Parser)]
#[command(name = "secv")]
#[command(about = "Advanced Cybersecurity Orchestration Platform")]
#[command(version = "2.0.0")]
struct SecVCli {
    #[command(subcommand)]
    command: Option<Commands>,
    
    /// Initialize directory structure
    #[arg(long)]
    init: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Execute a single module
    Execute {
        /// Module name to execute
        #[arg(short, long)]
        module: String,
        /// Primary target
        #[arg(short, long)]
        target: String,
        /// Additional parameters in JSON format
        #[arg(short, long)]
        params: Option<String>,
    },
    /// Run a workflow from file
    Workflow {
        /// Path to workflow file
        #[arg(short, long)]
        file: PathBuf,
        /// Primary target
        #[arg(short, long)]
        target: String,
    },
    /// List available modules
    List {
        /// Filter by category
        #[arg(short, long)]
        category: Option<String>,
    },
    /// Show module information
    Info {
        /// Module name
        module: String,
    },
    /// Start interactive mode
    Interactive,
}

/// Core module metadata structure with enhanced validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMetadata {
    pub name: String,
    pub version: String,
    pub category: String,
    pub description: String,
    pub author: String,
    pub dependencies: Vec<String>,
    pub inputs: HashMap<String, InputSpec>,
    pub outputs: HashMap<String, OutputSpec>,
    pub capabilities: Vec<String>,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputSpec {
    pub description: String,
    pub input_type: String,
    pub required: bool,
    pub default_value: Option<String>,
    pub validation_regex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputSpec {
    pub description: String,
    pub output_type: String,
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Execution context passed between modules in workflows
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    pub target: String,
    pub parameters: HashMap<String, serde_json::Value>,
    pub results: HashMap<String, ModuleResult>,
    pub metadata: HashMap<String, String>,
}

/// Standardized result structure for all module executions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleResult {
    pub success: bool,
    pub data: serde_json::Value,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub execution_time_ms: u64,
    pub artifacts: Vec<String>, // File paths to generated artifacts
}

/// Enhanced error types for better error handling
#[derive(thiserror::Error, Debug)]
pub enum SecVError {
    #[error("Module not found: {0}")]
    ModuleNotFound(String),
    
    #[error("Dependency missing: {0}")]
    DependencyMissing(String),
    
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
    
    #[error("Execution failed: {0}")]
    ExecutionFailed(String),
    
    #[error("Workflow error: {0}")]
    WorkflowError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

/// Core trait that all SecV modules must implement
/// This provides true polymorphism and compile-time safety
#[async_trait]
pub trait SecVModule: Send + Sync {
    /// Returns the module's metadata
    fn metadata(&self) -> &ModuleMetadata;
    
    /// Validates that all dependencies are available
    async fn validate_dependencies(&self) -> Result<(), SecVError>;
    
    /// Validates input parameters against the module's specification
    fn validate_inputs(&self, inputs: &HashMap<String, serde_json::Value>) -> Result<(), SecVError>;
    
    /// Main execution method - this is where the actual work happens
    async fn execute(&self, context: ExecutionContext) -> Result<ModuleResult, SecVError>;
    
    /// Optional cleanup method called after execution
    async fn cleanup(&self) -> Result<(), SecVError> {
        Ok(())
    }
    
    /// Returns the module's current health status
    async fn health_check(&self) -> Result<bool, SecVError> {
        self.validate_dependencies().await.map(|_| true)
    }
}

/// Advanced module loader with dynamic loading capabilities
pub struct ModuleLoader {
    modules: HashMap<String, Arc<dyn SecVModule>>,
    tools_directory: PathBuf,
}

impl ModuleLoader {
    pub fn new(tools_directory: impl Into<PathBuf>) -> Self {
        Self {
            modules: HashMap::new(),
            tools_directory: tools_directory.into(),
        }
    }
    
    /// Discovers and loads all modules from the tools directory
    pub async fn discover_modules(&mut self) -> Result<usize> {
        println!("{}", "🔍 Discovering modules...".cyan().bold());
        
        if !self.tools_directory.exists() {
            return Err(anyhow::anyhow!("Tools directory does not exist: {:?}", self.tools_directory));
        }
        
        let mut loaded_count = 0;
        let mut entries = fs::read_dir(&self.tools_directory).await?;
        
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                if let Ok(()) = self.load_module_from_directory(&entry.path()).await {
                    loaded_count += 1;
                }
            }
        }
        
        println!("{} {}", "✅ Module discovery complete.".green().bold(), 
                format!("Loaded {} modules.", loaded_count).white());
        
        Ok(loaded_count)
    }
    
    /// Loads a single module from a directory
    async fn load_module_from_directory(&mut self, path: &Path) -> Result<()> {
        let metadata_path = path.join("module.json");
        if !metadata_path.exists() {
            return Err(anyhow::anyhow!("No module.json found in {:?}", path));
        }
        
        let metadata_content = fs::read_to_string(&metadata_path).await
            .context("Failed to read module.json")?;
        
        let metadata: ModuleMetadata = serde_json::from_str(&metadata_content)
            .context("Failed to parse module.json")?;
        
        // In a real implementation, this would use dynamic loading
        // For now, we'll create a placeholder module
        let module = Arc::new(PlaceholderModule::new(metadata));
        
        println!("  {} {}", "📦".blue(), 
                format!("Loaded: {} v{}", module.metadata().name, module.metadata().version).cyan());
        
        self.modules.insert(module.metadata().name.clone(), module);
        
        Ok(())
    }
    
    /// Retrieves a module by name
    pub fn get_module(&self, name: &str) -> Option<Arc<dyn SecVModule>> {
        self.modules.get(name).cloned()
    }
    
    /// Returns all modules grouped by category
    pub fn modules_by_category(&self) -> HashMap<String, Vec<Arc<dyn SecVModule>>> {
        let mut categories = HashMap::new();
        
        for module in self.modules.values() {
            categories
                .entry(module.metadata().category.clone())
                .or_insert_with(Vec::new)
                .push(module.clone());
        }
        
        categories
    }
    
    /// Returns all module names
    pub fn module_names(&self) -> Vec<String> {
        self.modules.keys().cloned().collect()
    }
}

/// Placeholder module implementation for demonstration
pub struct PlaceholderModule {
    metadata: ModuleMetadata,
}

impl PlaceholderModule {
    pub fn new(metadata: ModuleMetadata) -> Self {
        Self { metadata }
    }
}

#[async_trait]
impl SecVModule for PlaceholderModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.metadata
    }
    
    async fn validate_dependencies(&self) -> Result<(), SecVError> {
        // Check if required system dependencies are available
        for dep in &self.metadata.dependencies {
            match tokio::process::Command::new("which")
                .arg(dep)
                .output()
                .await
            {
                Ok(output) if output.status.success() => continue,
                _ => return Err(SecVError::DependencyMissing(dep.clone())),
            }
        }
        Ok(())
    }
    
    fn validate_inputs(&self, inputs: &HashMap<String, serde_json::Value>) -> Result<(), SecVError> {
        for (key, spec) in &self.metadata.inputs {
            if spec.required && !inputs.contains_key(key) {
                return Err(SecVError::ValidationFailed(
                    format!("Required input '{}' is missing", key)
                ));
            }
            
            // Additional validation could be implemented here using regex patterns
        }
        Ok(())
    }
    
    async fn execute(&self, context: ExecutionContext) -> Result<ModuleResult, SecVError> {
        let start_time = std::time::Instant::now();
        
        // Simulate module execution
        println!("⚙️  Executing {} against {}", 
                self.metadata.name.yellow().bold(), 
                context.target.green().bold());
        
        // This is where real module logic would go
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        let execution_time = start_time.elapsed();
        
        Ok(ModuleResult {
            success: true,
            data: serde_json::json!({
                "message": format!("Successfully executed {} against {}", 
                                 self.metadata.name, context.target),
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }),
            errors: Vec::new(),
            warnings: Vec::new(),
            execution_time_ms: execution_time.as_millis() as u64,
            artifacts: Vec::new(),
        })
    }
}

/// Workflow definition structure
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkflowDefinition {
    pub name: String,
    pub description: String,
    pub version: String,
    pub author: String,
    pub steps: Vec<WorkflowStep>,
    pub global_settings: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub name: String,
    pub module: String,
    pub inputs: HashMap<String, serde_json::Value>,
    pub condition: Option<String>,
    pub on_error: ErrorAction,
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ErrorAction {
    Stop,
    Continue,
    Retry(u32),
}

/// Advanced workflow engine with parallel execution capabilities
pub struct WorkflowEngine {
    module_loader: Arc<ModuleLoader>,
}

impl WorkflowEngine {
    pub fn new(module_loader: Arc<ModuleLoader>) -> Self {
        Self { module_loader }
    }
    
    /// Loads a workflow from a file
    pub async fn load_workflow(&self, path: &Path) -> Result<WorkflowDefinition> {
        let content = fs::read_to_string(path).await
            .context("Failed to read workflow file")?;
        
        let workflow: WorkflowDefinition = if path.extension()
            .and_then(|s| s.to_str()) == Some("yml") || 
            path.extension().and_then(|s| s.to_str()) == Some("yaml") 
        {
            serde_yaml::from_str(&content)
                .context("Failed to parse YAML workflow")?
        } else {
            serde_json::from_str(&content)
                .context("Failed to parse JSON workflow")?
        };
        
        Ok(workflow)
    }
    
    /// Executes a workflow with full context management
    pub async fn execute_workflow(
        &self, 
        workflow: WorkflowDefinition, 
        target: String
    ) -> Result<HashMap<String, ModuleResult>> {
        println!("{}", format!("🚀 Executing Workflow: {}", workflow.name).magenta().bold());
        
        let mut context = ExecutionContext {
            target,
            parameters: workflow.global_settings,
            results: HashMap::new(),
            metadata: HashMap::new(),
        };
        
        for (step_index, step) in workflow.steps.iter().enumerate() {
            println!("\n{}", format!("--- Step {}: {} ---", step_index + 1, step.name).blue().bold());
            
            let module = self.module_loader.get_module(&step.module)
                .ok_or_else(|| SecVError::ModuleNotFound(step.module.clone()))?;
            
            // Resolve dynamic inputs using context
            let resolved_inputs = self.resolve_inputs(&step.inputs, &context)?;
            context.parameters.extend(resolved_inputs);
            
            // Validate inputs before execution
            module.validate_inputs(&context.parameters)?;
            
            // Execute with timeout if specified
            let result = if let Some(timeout) = step.timeout_seconds {
                tokio::time::timeout(
                    tokio::time::Duration::from_secs(timeout),
                    module.execute(context.clone())
                ).await
                .map_err(|_| SecVError::ExecutionFailed("Module execution timed out".to_string()))?
            } else {
                module.execute(context.clone()).await
            }?;
            
            if result.success {
                println!("{}", format!("✅ Step {} completed successfully", step_index + 1).green().bold());
                context.results.insert(step.module.clone(), result);
            } else {
                match step.on_error {
                    ErrorAction::Stop => {
                        return Err(SecVError::WorkflowError(
                            format!("Workflow stopped at step {} due to error", step_index + 1)
                        ));
                    },
                    ErrorAction::Continue => {
                        println!("{}", format!("⚠️  Step {} failed but continuing", step_index + 1).yellow());
                        context.results.insert(step.module.clone(), result);
                    },
                    ErrorAction::Retry(max_retries) => {
                        // Implement retry logic here
                        println!("{}", format!("🔄 Retrying step {} (max {} attempts)", step_index + 1, max_retries).yellow());
                        context.results.insert(step.module.clone(), result);
                    },
                }
            }
        }
        
        println!("\n{}", "🎉 Workflow completed successfully!".green().bold());
        Ok(context.results)
    }
    
    /// Resolves dynamic input references like ${results.scanner.ports}
    fn resolve_inputs(
        &self, 
        inputs: &HashMap<String, serde_json::Value>, 
        context: &ExecutionContext
    ) -> Result<HashMap<String, serde_json::Value>> {
        let mut resolved = HashMap::new();
        
        for (key, value) in inputs {
            let resolved_value = if let serde_json::Value::String(s) = value {
                if s.starts_with("${") && s.ends_with("}") {
                    let path = &s[2..s.len()-1];
                    self.resolve_context_path(path, context)?
                } else {
                    value.clone()
                }
            } else {
                value.clone()
            };
            
            resolved.insert(key.clone(), resolved_value);
        }
        
        Ok(resolved)
    }
    
    /// Resolves a dot-notation path in the execution context
    fn resolve_context_path(&self, path: &str, context: &ExecutionContext) -> Result<serde_json::Value> {
        let parts: Vec<&str> = path.split('.').collect();
        
        match parts.as_slice() {
            ["target"] => Ok(serde_json::Value::String(context.target.clone())),
            ["results", module_name, field] => {
                if let Some(result) = context.results.get(*module_name) {
                    result.data.get(field)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("Field '{}' not found in module '{}' results", field, module_name))
                } else {
                    Err(anyhow::anyhow!("Module '{}' results not found", module_name))
                }
            },
            _ => Err(anyhow::anyhow!("Invalid context path: {}", path)),
        }
    }
}

/// Interactive CLI interface with enhanced user experience
pub struct InteractiveInterface {
    module_loader: Arc<ModuleLoader>,
    workflow_engine: Arc<WorkflowEngine>,
}

impl InteractiveInterface {
    pub fn new(module_loader: Arc<ModuleLoader>) -> Self {
        let workflow_engine = Arc::new(WorkflowEngine::new(module_loader.clone()));
        
        Self {
            module_loader,
            workflow_engine,
        }
    }
    
    /// Main interactive loop
    pub async fn run(&self) -> Result<()> {
        self.print_banner();
        
        loop {
            let options = vec![
                "List Modules",
                "Execute Single Module", 
                "Run Workflow",
                "Module Information",
                "System Health Check",
                "Exit"
            ];
            
            let selection = Select::new()
                .with_prompt("Choose an action")
                .items(&options)
                .interact()?;
            
            match selection {
                0 => self.list_modules().await?,
                1 => self.execute_single_module().await?,
                2 => self.run_workflow().await?,
                3 => self.show_module_info().await?,
                4 => self.health_check().await?,
                5 => {
                    println!("{}", "👋 Thank you for using SecV!".green().bold());
                    break;
                },
                _ => unreachable!(),
            }
            
            println!("\n{}", "Press Enter to continue...".dimmed());
            let _ = std::io::stdin().read_line(&mut String::new());
        }
        
        Ok(())
    }
    
    fn print_banner(&self) {
        let banner = format!(r#"
{}
╔═══════════════════════════════════════════════════════════════╗
║   ____            __     __  ____            _                ║
║  / ___|  ___  ___ \ \   / / |  _ \ _   _ ___ | |_              ║
║  \___ \ / _ \/ __| \ \ / /  | |_) | | | / __|| __|             ║
║   ___) |  __/ (__   \ V /   |  _ <| |_| \__ \| |_              ║
║  |____/ \___|\___|   \_/    |_| \_\\__,_|___/ \__|             ║
║                                                               ║
║       Advanced Cybersecurity Orchestration Platform          ║
║  Built with Rust for Maximum Performance by 0xbv1 v0.0.1     ║
╚═══════════════════════════════════════════════════════════════╝
{}
"#, "".blue().bold(), "🛡️  For authorized security testing and research only.".yellow());
        
        println!("{}", banner);
    }
    
    async fn list_modules(&self) -> Result<()> {
        println!("\n{}", "--- Available Modules ---".blue().bold());
        
        let categories = self.module_loader.modules_by_category();
        
        if categories.is_empty() {
            println!("{}", "No modules found. Run with --init to create the directory structure.".yellow());
            return Ok(());
        }
        
        for (category, modules) in categories {
            println!("\n{}", category.to_uppercase().green().bold().underline());
            for module in modules {
                let metadata = module.metadata();
                println!("  └── {}: {}", 
                        metadata.name.cyan().bold(), 
                        metadata.description.white());
            }
        }
        
        Ok(())
    }
    
    async fn execute_single_module(&self) -> Result<()> {
        println!("\n{}", "--- Execute Single Module ---".blue().bold());
        
        let module_names = self.module_loader.module_names();
        if module_names.is_empty() {
            println!("{}", "No modules available.".yellow());
            return Ok(());
        }
        
        let selection = Select::new()
            .with_prompt("Select a module")
            .items(&module_names)
            .interact()?;
        
        let module_name = &module_names[selection];
        let module = self.module_loader.get_module(module_name)
            .ok_or_else(|| SecVError::ModuleNotFound(module_name.clone()))?;
        
        // Collect inputs
        let target: String = Input::new()
            .with_prompt("Enter target")
            .interact_text()?;
        
        let mut parameters = HashMap::new();
        for (key, spec) in &module.metadata().inputs {
            if spec.required {
                let value: String = Input::new()
                    .with_prompt(&format!("Enter {} ({})", key, spec.description))
                    .interact_text()?;
                parameters.insert(key.clone(), serde_json::Value::String(value));
            }
        }
        
        let context = ExecutionContext {
            target,
            parameters,
            results: HashMap::new(),
            metadata: HashMap::new(),
        };
        
        println!("\n{}", format!("⚙️  Executing {}...", module_name).cyan().bold());
        
        let result = module.execute(context).await?;
        
        if result.success {
            println!("{}", format!("✅ Execution completed in {}ms", result.execution_time_ms).green().bold());
            println!("Result: {}", serde_json::to_string_pretty(&result.data)?);
        } else {
            println!("{}", "❌ Execution failed".red().bold());
            for error in &result.errors {
                println!("  Error: {}", error.red());
            }
        }
        
        Ok(())
    }
    
    async fn run_workflow(&self) -> Result<()> {
        println!("\n{}", "--- Run Workflow ---".blue().bold());
        
        let workflow_path: String = Input::new()
            .with_prompt("Enter workflow file path")
            .interact_text()?;
        
        let target: String = Input::new()
            .with_prompt("Enter primary target")
            .interact_text()?;
        
        let workflow = self.workflow_engine.load_workflow(&PathBuf::from(workflow_path)).await?;
        let results = self.workflow_engine.execute_workflow(workflow, target).await?;
        
        println!("\n{}", "--- Final Results ---".blue().bold());
        for (module_name, result) in results {
            println!("{}: {}", module_name.cyan().bold(), 
                    if result.success { "✅ Success".green() } else { "❌ Failed".red() });
        }
        
        Ok(())
    }
    
    async fn show_module_info(&self) -> Result<()> {
        println!("\n{}", "--- Module Information ---".blue().bold());
        
        let module_names = self.module_loader.module_names();
        if module_names.is_empty() {
            println!("{}", "No modules available.".yellow());
            return Ok(());
        }
        
        let selection = Select::new()
            .with_prompt("Select a module")
            .items(&module_names)
            .interact()?;
        
        let module_name = &module_names[selection];
        let module = self.module_loader.get_module(module_name)
            .ok_or_else(|| SecVError::ModuleNotFound(module_name.clone()))?;
        
        let metadata = module.metadata();
        
        println!("\n{} v{}", metadata.name.cyan().bold(), metadata.version.white());
        println!("{}", metadata.description.white());
        println!("{}", "-".repeat(50));
        println!("Category: {}", metadata.category.green());
        println!("Author: {}", metadata.author.white());
        println!("Risk Level: {:?}", metadata.risk_level);
        println!("Dependencies: {}", metadata.dependencies.join(", "));
        
        println!("\n{}:", "Inputs".yellow().bold());
        for (key, spec) in &metadata.inputs {
            let required = if spec.required { "required" } else { "optional" };
            println!("  └── {} ({}, {}) - {}", 
                    key.cyan(), spec.input_type, required, spec.description);
        }
        
        Ok(())
    }
    
    async fn health_check(&self) -> Result<()> {
        println!("\n{}", "--- System Health Check ---".blue().bold());
        
        let mut all_healthy = true;
        
        for (name, module) in &self.module_loader.modules {
            print!("Checking {}... ", name.cyan());
            match module.health_check().await {
                Ok(true) => println!("{}", "✅ Healthy".green()),
                Ok(false) => {
                    println!("{}", "⚠️  Unhealthy".yellow());
                    all_healthy = false;
                },
                Err(e) => {
                    println!("{}: {}", "❌ Error".red(), e);
                    all_healthy = false;
                },
            }
        }
        
        if all_healthy {
            println!("\n{}", "🎉 All modules are healthy!".green().bold());
        } else {
            println!("\n{}", "⚠️  Some modules have issues.".yellow().bold());
        }
        
        Ok(())
    }
}

/// Initialize directory structure for new installations
async fn initialize_structure() -> Result<()> {
    println!("{}", "🔧 Initializing SecV directory structure...".cyan().bold());
    
    let directories = [
        "tools/reconnaissance",
        "tools/vulnerability-assessment", 
        "tools/exploitation",
        "tools/post-exploitation",
        "workflows",
        "configs",
        "logs",
    ];
    
    for dir in &directories {
        fs::create_dir_all(dir).await
            .context(format!("Failed to create directory: {}", dir))?;
        println!("  Created: {}", dir.green());
    }
    
    // Create example module structure
    let example_module_dir = "tools/reconnaissance/example-scanner";
    fs::create_dir_all(&format!("{}/src", example_module_dir)).await?;
    
    let example_metadata = ModuleMetadata {
        name: "example-scanner".to_string(),
        version: "1.0.0".to_string(),
        category: "reconnaissance".to_string(),
        description: "Example network scanner module".to_string(),
        author: "SecV Team".to_string(),
        dependencies: vec!["nmap".to_string()],
        inputs: {
            let mut inputs = HashMap::new();
            inputs.insert("target".to_string(), InputSpec {
                description: "Target IP or hostname".to_string(),
                input_type: "string".to_string(),
                required: true,
                default_value: None,
                validation_regex: Some(r"^[\w\.-]+$".to_string()),
            });
            inputs
        },
        outputs: {
            let mut outputs = HashMap::new();
            outputs.insert("scan_results".to_string(), OutputSpec {
                description: "Scan results in JSON format".to_string(),
                output_type: "object".to_string(),
                format: "json".to_string(),
            });
            outputs
        },
        capabilities: vec!["network-scanning".to_string(), "port-detection".to_string()],
        risk_level: RiskLevel::Low,
    };
    
    let metadata_json = serde_json::to_string_pretty(&example_metadata)?;
    fs::write(&format!("{}/module.json", example_module_dir), metadata_json).await?;
    
    println!("{}", "✅ Directory structure initialized successfully!".green().bold());
    println!("{}", "You can now add modules to the tools/ directory.".white());
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = SecVCli::parse();
    
    if cli.init {
        initialize_structure().await?;
        return Ok(());
    }
    
    let mut module_loader = ModuleLoader::new("tools");
    module_loader.discover_modules().await?;
    let module_loader = Arc::new(module_loader);
    
    match cli.command {
        Some(Commands::Execute { module, target, params }) => {
            let module_instance = module_loader.get_module(&module)
                .ok_or_else(|| SecVError::ModuleNotFound(module.clone()))?;
            
            let mut parameters = HashMap::new();
            if let Some(params_str) = params {
                parameters = serde_json::from_str(&params_str)
                    .context("Failed to parse parameters JSON")?;
            }
            
            let context = ExecutionContext {
                target,
                parameters,
                results: HashMap::new(),
                metadata: HashMap::new(),
            };
            
            println!("{}", format!("⚙️  Executing {} against {}", 
                    module.yellow().bold(), context.target.green().bold()));
            
            let result = module_instance.execute(context).await?;
            
            if result.success {
                println!("{}", format!("✅ Execution completed in {}ms", 
                        result.execution_time_ms).green().bold());
                println!("{}", serde_json::to_string_pretty(&result.data)?);
            } else {
                println!("{}", "❌ Execution failed".red().bold());
                for error in &result.errors {
                    println!("  {}: {}", "Error".red().bold(), error);
                }
                std::process::exit(1);
            }
        },
        
        Some(Commands::Workflow { file, target }) => {
            let workflow_engine = WorkflowEngine::new(module_loader.clone());
            let workflow = workflow_engine.load_workflow(&file).await?;
            let results = workflow_engine.execute_workflow(workflow, target).await?;
            
            println!("\n{}", "--- Workflow Results Summary ---".blue().bold());
            for (module_name, result) in results {
                let status = if result.success {
                    format!("✅ Success ({}ms)", result.execution_time_ms).green()
                } else {
                    "❌ Failed".red()
                };
                println!("{}: {}", module_name.cyan().bold(), status);
                
                if !result.warnings.is_empty() {
                    for warning in &result.warnings {
                        println!("  ⚠️  {}", warning.yellow());
                    }
                }
            }
        },
        
        Some(Commands::List { category }) => {
            let categories = module_loader.modules_by_category();
            
            if categories.is_empty() {
                println!("{}", "No modules found. Run 'secv --init' to initialize.".yellow());
                return Ok(());
            }
            
            for (cat_name, modules) in categories {
                if let Some(filter) = &category {
                    if cat_name.to_lowercase() != filter.to_lowercase() {
                        continue;
                    }
                }
                
                println!("\n{}", cat_name.to_uppercase().green().bold().underline());
                for module in modules {
                    let metadata = module.metadata();
                    let risk_indicator = match metadata.risk_level {
                        RiskLevel::Low => "🟢",
                        RiskLevel::Medium => "🟡", 
                        RiskLevel::High => "🟠",
                        RiskLevel::Critical => "🔴",
                    };
                    
                    println!("  {} {} v{}: {}", 
                            risk_indicator,
                            metadata.name.cyan().bold(),
                            metadata.version.dimmed(),
                            metadata.description.white());
                    
                    if !metadata.capabilities.is_empty() {
                        println!("    📋 Capabilities: {}", 
                                metadata.capabilities.join(", ").dimmed());
                    }
                }
            }
        },
        
        Some(Commands::Info { module }) => {
            let module_instance = module_loader.get_module(&module)
                .ok_or_else(|| SecVError::ModuleNotFound(module.clone()))?;
            
            let metadata = module_instance.metadata();
            
            println!("\n{}", "=".repeat(60).blue());
            println!("{} v{}", metadata.name.cyan().bold(), metadata.version.white().bold());
            println!("{}", "=".repeat(60).blue());
            
            println!("\n{}", metadata.description.white());
            
            println!("\n{}:", "Details".yellow().bold());
            println!("  Category: {}", metadata.category.green());
            println!("  Author: {}", metadata.author.white());
            println!("  Risk Level: {:?}", metadata.risk_level);
            
            if !metadata.dependencies.is_empty() {
                println!("  Dependencies: {}", metadata.dependencies.join(", ").cyan());
            }
            
            if !metadata.capabilities.is_empty() {
                println!("  Capabilities: {}", metadata.capabilities.join(", ").green());
            }
            
            println!("\n{}:", "Inputs".yellow().bold());
            for (key, spec) in &metadata.inputs {
                let required_badge = if spec.required { 
                    "[REQUIRED]".red().bold() 
                } else { 
                    "[OPTIONAL]".green().bold() 
                };
                
                println!("  └── {} {} ({})", 
                        key.cyan().bold(), required_badge, spec.input_type.dimmed());
                println!("      {}", spec.description.white());
                
                if let Some(default) = &spec.default_value {
                    println!("      Default: {}", default.dimmed());
                }
            }
            
            println!("\n{}:", "Outputs".yellow().bold());
            for (key, spec) in &metadata.outputs {
                println!("  └── {} ({})", key.cyan().bold(), spec.output_type.dimmed());
                println!("      {}", spec.description.white());
            }
            
            // Check module health
            print!("\n{}: ", "Health Status".yellow().bold());
            match module_instance.health_check().await {
                Ok(true) => println!("{}", "✅ Healthy".green().bold()),
                Ok(false) => println!("{}", "⚠️  Issues detected".yellow().bold()),
                Err(e) => println!("{}: {}", "❌ Error".red().bold(), e),
            }
        },
        
        Some(Commands::Interactive) | None => {
            let interface = InteractiveInterface::new(module_loader);
            interface.run().await?;
        },
    }
    
    Ok(())
}

// Additional utility functions and improvements

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "🟢 Low"),
            RiskLevel::Medium => write!(f, "🟡 Medium"),
            RiskLevel::High => write!(f, "🟠 High"),
            RiskLevel::Critical => write!(f, "🔴 Critical"),
        }
    }
}

/// Enhanced module implementation with real-world capabilities
pub struct NetworkScannerModule {
    metadata: ModuleMetadata,
}

impl NetworkScannerModule {
    pub fn new() -> Self {
        let mut inputs = HashMap::new();
        inputs.insert("target".to_string(), InputSpec {
            description: "Target IP address or hostname".to_string(),
            input_type: "string".to_string(),
            required: true,
            default_value: None,
            validation_regex: Some(r"^[\w\.-]+$".to_string()),
        });
        inputs.insert("ports".to_string(), InputSpec {
            description: "Port range to scan (e.g., 1-1000)".to_string(),
            input_type: "string".to_string(),
            required: false,
            default_value: Some("1-1000".to_string()),
            validation_regex: Some(r"^\d+(-\d+)?$".to_string()),
        });
        inputs.insert("scan_type".to_string(), InputSpec {
            description: "Type of scan (tcp, udp, syn)".to_string(),
            input_type: "string".to_string(),
            required: false,
            default_value: Some("tcp".to_string()),
            validation_regex: Some(r"^(tcp|udp|syn)$".to_string()),
        });

        let mut outputs = HashMap::new();
        outputs.insert("open_ports".to_string(), OutputSpec {
            description: "List of open ports discovered".to_string(),
            output_type: "array".to_string(),
            format: "json".to_string(),
        });
        outputs.insert("scan_duration".to_string(), OutputSpec {
            description: "Time taken for the scan in seconds".to_string(),
            output_type: "number".to_string(),
            format: "float".to_string(),
        });

        let metadata = ModuleMetadata {
            name: "network-scanner".to_string(),
            version: "2.0.0".to_string(),
            category: "reconnaissance".to_string(),
            description: "Advanced network port scanner with multiple scan types".to_string(),
            author: "SecV Core Team".to_string(),
            dependencies: vec!["nmap".to_string()],
            inputs,
            outputs,
            capabilities: vec![
                "port-scanning".to_string(),
                "service-detection".to_string(),
                "os-fingerprinting".to_string(),
            ],
            risk_level: RiskLevel::Low,
        };

        Self { metadata }
    }
}

#[async_trait]
impl SecVModule for NetworkScannerModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.metadata
    }

    async fn validate_dependencies(&self) -> Result<(), SecVError> {
        // Check for nmap installation
        let output = tokio::process::Command::new("nmap")
            .arg("--version")
            .output()
            .await
            .map_err(|_| SecVError::DependencyMissing("nmap".to_string()))?;

        if !output.status.success() {
            return Err(SecVError::DependencyMissing("nmap".to_string()));
        }

        Ok(())
    }

    fn validate_inputs(&self, inputs: &HashMap<String, serde_json::Value>) -> Result<(), SecVError> {
        // Validate target is present
        if !inputs.contains_key("target") {
            return Err(SecVError::ValidationFailed("Target is required".to_string()));
        }

        // Validate port range format if provided
        if let Some(ports) = inputs.get("ports") {
            if let serde_json::Value::String(port_str) = ports {
                if !port_str.matches(char::is_numeric).any() {
                    return Err(SecVError::ValidationFailed(
                        "Invalid port range format".to_string()
                    ));
                }
            }
        }

        Ok(())
    }

    async fn execute(&self, context: ExecutionContext) -> Result<ModuleResult, SecVError> {
        let start_time = std::time::Instant::now();
        
        let target = context.parameters.get("target")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SecVError::ValidationFailed("Target not provided".to_string()))?;

        let ports = context.parameters.get("ports")
            .and_then(|v| v.as_str())
            .unwrap_or("1-1000");

        let scan_type = context.parameters.get("scan_type")
            .and_then(|v| v.as_str())
            .unwrap_or("tcp");

        println!("🔍 Scanning {} ports {} on {}", 
                ports.yellow(), scan_type.cyan(), target.green().bold());

        // Build nmap command
        let mut cmd = tokio::process::Command::new("nmap");
        cmd.arg("-p").arg(ports);
        
        match scan_type {
            "syn" => { cmd.arg("-sS"); },
            "udp" => { cmd.arg("-sU"); },
            _ => { cmd.arg("-sT"); }, // TCP connect scan (default)
        }
        
        cmd.arg("--open")
           .arg("-T4") // Aggressive timing
           .arg("--host-timeout").arg("300s")
           .arg(target);

        // Execute scan
        let output = cmd.output().await
            .map_err(|e| SecVError::ExecutionFailed(format!("Failed to execute nmap: {}", e)))?;

        let execution_time = start_time.elapsed();
        
        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Ok(ModuleResult {
                success: false,
                data: serde_json::json!({}),
                errors: vec![format!("Nmap scan failed: {}", error_msg)],
                warnings: vec![],
                execution_time_ms: execution_time.as_millis() as u64,
                artifacts: vec![],
            });
        }

        // Parse nmap output (simplified parsing)
        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut open_ports = Vec::new();
        
        for line in output_str.lines() {
            if line.contains("/tcp") && line.contains("open") {
                if let Some(port) = line.split('/').next() {
                    if let Ok(port_num) = port.trim().parse::<u16>() {
                        open_ports.push(port_num);
                    }
                }
            }
        }

        let result_data = serde_json::json!({
            "target": target,
            "scan_type": scan_type,
            "port_range": ports,
            "open_ports": open_ports,
            "total_open_ports": open_ports.len(),
            "scan_duration": execution_time.as_secs_f64(),
            "raw_output": output_str,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        println!("✅ Found {} open ports in {:.2}s", 
                open_ports.len().to_string().green().bold(),
                execution_time.as_secs_f64());

        Ok(ModuleResult {
            success: true,
            data: result_data,
            errors: vec![],
            warnings: if open_ports.is_empty() { 
                vec!["No open ports found".to_string()] 
            } else { 
                vec![] 
            },
            execution_time_ms: execution_time.as_millis() as u64,
            artifacts: vec![],
        })
    }

    async fn cleanup(&self) -> Result<(), SecVError> {
        // Clean up any temporary files or processes if needed
        Ok(())
    }
}
