cargo build --release
The resulting binary will be located at target/release/secv (or target/release/secv.exe on Windows).
cargo run -- --init
cargo run -- interactive
List Available Modules:
cargo run -- list
Execute a Single Module:
cargo run -- execute --module example-scanner --target example.com
Run a Workflow:
cargo run -- workflow --file workflows/example.json --target example.com
This executes a predefined workflow that chains multiple modules together.
Extending the Platform
One of the most powerful aspects of this platform is its extensibility. You can add new modules by creating directories in the appropriate category under tools/ and following the module structure. Each module needs:

A module.json file describing its capabilities and requirements
The actual implementation (could be a script, binary, or other executable)
Proper input validation and output formatting

The system uses a trait-based architecture in Rust, which means all modules follow the same interface contract. This ensures consistency and makes it easy to chain modules together in workflows.
Troubleshooting Common Issues
If you encounter build errors, they're typically related to missing dependencies. Make sure you have:

A recent version of Rust (1.70 or newer recommended)
All system dependencies for the crates being used
Proper permissions to create directories and execute commands

If modules aren't being discovered, check that their module.json files are properly formatted and that the directory structure matches what the module loader expects.
