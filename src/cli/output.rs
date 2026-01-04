//! Output formatting and file I/O utilities for CLI.

use std::fs;
use std::path::Path;

/// Write JSON data to a file with pretty formatting
pub fn write_json<T: serde::Serialize>(
    path: &Path,
    data: &T,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(data)?;
    fs::write(path, json)?;
    Ok(())
}

/// Read and deserialize JSON from a file
pub fn read_json<T: serde::de::DeserializeOwned>(
    path: &Path,
) -> Result<T, Box<dyn std::error::Error>> {
    let json = fs::read_to_string(path)?;
    let data = serde_json::from_str(&json)?;
    Ok(data)
}

/// Print JSON to stdout with pretty formatting, or write to file if path provided
pub fn output_json<T: serde::Serialize>(
    data: &T,
    path: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(data)?;
    if let Some(output_path) = path {
        fs::write(output_path, json)?;
        println!("✓ Output written to {}", output_path.display());
    } else {
        println!("{}", json);
    }
    Ok(())
}
