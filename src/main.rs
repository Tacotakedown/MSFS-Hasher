use crypto_hash::{Algorithm, Hasher};
use serde::{Deserialize, Serialize};
use serde_json::to_string_pretty;
use std::{
    fs::{self, File},
    io::{self, Write},
    path::PathBuf,
};
use walkdir::WalkDir;

#[derive(Debug, Serialize, Deserialize)]
struct HashOutput {
    file_name: String,
    hash: String,
}
#[derive(Debug, Serialize, Deserialize)]
struct FileStructure {
    version: String,
    files: Vec<HashOutput>,
}

fn compare_maps(old_path: &str, new_path: &str) -> io::Result<()> {
    let old_file_content = fs::read_to_string(old_path)?;
    let new_file_content = fs::read_to_string(new_path)?;

    let old_structure: FileStructure = serde_json::from_str(&old_file_content)?;
    let new_structure: FileStructure = serde_json::from_str(&new_file_content)?;

    for old_entry in &old_structure.files {
        if let Some(new_hash) = new_structure
            .files
            .iter()
            .find(|new_entry| new_entry.file_name == old_entry.file_name)
        {
            if new_hash.hash != old_entry.hash {
                println!(
                    "Hash changed for file '{}':\n  Old Hash: {}\n  New Hash: {}",
                    new_hash.file_name, old_entry.hash, new_hash.hash
                );
            }
        } else {
            println!("File '{}' was removed", old_entry.file_name);
        }
    }

    for new_entry in &new_structure.files {
        if !old_structure
            .files
            .iter()
            .any(|old_entry| old_entry.file_name == new_entry.file_name)
        {
            println!("File '{}' was added", new_entry.file_name);
        }
    }

    Ok(())
}

fn hash_aircraft(path: &str, version: &str) -> io::Result<()> {
    let mut file_hashes = FileStructure {
        version: version.to_string(),
        files: Vec::new(),
    };

    let dir = PathBuf::from(path);

    for entry in WalkDir::new(&dir) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let file_name = entry
                .path()
                .strip_prefix(&dir)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let file_path = entry.path();

            let mut file = File::open(file_path)?;
            let mut hasher = Hasher::new(Algorithm::SHA256);
            io::copy(&mut file, &mut hasher)?;

            let hash = hasher.finish();
            let hash_string = hex::encode(hash);

            let file_hash = HashOutput {
                file_name,
                hash: hash_string,
            };

            file_hashes.files.push(file_hash);
        }
    }

    let map_json = to_string_pretty(&file_hashes)?;
    let mut file = File::create("map.json")?;
    file.write_all(map_json.as_bytes())?;

    Ok(())
}

fn main() {
    let mut input = String::new();

    println!("Paste Directory Path:");
    io::stdin()
        .read_line(&mut input)
        .expect("failed to read input");
    let directory_path = input.clone();
    let directory_path = directory_path.trim();

    input.clear();

    println!("enter version:");
    io::stdin()
        .read_line(&mut input)
        .expect("failed to read line");
    let version = input.trim();
    hash_aircraft(directory_path, version).expect("failed to hash");
}
