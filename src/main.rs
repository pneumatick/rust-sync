use std::io::Result;
use std::env;
use std::fs::File;

use common::checksum;

fn validate_paths(src_str: &str, dest_str: &str) -> Result<()> {
    File::open(src_str)?;
    File::open(dest_str)?;

    Ok(())
}

fn main() {
    // Get the src and dest file paths and convert them into strings
    let src_path = env::args_os()
        .nth(1)
        .expect("Error: Missing arguments!")
        .into_string()
        .expect("Invalid UTF-8 in SRC file path!");
    
    let dest_path = env::args_os()
        .nth(2)
        .expect("Error: Missing DEST path argument")
        .into_string()
        .expect("Invalid UTF-8 in DEST file path!");

    // Check that both paths are valid and accessible
    match validate_paths(&src_path, &dest_path) {
        Ok(()) => {
            println!("SRC: {src_path}\nDEST: {dest_path}");
        },
        Err(e) => {
            eprintln!("{:?}", e);
            return
        }
    }

    // Get the list of signatures from dest
    let signatures = match checksum::gen_beta_checksums(&dest_path, 1024) {
        Ok(signatures) => signatures,
        Err(e) => {
            eprintln!("Checksum error: {e}");
            return
        }
    };

    // NOTE: Only for testing purposes
    for block in signatures {
        let weak = block.weak;
        println!("Weak: {weak}");
    }
}
