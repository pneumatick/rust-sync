use std::env;

use common::checksum;

fn main() {
    // Get the alpha file path and convert it into a string
    let from_path = env::args_os()
        .nth(1)
        .expect("Error: Missing arguments!");

    println!("Reading file: {:?}", from_path);

    let from_string = match from_path.into_string() {
        Ok(utf8) => utf8,
        Err(original_os_str) => {
            eprintln!("Invalid UTF-8: {:?}", original_os_str);
            return
        }
    };

    // NOTE: Do the same for the beta file path

    // Get the list of signatures from "beta"
    let signatures = match checksum::gen_beta_checksums(&from_string, 1024) {
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
