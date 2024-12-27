mod ewf;
mod raw;

use clap::{Arg, ArgAction, Command};
use ewf::EWF;
use raw::RAW;
use std;

fn process_file(file_path: &str, format: &str, size: &usize, offset: &usize, verbose: &bool) {
    match format {
        "raw" => {
            if *verbose {
                println!("Processing the file '{}' in 'raw' format...", file_path);
            }
            let mut file = match RAW::new(file_path) {
                Ok(file) => file,
                Err(err) => {
                    eprintln!("Error: {}", err);
                    std::process::exit(1);
                }
            };
            if *verbose {
                println!("------------------------------------------------------------");
                println!("Selected reader: RAW");
                println!("Description: Standard reader.");
                println!("------------------------------------------------------------");
            }

            // Seek to the offset
            file.seek(*offset);
            let bytes = file.read(*size);
            let result = String::from_utf8_lossy(&bytes);
            println!("{}", result);
        }
        "ewf" => {
            if *verbose {
                println!("Processing the file '{}' in 'ewf' format...", file_path);
            }
            let mut file = match EWF::new(file_path) {
                Ok(file) => file,
                Err(err) => {
                    eprintln!("Error: {}", err);
                    std::process::exit(1);
                }
            };
            if *verbose {
                println!("------------------------------------------------------------");
                println!("Selected reader: EWF");
                println!("Description: Expert Witness Format.");
                println!("------------------------------------------------------------");
            }

            // Seek to the offset
            file.seek(*offset);
            let bytes = file.read(*size);
            let result = String::from_utf8_lossy(&bytes);
            println!("{}", result);
        }
        _ => {
            eprintln!(
                "Error: Invalid format '{}'. Supported formats are 'raw' and 'ewf'.",
                format
            );
            std::process::exit(1);
        }
    }
}

fn main() {
    let matches = Command::new("my_program")
        .version("1.0")
        .author("ForensicXlab")
        .about("A program that processes files based on the given format.")
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .value_parser(clap::value_parser!(String))
                .required(true)
                .help("The path to the input file."),
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_parser(clap::value_parser!(String))
                .required(true)
                .help("The format of the file, either 'raw' or 'ewf'."),
        )
        .arg(
            Arg::new("size")
                .short('s')
                .long("size")
                .value_parser(clap::value_parser!(usize))
                .required(true)
                .help("The size (in bytes) to read."),
        )
        .arg(
            Arg::new("offset")
                .short('o')
                .long("offset")
                .value_parser(clap::value_parser!(usize))
                .required(false)
                .help("Read at a specific offset."),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    let file_path = matches.get_one::<String>("input").unwrap();
    let format = matches.get_one::<String>("format").unwrap();
    let size = matches.get_one::<usize>("size").unwrap();
    let offset = match matches.get_one::<usize>("offset") {
        Some(offset) => offset,
        None => &(0 as usize),
    };
    let verbose = match matches.get_one::<bool>("verbose") {
        Some(verbose) => verbose,
        None => &false,
    };
    process_file(file_path, format, size, offset, verbose);
}
