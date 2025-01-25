use clap::{Arg, ArgAction, Command};
use exhume_body::Body;
use std::io::{Read, Seek, SeekFrom};

fn process_file(file_path: &str, format: &str, size: &usize, offset: &u64, verbose: &bool) {
    let mut reader: Body;
    match format {
        "raw" => {
            if *verbose {
                println!("Processing the file '{}' in 'raw' format...", file_path);
            }
            reader = Body::new(file_path.to_string(), format);
            if *verbose {
                reader.print_info();
                println!("------------------------------------------------------------");
                println!("Selected format: RAW");
                println!("Description: Raw Data");
                println!("------------------------------------------------------------");
            }
        }
        "ewf" => {
            reader = Body::new(file_path.to_string(), format);
            if *verbose {
                println!("Processing the file '{}' in 'ewf' format...", file_path);
            }

            if *verbose {
                println!("------------------------------------------------------------");
                println!("Selected format: EWF");
                println!("Description: Expert Witness Format.");
                println!("------------------------------------------------------------");
            }
        }
        _ => {
            eprintln!(
                "Error: Invalid format '{}'. Supported formats are 'raw' and 'ewf'.",
                format
            );
            std::process::exit(1);
        }
    }
    // Seek to the offset
    reader.seek(SeekFrom::Start(*offset)).unwrap();
    let mut bytes = vec![0u8; *size];
    reader.read(&mut bytes).unwrap();
    let result = String::from_utf8_lossy(&bytes);
    println!("{}", result);
}

fn main() {
    let matches = Command::new("exhume_body")
        .version("1.0")
        .author("ForensicXlab")
        .about("Exhume a body of data from many file formats.")
        .arg(
            Arg::new("body")
                .short('b')
                .long("body")
                .value_parser(clap::value_parser!(String))
                .required(true)
                .help("The path to the body to exhume."),
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
                .value_parser(clap::value_parser!(u64))
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

    let file_path = matches.get_one::<String>("body").unwrap();
    let format = matches.get_one::<String>("format").unwrap();
    let size = matches.get_one::<usize>("size").unwrap();
    let offset = match matches.get_one::<u64>("offset") {
        Some(offset) => offset,
        None => &(0),
    };
    let verbose = match matches.get_one::<bool>("verbose") {
        Some(verbose) => verbose,
        None => &false,
    };
    process_file(file_path, format, size, offset, verbose);
}
