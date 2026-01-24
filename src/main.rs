use clap::*;
use clap_num::maybe_hex;
use exhume_body::Body;
use log::{debug, error, info, LevelFilter};
use std::io::Read;

fn process_file(file_path: &str, format: &str, size: &u64, offset: &u64) {
    let mut reader: Body;
    match format {
        "raw" => {
            info!("Processing the file '{}' in 'raw' format...", file_path);
            reader = Body::new_from(file_path.to_string(), format, Some(*offset));

            debug!("------------------------------------------------------------");
            info!("Selected format: RAW");
            info!("Description: Raw Data");
            debug!("------------------------------------------------------------");
        }
        "ewf" => {
            reader = Body::new_from(file_path.to_string(), format, Some(*offset));
            info!("Processing the file '{}' in 'ewf' format...", file_path);
            info!("------------------------------------------------------------");
            info!("Selected format: EWF");
            info!("Description: Expert Witness Format.");
            info!("Sector size: {:?}", reader.get_sector_size());
            debug!("------------------------------------------------------------");
        }
        "vmdk" => {
            info!("Processing the file '{}' in 'vmdk' format...", file_path);
            reader = Body::new_from(file_path.to_string(), format, Some(*offset));
            info!("------------------------------------------------------------");
            info!("Selected format: VMDK");
            info!("Description: VMDK (Virtual Machine Disk) file.");
            debug!("------------------------------------------------------------");
        }
        "auto" => {
            info!("Processing the file '{}' in 'auto' format...", file_path);
            reader = Body::new_from(file_path.to_string(), format, Some(*offset));
        }
        "aff4" | "aff4l" => {
            info!("Processing the file '{}' in 'aff4' format...", file_path);
            reader = Body::new_from(file_path.to_string(), "aff4", Some(*offset));
            info!("------------------------------------------------------------");
            info!("Selected format: AFF4 / AFF4-L");
            info!("Description: AFF4 ImageStream (Zip volume).");
            info!("Sector size: {:?}", reader.get_sector_size());
            debug!("------------------------------------------------------------");
        }
        _ => {
            error!(
                "Invalid format '{}'. Supported formats are 'raw', 'ewf', 'vmdk', 'aff4', and 'auto'.",
                format
            );
            std::process::exit(1);
        }
    }
    reader.print_info();

    let mut bytes = vec![0u8; *size as usize];
    reader.read(&mut bytes).unwrap();
    let result = String::from_utf8_lossy(&bytes);
    println!("{}", result);
}

fn main() {
    let matches = Command::new("exhume_body")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Exhume a body of data from many file formats.")
        .arg(
            Arg::new("body")
                .short('b')
                .long("body")
                .value_parser(value_parser!(String))
                .required(true)
                .help("The path to the body to exhume."),
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_parser(value_parser!(String))
                .required(false)
                .help("The format of the file, either 'raw', 'ewf', 'vmdk', 'aff4' or 'auto'."),
        )
        .arg(
            Arg::new("size")
                .short('s')
                .long("size")
                .value_parser(maybe_hex::<u64>)
                .required(true)
                .help("The size (in bytes) to read."),
        )
        .arg(
            Arg::new("offset")
                .short('o')
                .long("offset")
                .value_parser(maybe_hex::<u64>)
                .required(false)
                .help("Read at a specific offset."),
        )
        .arg(
            Arg::new("log_level")
                .short('l')
                .long("log-level")
                .value_parser(["error", "warn", "info", "debug", "trace"])
                .default_value("info")
                .help("Set the log verbosity level"),
        )
        .get_matches();

    let log_level_str = matches.get_one::<String>("log_level").unwrap();
    let level_filter = match log_level_str.as_str() {
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Info,
    };

    env_logger::Builder::new().filter_level(level_filter).init();

    let file_path = matches.get_one::<String>("body").unwrap();
    let auto = String::from("auto");
    let format = matches.get_one::<String>("format").unwrap_or(&auto);
    let size = matches.get_one::<u64>("size").unwrap();
    let offset = matches.get_one::<u64>("offset").unwrap_or(&0);

    process_file(file_path, format, size, offset);
}
