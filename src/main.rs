use clap::*;
use clap_num::maybe_hex;
use exhume_body::Body;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, error, info, LevelFilter};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};

const EXPORT_CHUNK: usize = 1024 * 1024;


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
        "aff" => {
            info!("Processing the file '{}' in 'aff' format...", file_path);
            reader = Body::new_from(file_path.to_string(), "aff", Some(*offset));
            info!("------------------------------------------------------------");
            info!("Selected format: AFF");
            info!("Description: Advanced Forensics Format.");
            info!("Sector size: {:?}", reader.get_sector_size());
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
                "Invalid format '{}'. Supported formats are 'raw', 'ewf', 'vmdk', 'aff', 'aff4', and 'auto'.",
                format
            );
            std::process::exit(1);
        }
    }
    reader.print_info();

    let mut bytes = vec![0u8; *size as usize];
    reader.read_exact(&mut bytes).unwrap();
    let result = String::from_utf8_lossy(&bytes);
    println!("{}", result);
}


fn export_to_raw(input: &str, format: &str, output: &str) {
    let mut body = Body::new(input.to_string(), format);
    body.print_info();

    let total = match body.seek(SeekFrom::End(0)) {
        Ok(n) => n,
        Err(e) => {
            error!("Cannot determine image size: {}", e);
            std::process::exit(1);
        }
    };
    body.seek(SeekFrom::Start(0)).unwrap();

    info!(
        "Exporting {} bytes ({:.2} GiB) to '{}'",
        total,
        total as f64 / (1u64 << 30) as f64,
        output
    );

    let writer: Box<dyn Write> = if output == "-" {
        Box::new(io::stdout().lock())
    } else {
        match std::fs::File::create(output) {
            Ok(f) => Box::new(BufWriter::new(f)),
            Err(e) => {
                error!("Cannot create output file '{}': {}", output, e);
                std::process::exit(1);
            }
        }
    };
    let mut writer = writer;

    let bar = if output == "-" {
        let b = ProgressBar::hidden();
        b
    } else {
        let b = ProgressBar::new(total);
        b.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, eta {eta})",
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        b
    };

    let mut buf = vec![0u8; EXPORT_CHUNK];
    let mut written: u64 = 0;
    loop {
        let remaining = total - written;
        if remaining == 0 {
            break;
        }
        let to_read = (remaining as usize).min(EXPORT_CHUNK);
        match body.read(&mut buf[..to_read]) {
            Ok(0) => break,
            Ok(n) => {
                if let Err(e) = writer.write_all(&buf[..n]) {
                    error!("Write error: {}", e);
                    std::process::exit(1);
                }
                written += n as u64;
                bar.set_position(written);
            }
            Err(e) => {
                error!("Read error: {}", e);
                std::process::exit(1);
            }
        }
    }

    if let Err(e) = writer.flush() {
        error!("Flush error: {}", e);
        std::process::exit(1);
    }
    bar.finish_with_message("done");
    info!("Export complete: {} bytes written to '{}'", written, output);
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
                .help(
                    "The format of the file, either 'raw', 'ewf', 'vmdk', 'aff', 'aff4' or 'auto'.",
                ),
        )
        .arg(
            Arg::new("size")
                .short('s')
                .long("size")
                .value_parser(maybe_hex::<u64>)
                .required_unless_present("export")
                .help("The size (in bytes) to read (not required when --export is used)."),
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
            Arg::new("export")
                .short('e')
                .long("export")
                .value_parser(value_parser!(String))
                .required(false)
                .help("Export the full image as a raw/dd file. Use '-' to write to stdout."),
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
    let offset = matches.get_one::<u64>("offset").unwrap_or(&0);

    if let Some(output) = matches.get_one::<String>("export") {
        export_to_raw(file_path, format, output);
    } else {
        let size = matches.get_one::<u64>("size").unwrap();
        process_file(file_path, format, size, offset);
    }
}
