//! Command line over the two formats.
//!
//! ```text
//! sable-aes seal <source.zip> <sealed.zip> <password>
//! sable-aes open <sealed.zip> <folder> <password>
//! sable-aes image <artifact.exe> <payload.zip>
//! sable-aes trailer <artifact.exe>
//! sable-aes seal-blob <payload.zip> <blob.bin> <seal key>
//! ```
//!
//! Every command prints one line and exits 0, or prints the reason and exits 2. There
//! is no interactive mode: this is a tool for a script and for a test harness, and both
//! of them want an exit code.

use std::path::PathBuf;
use std::process::ExitCode;

use sable_aes::container::{open_sealed, read_sealed, read_trailer, seal_blob};
use sable_aes::winzip::{open_archive, seal_archive};

fn usage() -> ExitCode {
    eprintln!("usage:");
    eprintln!("  sable-aes seal <source.zip> <sealed.zip> <password>");
    eprintln!("  sable-aes open <sealed.zip> <folder> <password>");
    eprintln!("  sable-aes image <artifact.exe> <payload.zip>");
    eprintln!("  sable-aes trailer <artifact.exe>");
    eprintln!("  sable-aes seal-blob <payload.zip> <blob.bin> <seal key>");
    ExitCode::from(1)
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.is_empty() {
        return usage();
    }

    let outcome = match arguments[0].as_str() {
        "seal" => seal(&arguments),
        "open" => open(&arguments),
        "image" => image(&arguments),
        "trailer" => trailer(&arguments),
        "seal-blob" => blob(&arguments),
        "--version" | "version" => {
            println!("sable-aes {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => return usage(),
    };

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(detail) => {
            eprintln!("{detail}");
            ExitCode::from(2)
        }
    }
}

fn seal(arguments: &[String]) -> Result<(), String> {
    let (source, destination, password) = three(arguments)?;
    let count =
        seal_archive(&source, &destination, &password).map_err(|error| error.to_string())?;
    println!("sealed {count} members -> {}", destination.display());
    Ok(())
}

fn open(arguments: &[String]) -> Result<(), String> {
    let (source, destination, password) = three(arguments)?;
    let names =
        open_archive(&source, &destination, &password).map_err(|error| error.to_string())?;
    println!(
        "opened {} members -> {}",
        names.len(),
        destination.display()
    );
    Ok(())
}

fn image(arguments: &[String]) -> Result<(), String> {
    if arguments.len() < 3 {
        return Err("image needs an artifact and a destination".into());
    }
    let artifact = PathBuf::from(&arguments[1]);
    let destination = PathBuf::from(&arguments[2]);

    let trailer = read_trailer(&artifact).map_err(|error| error.to_string())?;
    let sealed = read_sealed(&artifact).map_err(|error| error.to_string())?;
    let plaintext = open_sealed(&sealed, &trailer.seal_key).map_err(|error| error.to_string())?;

    std::fs::write(&destination, &plaintext).map_err(|error| error.to_string())?;
    println!(
        "opened {} bytes -> {}",
        plaintext.len(),
        destination.display()
    );
    Ok(())
}

fn trailer(arguments: &[String]) -> Result<(), String> {
    if arguments.len() < 2 {
        return Err("trailer needs an artifact".into());
    }
    let trailer = read_trailer(&PathBuf::from(&arguments[1])).map_err(|error| error.to_string())?;
    println!("seal key  {}", trailer.seal_key);
    println!("mutex     {}", trailer.mutex);
    Ok(())
}

fn blob(arguments: &[String]) -> Result<(), String> {
    let (source, destination, key) = three(arguments)?;
    let plaintext = std::fs::read(&source).map_err(|error| error.to_string())?;
    let sealed = seal_blob(&plaintext, &key).map_err(|error| error.to_string())?;
    std::fs::write(&destination, &sealed).map_err(|error| error.to_string())?;
    println!("sealed {} bytes -> {}", sealed.len(), destination.display());
    Ok(())
}

fn three(arguments: &[String]) -> Result<(PathBuf, PathBuf, String), String> {
    if arguments.len() < 4 {
        return Err(format!("{} needs three arguments", arguments[0]));
    }
    Ok((
        PathBuf::from(&arguments[1]),
        PathBuf::from(&arguments[2]),
        arguments[3].clone(),
    ))
}
