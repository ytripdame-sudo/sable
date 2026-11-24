//! A launcher that records what it was started with, for the acceptance probe.
//!
//! The sideload's whole contract with the launcher is the command line: the path to itself, and
//! `--carrier <path>` when a picture is sitting in the same directory. Nothing else in the DLL
//! can be checked without executing it, and executing it happens on a guest — so the launcher
//! that receives the call is this, and it writes the call down.
//!
//! It writes `launcher.txt` beside itself: one line per argument, in order, `argv[0]` included.
//! Then it sleeps, so the probe has something to find while it is looking: a process that exits
//! before the check runs proves nothing about whether it ran.
//!
//! Built with a plain `rustc -O` on the guest. No cargo, no dependencies, no manifest — the
//! probe compiles this file directly.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

fn main() {
    let mut beside = env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    beside.pop();
    beside.push("launcher.txt");

    let mut recorded = String::new();
    for argument in env::args_os() {
        recorded.push_str(&argument.to_string_lossy());
        recorded.push('\n');
    }
    recorded.push_str(&format!("pid {}\n", std::process::id()));

    let _ = fs::write(&beside, recorded);

    thread::sleep(Duration::from_secs(6));
}
