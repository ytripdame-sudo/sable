//! Round trips inside Rust: the writer and the reader provably agree on shapes that
//! break naive implementations — an empty member, a nested path, a name that is not
//! ASCII — and a tampered byte fails rather than decrypting to plausible garbage.

use std::io::Write;
use std::path::Path;

use sable_aes::container::{
    open_sealed, read_sealed, read_trailer, seal_blob, write_image, FOOTER_SIZE, TRAILER_SIZE,
};
use sable_aes::winzip::{open_archive, seal_archive};
use sable_aes::Error;

const PASSWORD: &str = "round-trip-key-9a3f";

fn workspace(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("sable-aes-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("workspace");
    path
}

fn source_zip(path: &Path) -> zip::ZipWriter<std::fs::File> {
    let file = std::fs::File::create(path).expect("create");
    zip::ZipWriter::new(file)
}

fn tree_digest(root: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(root: &Path, at: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let mut entries: Vec<_> = std::fs::read_dir(at)
            .expect("read")
            .map(|entry| entry.expect("entry").path())
            .collect();
        entries.sort();

        for path in entries {
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let relative = path
                    .strip_prefix(root)
                    .expect("relative")
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((relative, std::fs::read(&path).expect("read member")));
            }
        }
    }

    let mut found = Vec::new();
    walk(root, root, &mut found);
    found
}

#[test]
fn seal_then_open_returns_every_member() {
    let work = workspace("roundtrip");
    let source = work.join("source.zip");
    let mut bundle = source_zip(&source);

    let members: [(&str, &[u8]); 4] = [
        ("plain.txt", b"the first member\n"),
        ("nested/deeper/notes.txt", b"the second member\n"),
        ("caf\u{00e9}.txt", b"a name that is not ascii\n"),
        ("empty.bin", b""),
    ];

    for (name, data) in members {
        bundle
            .start_file(name, zip::write::SimpleFileOptions::default())
            .expect("start");
        bundle.write_all(data).expect("write");
    }
    bundle.finish().expect("finish");

    let sealed = work.join("sealed.zip");
    let count = seal_archive(&source, &sealed, PASSWORD).expect("seal");
    assert_eq!(count, members.len());

    let out = work.join("out");
    let written = open_archive(&sealed, &out, PASSWORD).expect("open");
    assert_eq!(written.len(), members.len());

    for (name, data) in members {
        let path = out.join(name.replace('/', std::path::MAIN_SEPARATOR_STR));
        assert_eq!(std::fs::read(&path).expect("member"), data, "{name}");
    }

    // The reader produced exactly the tree the writer was handed.
    let expected: Vec<(String, Vec<u8>)> = members
        .iter()
        .map(|(n, d)| (n.to_string(), d.to_vec()))
        .collect();
    let mut got = tree_digest(&out);
    got.sort();
    let mut expected = expected;
    expected.sort();
    assert_eq!(got, expected);
}

#[test]
fn the_wrong_password_is_refused() {
    let work = workspace("wrong-key");
    let source = work.join("source.zip");
    let mut bundle = source_zip(&source);
    bundle
        .start_file("a.txt", zip::write::SimpleFileOptions::default())
        .expect("start");
    bundle.write_all(b"payload").expect("write");
    bundle.finish().expect("finish");

    let sealed = work.join("sealed.zip");
    seal_archive(&source, &sealed, PASSWORD).expect("seal");

    let out = work.join("out");
    match open_archive(&sealed, &out, "another-key") {
        Err(Error::Auth(_)) => {}
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn one_flipped_byte_fails_authentication() {
    let work = workspace("tamper");
    let source = work.join("source.zip");
    let mut bundle = source_zip(&source);
    bundle
        .start_file("a.txt", zip::write::SimpleFileOptions::default())
        .expect("start");
    bundle
        .write_all(b"a member worth tampering with\n")
        .expect("write");
    bundle.finish().expect("finish");

    let sealed = work.join("sealed.zip");
    seal_archive(&source, &sealed, PASSWORD).expect("seal");

    let mut bytes = std::fs::read(&sealed).expect("read");
    // Flip one bit inside the first member's ciphertext: past the 30-byte local header,
    // past the two-character name, into the salt-plus-verifier region.
    let at = 30 + 5 + 18 + 3;
    bytes[at] ^= 0x40;
    let tampered = work.join("tampered.zip");
    std::fs::write(&tampered, &bytes).expect("write");

    let out = work.join("out");
    match open_archive(&tampered, &out, PASSWORD) {
        Err(Error::Auth(_)) => {}
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn the_container_round_trips_through_its_own_writer() {
    let work = workspace("container");
    let launcher = work.join("launcher.exe");
    std::fs::write(&launcher, b"MZ").expect("launcher");

    let payload = b"a payload that stands in for an archive".to_vec();
    let sealed = seal_blob(&payload, "seal-key-1234").expect("seal");

    let image = work.join("artifact.exe");
    let length = write_image(
        &launcher,
        &[0u8; 64],
        &sealed,
        "seal-key-1234",
        "Global\\SableTest",
        &image,
    )
    .expect("write image");

    let expected = std::fs::metadata(&image).expect("stat").len();
    assert_eq!(length, expected);
    assert!(expected > FOOTER_SIZE + TRAILER_SIZE);

    let trailer = read_trailer(&image).expect("trailer");
    assert_eq!(trailer.seal_key, "seal-key-1234");
    assert_eq!(trailer.mutex, "Global\\SableTest");

    let blob = read_sealed(&image).expect("sealed");
    let recovered = open_sealed(&blob, &trailer.seal_key).expect("open");
    assert_eq!(recovered, payload);
}

#[test]
fn a_container_with_a_wrong_key_reports_auth_not_garbage() {
    let payload = b"another payload".to_vec();
    let sealed = seal_blob(&payload, "seal-key-1234").expect("seal");
    match open_sealed(&sealed, "seal-key-9999") {
        Err(Error::Auth(_)) => {}
        other => panic!("expected a refusal, got {other:?}"),
    }
}
