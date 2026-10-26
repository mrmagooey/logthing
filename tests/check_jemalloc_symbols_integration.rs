//! Integration test for `scripts/check-jemalloc-symbols.sh`, the guard `binaries.yml` runs
//! before and after the release build. It must fail for a binary without jemalloc markers.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/check-jemalloc-symbols.sh")
}

fn run(args: &[&str]) -> Output {
    Command::new("bash")
        .arg(script())
        .args(args)
        .output()
        .expect("run check-jemalloc-symbols.sh")
}

fn write_fake(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    path
}

#[test]
fn test_script_passes_when_jemalloc_symbols_present() {
    let dir = tempfile::tempdir().unwrap();
    let mut body = b"\x7fELF\0\0/etc/_rjem_malloc.conf\0".to_vec();
    for i in 0..12 {
        body.extend_from_slice(format!("<jemalloc>: message {i}\0").as_bytes());
    }
    let fake = write_fake(dir.path(), "with", &body);
    let out = run(&[fake.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn test_script_fails_when_jemalloc_symbols_absent() {
    let dir = tempfile::tempdir().unwrap();
    let fake = write_fake(dir.path(), "without", b"\x7fELF\0\0malloc\0free\0");
    let out = run(&[fake.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("_rjem_malloc.conf"));
}

#[test]
fn test_script_fails_when_only_the_config_marker_is_present() {
    let dir = tempfile::tempdir().unwrap();
    let fake = write_fake(
        dir.path(),
        "partial",
        b"\x7fELF\0\0/etc/_rjem_malloc.conf\0",
    );
    let out = run(&[fake.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("<jemalloc>:"));
}

#[test]
fn test_script_exits_2_for_unknown_second_argument() {
    let dir = tempfile::tempdir().unwrap();
    let fake = write_fake(dir.path(), "any", b"\x7fELF\0\0");
    let out = run(&[fake.to_str().unwrap(), "--rnu"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage"));
}

#[test]
fn test_script_exits_2_for_missing_file_or_no_argument() {
    assert_eq!(run(&["/nonexistent/logthing"]).status.code(), Some(2));
    assert_eq!(run(&[]).status.code(), Some(2));
}

#[test]
fn test_script_matches_the_real_binary_allocator() {
    // Default gnu build: system allocator, no jemalloc markers. `--features jemalloc` (or a musl
    // test build): symbols present AND the binary actually starts and logs allocator=jemalloc.
    let bin = env!("CARGO_BIN_EXE_logthing");
    if cfg!(any(feature = "jemalloc", target_env = "musl")) {
        let out = run(&[bin, "--run"]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    } else {
        assert_eq!(run(&[bin]).status.code(), Some(1));
    }
}

#[test]
fn test_script_run_mode_kills_a_binary_that_ignores_term() {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("fake.pid");
    let mut body = String::from("#!/usr/bin/env bash\n# /etc/_rjem_malloc.conf\n");
    for i in 0..12 {
        body.push_str(&format!("# <jemalloc>: message {i}\n"));
    }
    body.push_str(&format!(
        "echo $$ > '{}'\necho allocator=jemalloc\ntrap '' TERM\nwhile :; do sleep 1; done\n",
        pidfile.display()
    ));
    let fake = write_fake(dir.path(), "stubborn", body.as_bytes());
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

    let mut child = Command::new("bash")
        .arg(script())
        .arg(&fake)
        .arg("--run")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn check-jemalloc-symbols.sh");
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let fake_pid = std::fs::read_to_string(&pidfile)
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok());
    if status.is_none() {
        // Clean up only the PIDs this test started, so a hang cannot leak processes.
        let _ = child.kill();
        let _ = child.wait();
        if let Some(pid) = fake_pid {
            let _ = Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .status();
        }
        panic!("check-jemalloc-symbols.sh --run hung >30s on a binary that ignores SIGTERM");
    }
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert_eq!(status.unwrap().code(), Some(0), "stderr: {stderr}");
    let pid = fake_pid.expect("fake binary recorded its pid");
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "fake binary (pid {pid}) survived the script"
    );
}
