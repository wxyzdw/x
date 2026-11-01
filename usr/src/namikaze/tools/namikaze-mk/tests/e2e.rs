// SPDX-License-Identifier: MPL-2.0
//! End-to-end tests: run the real namikaze-mk binary in temp work
//! directories, the way a user would.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

struct Work {
    dir: PathBuf,
}

impl Work {
    fn new(name: &str) -> Work {
        let dir = std::env::temp_dir().join(format!("mk-e2e-{}-{name}", std::process::id()));
        fs::create_dir_all(&dir).expect("mkdir");
        Work { dir }
    }

    fn write(&self, name: &str, text: &str) {
        fs::write(self.dir.join(name), text).expect("write");
    }

    fn mk(&self, args: &[&str]) -> (String, String, i32) {
        let out = Command::new(env!("CARGO_BIN_EXE_namikaze-mk"))
            .current_dir(&self.dir)
            .args(args)
            .output()
            .expect("spawn namikaze-mk");
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
            out.status.code().unwrap_or(-1),
        )
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn builds_the_default_goal_once_and_stays_up_to_date() {
    let w = Work::new("default");
    w.write(
        "mkfile",
        "prog: part.txt\n\tcat part.txt > prog\n\techo built $target\n\npart.txt:\n\techo data > part.txt\n",
    );
    let (out, _, code) = w.mk(&[]);
    assert_eq!(code, 0, "first build");
    assert!(out.contains("echo data > part.txt"), "recipes are echoed: {out}");
    assert!(out.contains("built prog"), "recipe variables expand: {out}");
    assert!(w.dir.join("prog").exists());

    let (out, _, code) = w.mk(&[]);
    assert_eq!((code, out.as_str()), (0, ""), "second build is a no-op");
}

#[test]
fn a_newer_prereq_triggers_a_rebuild() {
    let w = Work::new("rebuild");
    w.write("mkfile", "out: in\n\tcp in out\n");
    w.write("in", "v1");
    let _ = w.mk(&[]);
    let first = fs::metadata(w.dir.join("out")).expect("out exists").modified().expect("mtime");
    std::thread::sleep(std::time::Duration::from_millis(20));
    w.write("in", "v2");
    let _ = w.mk(&[]);
    let second = fs::metadata(w.dir.join("out")).expect("out exists").modified().expect("mtime");
    assert!(second > first, "the recipe ran again after the prereq changed");
    assert_eq!(fs::read_to_string(w.dir.join("out")).expect("read"), "v2");
}

#[test]
fn meta_rules_match_stems() {
    let w = Work::new("meta");
    w.write(
        "mkfile",
        "%.echo: %.src\n\tcp $prereq $target\n",
    );
    w.write("hello.src", "x");
    let (out, _, code) = w.mk(&["hello.echo"]);
    assert_eq!(code, 0, "meta-rule applies: {out}");
    assert!(out.contains("cp hello.src hello.echo"), "$prereq and % substitution: {out}");
    assert_eq!(fs::read_to_string(w.dir.join("hello.echo")).expect("read"), "x");
}

#[test]
fn virtual_rules_always_run_and_group_prereqs() {
    let w = Work::new("virtual");
    w.write(
        "mkfile",
        "all:V: one two\none:\n\techo one >> log\ntwo:\n\techo two >> log\n",
    );
    let (out, _, code) = w.mk(&["all"]);
    assert_eq!(code, 0, "{out}");
    let log = fs::read_to_string(w.dir.join("log")).expect("read");
    assert_eq!(log, "one\ntwo\n");
    // again: V keeps them virtual, the log grows
    let _ = w.mk(&["all"]);
    let log = fs::read_to_string(w.dir.join("log")).expect("read");
    assert_eq!(log, "one\ntwo\none\ntwo\n");
}

#[test]
fn dry_run_prints_without_executing() {
    let w = Work::new("dryrun");
    w.write("mkfile", "out:\n\techo should-not-run > out\n");
    let (out, _, code) = w.mk(&["-n", "out"]);
    assert_eq!(code, 0);
    assert!(out.contains("echo should-not-run > out"), "-n still prints: {out}");
    assert!(!w.dir.join("out").exists(), "-n does not execute");
}

#[test]
fn failures_carry_the_rule_line() {
    let w = Work::new("fail");
    w.write("mkfile", "bad:\n\texit 7\n");
    let (_, err, code) = w.mk(&[]);
    assert_eq!(code, 1);
    assert!(err.contains("line 2"), "the rule line is named: {err}");
    assert!(err.contains("status 7"), "the exit status is named: {err}");
}

#[test]
fn cycles_are_reported_with_the_chain() {
    let w = Work::new("cycle");
    w.write("mkfile", "a: b\nb: a\n");
    let (_, err, code) = w.mk(&["a"]);
    assert_eq!(code, 1);
    assert!(err.contains("a -> b -> a"), "the loop is shown: {err}");
}

#[test]
fn no_rule_errors_name_the_needed_by_target() {
    let w = Work::new("norule");
    w.write("mkfile", "top: ghost.txt\n\tcat ghost.txt\n");
    let (_, err, code) = w.mk(&["top"]);
    assert_eq!(code, 1);
    assert!(err.contains("no rule to make ghost.txt, needed by top"), "got: {err}");
}

#[test]
fn command_line_overrides_win_in_any_position() {
    let w = Work::new("override");
    w.write("mkfile", "MSG=from-file\nshow:\n\techo $MSG\n");
    let (out, _, code) = w.mk(&["MSG=from-argv"]);
    assert_eq!(code, 0);
    assert!(out.contains("echo from-argv"), "recipe echoed expanded: {out}");
    assert!(out.contains("from-argv\n"), "variable used the override: {out}");
    let (out, _, _) = w.mk(&["-a", "show", "MSG=from-argv-after"]);
    assert!(out.contains("echo from-argv-after"), "later position works too: {out}");
    assert!(out.ends_with("from-argv-after\n"));
}
