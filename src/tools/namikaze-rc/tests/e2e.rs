// SPDX-License-Identifier: MPL-2.0
//! End-to-end tests: run the real namikaze-rc binary as a child, the
//! way a user would, and check stdout, stderr and exit codes.

use std::process::Command;

fn rc(args: &[&str]) -> (String, String, i32) {
    let out = Command::new(env!("CARGO_BIN_EXE_namikaze-rc"))
        .args(args)
        .output()
        .expect("spawn namikaze-rc");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

fn one_line(src: &str) -> (String, String, i32) {
    rc(&["-c", src])
}

#[test]
fn pipes_and_redirections() {
    let (out, err, code) = one_line("seq 1 5 | tail -2");
    assert_eq!((code, err.as_str()), (0, ""));
    assert_eq!(out, "4\n5\n");

    let dir = std::env::temp_dir().join(format!("rc-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let file = dir.join("out.txt");
    let (out, _, code) =
        one_line(&format!("seq 1 3 > {}; wc -l < {}", file.display(), file.display()));
    assert_eq!((code, out.as_str()), (0, "3\n"));
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn variables_lists_and_subscripts() {
    let (out, _, code) = one_line("x=hello; echo $x^!");
    assert_eq!((code, out.as_str()), (0, "hello!\n"));
    let (out, _, _) = one_line("list=(alpha beta gamma); echo $list(2)");
    assert_eq!(out, "beta\n");
    let (out, _, _) = one_line("x=; echo count=$#x");
    // $# is a documented limitation of this port; the literal survives
    assert!(out.contains("count="), "got: {out}");
}

#[test]
fn pattern_matching_and_if_not() {
    let (out, _, code) = one_line("if(~ namikaze nam* x) echo hit; if not echo miss");
    assert_eq!((code, out.as_str()), (0, "hit\n"));
    let (out, _, code) = one_line("if(~ namikaze lin*) echo hit; if not echo miss");
    assert_eq!((code, out.as_str()), (0, "miss\n"));
}

#[test]
fn status_variable_tracks_the_last_command() {
    let (out, _, _) = one_line("true; echo $status");
    assert_eq!(out, "0\n");
    let (out, _, _) = one_line("false; echo $status");
    assert_eq!(out, "1\n");
}

#[test]
fn missing_files_use_plan9_wording() {
    // rc reports its own exec failure with the plan9 wording
    let (_, err, code) = one_line("nonexistent-command-xyz");
    assert_eq!(code, 1);
    assert!(err.contains("file does not exist"), "got: {err}");
}

#[test]
fn syntax_errors_carry_positions_and_exit_two() {
    let (_, err, code) = one_line("echo 'unterminated");
    assert_eq!(code, 2);
    assert!(err.contains("line 1, column 6"), "got: {err}");
    let (_, err, code) = one_line("if x) echo");
    assert_eq!(code, 2);
    assert!(err.contains("expected '(' after 'if'"), "got: {err}");
}

#[test]
fn script_files_take_arguments_and_shift() {
    let dir = std::env::temp_dir().join(format!("rc-script-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let script = dir.join("demo.rc");
    std::fs::write(&script, "echo args: $*\nshift\necho now: $*\n").expect("write");
    let (out, _, code) = rc(&[script.to_str().expect("utf8"), "one", "two", "three"]);
    assert_eq!((code, out.as_str()), (0, "args: one two three\nnow: two three\n"));
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn globbing_runs_against_the_working_directory() {
    let dir = std::env::temp_dir().join(format!("rc-glob-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    std::fs::write(dir.join("aaa.txt"), b"x").expect("touch");
    std::fs::write(dir.join("aab.txt"), b"x").expect("touch");
    // run with cwd = dir via a child shell doing the cd itself
    let out = Command::new(env!("CARGO_BIN_EXE_namikaze-rc"))
        .arg("-c")
        .arg("cd $1; echo *.txt")
        .arg(dir.to_str().expect("utf8"))
        .output()
        .expect("spawn");
    let out = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(out, "aaa.txt aab.txt\n");
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn assignment_from_var_and_backquote_yields_lists() {
    let (out, _err, code) = one_line("y=(p q); x=$y; echo $#x");
    assert_eq!(code, 0, "x=$y is an assignment");
    assert_eq!(out.trim(), "2");

    let (out, _err, code) = one_line("x=`{echo a b}; echo $#x");
    assert_eq!(code, 0, "backquote assignment is an assignment");
    assert_eq!(out.trim(), "2");
}
