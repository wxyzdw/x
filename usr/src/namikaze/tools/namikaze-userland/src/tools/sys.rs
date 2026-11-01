// SPDX-License-Identifier: MPL-2.0
#![forbid(unsafe_code)]
//! System information tools: true, false, sleep, env, printenv, nproc,
//! tty, id, uname, hostname, which, date, whoami.
//!
//! Determinism note: the userland is timezone-naive and always reports UTC.
//! This is a deliberate privacy property - no local timezone leaks into
//! logs, filenames or reports.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use crate::{fail, usage, EXIT_OK};

// ----------------------------------------------------------- true/false ----

/// true: exit 0.
pub fn r#true(_argv: &[String]) -> i32 {
    EXIT_OK
}

/// false: exit 1.
pub fn r#false(_argv: &[String]) -> i32 {
    crate::EXIT_FAILURE
}

// ---------------------------------------------------------------- sleep ----

fn parse_duration(txt: &str) -> Result<f64, String> {
    let (num, mult) = match txt.chars().last() {
        Some('s') => (&txt[..txt.len() - 1], 1.0),
        Some('m') => (&txt[..txt.len() - 1], 60.0),
        Some('h') => (&txt[..txt.len() - 1], 3600.0),
        Some('d') => (&txt[..txt.len() - 1], 86400.0),
        _ => (txt, 1.0),
    };
    let v: f64 = num.parse().map_err(|_| format!("invalid interval: {txt}"))?;
    if !v.is_finite() || v < 0.0 {
        return Err(format!("invalid interval: {txt}"));
    }
    Ok(v * mult)
}

/// sleep: pause for the sum of the given intervals (s, m, h, d suffixes).
pub fn sleep(argv: &[String]) -> i32 {
    let mut total = 0.0f64;
    for a in argv.iter().filter(|a| a.as_str() != "--") {
        match parse_duration(a) {
            Ok(v) => total += v,
            Err(e) => return fail("sleep", &e),
        }
    }
    if argv.is_empty() {
        return usage("sleep", "missing interval");
    }
    std::thread::sleep(std::time::Duration::from_secs_f64(total));
    EXIT_OK
}

// ------------------------------------------------------------------ env ----

/// env: run a command with a modified environment, or print it.
pub fn env(argv: &[String]) -> i32 {
    let mut clear = false;
    let mut assigns: Vec<(String, String)> = Vec::new();
    let mut cmd_start: Option<usize> = None;
    for (idx, a) in argv.iter().enumerate() {
        if cmd_start.is_some() {
            break;
        }
        match a.as_str() {
            "-i" => clear = true,
            "--" => cmd_start = Some(idx + 1),
            s if s.contains('=') => {
                let (k, v) = s.split_once('=').unwrap_or((s, ""));
                assigns.push((k.to_string(), v.to_string()));
            }
            s => {
                if s.starts_with('-') && s.len() > 1 {
                    return usage("env", &format!("unsupported option: {s}"));
                }
                cmd_start = Some(idx);
            }
        }
    }
    if let Some(start) = cmd_start {
        if start >= argv.len() {
            return EXIT_OK;
        }
        let mut cmd = Command::new(&argv[start]);
        cmd.args(&argv[start + 1..]);
        if clear {
            cmd.env_clear();
        }
        for (k, v) in &assigns {
            cmd.env(k, v);
        }
        return match cmd.status() {
            Ok(st) if st.success() => EXIT_OK,
            Ok(st) => st.code().unwrap_or(1),
            Err(e) => fail("env", &format!("cannot run {}: {e}", argv[start])),
        };
    }
    // print mode: the effective environment, sorted for determinism
    let mut vars: BTreeMap<String, String> =
        if clear { BTreeMap::new() } else { std::env::vars().collect() };
    for (k, v) in assigns {
        vars.insert(k, v);
    }
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for (k, v) in &vars {
        let _ = writeln!(out, "{k}={v}");
    }
    let _ = out.flush();
    EXIT_OK
}

// ------------------------------------------------------------- printenv ----

/// printenv: print environment variable values; exit 1 if any is unset.
pub fn printenv(argv: &[String]) -> i32 {
    let names: Vec<&String> = argv.iter().filter(|a| a.as_str() != "--").collect();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if names.is_empty() {
        for (k, v) in std::env::vars() {
            let _ = writeln!(out, "{k}={v}");
        }
        let _ = out.flush();
        return EXIT_OK;
    }
    let mut missing = false;
    for n in names {
        match std::env::var(n) {
            Ok(v) => {
                let _ = writeln!(out, "{v}");
            }
            Err(_) => missing = true,
        }
    }
    let _ = out.flush();
    if missing {
        crate::EXIT_FAILURE
    } else {
        EXIT_OK
    }
}

// ----------------------------------------------------------------- nproc ----

/// nproc: number of usable processing units.
pub fn nproc(_argv: &[String]) -> i32 {
    let n = std::thread::available_parallelism().map(|v| v.get()).unwrap_or(1);
    println!("{n}");
    EXIT_OK
}

// ------------------------------------------------------------------ tty ----

/// tty: print the file name of the terminal on standard input.
pub fn tty(_argv: &[String]) -> i32 {
    match fs::read_link("/proc/self/fd/0") {
        Ok(p) => {
            let s = p.to_string_lossy();
            if s.starts_with("/dev/") {
                println!("{s}");
                EXIT_OK
            } else {
                eprintln!("namikaze-userland: tty: not a tty");
                crate::EXIT_FAILURE
            }
        }
        Err(_) => {
            eprintln!("namikaze-userland: tty: not a tty");
            crate::EXIT_FAILURE
        }
    }
}

// ------------------------------------------------------------------- id ----

fn field_after(line: &str, tag: &str) -> Option<String> {
    let rest = line.strip_prefix(tag)?;
    let rest = rest.trim_start();
    Some(rest.split_whitespace().next().unwrap_or("").to_string())
}

fn parse_ids(status: &str) -> (u32, u32, Vec<u32>) {
    let mut uid = 0;
    let mut gid = 0;
    let mut groups: Vec<u32> = Vec::new();
    for line in status.lines() {
        if let Some(v) = field_after(line, "Uid:") {
            uid = v.split('\t').find_map(|p| p.parse().ok()).unwrap_or(0);
        } else if let Some(v) = field_after(line, "Gid:") {
            gid = v.split('\t').find_map(|p| p.parse().ok()).unwrap_or(0);
        } else if let Some(v) = field_after(line, "Groups:") {
            groups = v.split(',').filter_map(|p| p.trim().parse().ok()).collect();
        }
    }
    (uid, gid, groups)
}

struct NameMaps {
    users: BTreeMap<u32, String>,
    groups: BTreeMap<u32, String>,
}

fn load_names() -> NameMaps {
    let mut users = BTreeMap::new();
    let mut groups = BTreeMap::new();
    if let Ok(text) = fs::read_to_string("/etc/passwd") {
        for line in text.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() >= 3 {
                if let Ok(uid) = f[2].parse::<u32>() {
                    users.insert(uid, f[0].to_string());
                }
            }
        }
    }
    if let Ok(text) = fs::read_to_string("/etc/group") {
        for line in text.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() >= 3 {
                if let Ok(gid) = f[2].parse::<u32>() {
                    groups.insert(gid, f[0].to_string());
                }
            }
        }
    }
    NameMaps { users, groups }
}

fn user_name(maps: &NameMaps, uid: u32) -> String {
    maps.users.get(&uid).cloned().unwrap_or_else(|| uid.to_string())
}

fn group_name(maps: &NameMaps, gid: u32) -> String {
    maps.groups.get(&gid).cloned().unwrap_or_else(|| gid.to_string())
}

/// id: print user and group identities from /proc/self/status.
pub fn id(_argv: &[String]) -> i32 {
    let status = match fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(e) => return fail("id", &format!("cannot read /proc/self/status: {e}")),
    };
    let (uid, gid, groups) = parse_ids(&status);
    let maps = load_names();
    let group_list: Vec<String> =
        groups.iter().map(|g| format!("{}({})", g, group_name(&maps, *g))).collect();
    println!(
        "uid={}({}) gid={}({}) groups={}",
        uid,
        user_name(&maps, uid),
        gid,
        group_name(&maps, gid),
        group_list.join(",")
    );
    EXIT_OK
}

// ---------------------------------------------------------------- uname ----

fn machine_name() -> &'static str {
    match option_env!("CARGO_CFG_TARGET_ARCH").unwrap_or("unknown") {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        "arm" => "armv7l",
        "riscv64" | "riscv64gc" => "riscv64",
        "loongarch64" => "loongarch64",
        "powerpc64" => "ppc64le",
        "s390x" => "s390x",
        other => Box::leak(other.to_string().into_boxed_str()),
    }
}

fn read_kernel_field(name: &str) -> String {
    fs::read_to_string(format!("/proc/sys/kernel/{name}"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// uname: print kernel identity; -a -s -n -r -m -o (UTC-deterministic).
pub fn uname(argv: &[String]) -> i32 {
    let mut all = false;
    let mut want = Vec::new();
    for a in argv {
        let flags = a.strip_prefix('-').unwrap_or("");
        if a == "--" || a.starts_with('-') && a.len() > 1 {
            for c in flags.chars() {
                match c {
                    'a' => all = true,
                    's' | 'n' | 'r' | 'm' | 'o' | 'v' => want.push(c),
                    _ => return usage("uname", &format!("unsupported option: {a}")),
                }
            }
        } else {
            return usage("uname", "unexpected operand");
        }
    }
    let sysname = {
        let t = read_kernel_field("ostype");
        if t.is_empty() {
            String::from("Linux")
        } else {
            t
        }
    };
    let release = read_kernel_field("osrelease");
    let version = read_kernel_field("version");
    let nodename = read_kernel_field("hostname");
    let machine = machine_name().to_string();
    if all {
        println!("{sysname} {nodename} {release} {version} {machine} NamikazeOS");
        return EXIT_OK;
    }
    if want.is_empty() {
        println!("{sysname}");
        return EXIT_OK;
    }
    let mut parts: Vec<String> = Vec::new();
    for c in want {
        parts.push(match c {
            's' => sysname.clone(),
            'n' => nodename.clone(),
            'r' => release.clone(),
            'v' => version.clone(),
            'm' => machine.clone(),
            _ => String::from("NamikazeOS"),
        });
    }
    println!("{}", parts.join(" "));
    EXIT_OK
}

// -------------------------------------------------------------- hostname ----

/// hostname: print the system hostname.
pub fn hostname(argv: &[String]) -> i32 {
    if let Some(a) = argv.first() {
        if a.starts_with('-') && a.len() > 1 {
            return usage("hostname", &format!("unsupported option: {a}"));
        }
    }
    let name = read_kernel_field("hostname");
    println!("{name}");
    EXIT_OK
}

// ---------------------------------------------------------------- which ----

fn is_executable(p: &std::path::Path) -> bool {
    fs::metadata(p).map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
}

/// which: locate commands on PATH; -a lists every match.
pub fn which(argv: &[String]) -> i32 {
    let mut all = false;
    let mut names: Vec<String> = Vec::new();
    for a in argv {
        match a.as_str() {
            "-a" => all = true,
            "--" => {}
            other if other.starts_with('-') && other.len() > 1 => {
                return usage("which", &format!("unsupported option: {other}"));
            }
            other => names.push(other.to_string()),
        }
    }
    if names.is_empty() {
        return usage("which", "missing operand");
    }
    let path = std::env::var("PATH").unwrap_or_default();
    let dirs: Vec<std::path::PathBuf> = std::env::split_paths(&path).collect();
    let mut code = EXIT_OK;
    for name in &names {
        if name.contains('/') {
            if is_executable(std::path::Path::new(name)) {
                println!("{name}");
            } else {
                code = crate::EXIT_FAILURE;
            }
            continue;
        }
        let mut found = false;
        for d in &dirs {
            let cand = d.join(name);
            if is_executable(&cand) {
                println!("{}", cand.display());
                found = true;
                if !all {
                    break;
                }
            }
        }
        if !found {
            code = crate::EXIT_FAILURE;
        }
    }
    code
}

// ----------------------------------------------------------------- date ----

/// A UTC civil timestamp.
pub struct Civil {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub weekday: u32,
    pub hour: u32,
    pub min: u32,
    pub sec: u32,
}

/// Days-since-epoch to (year, month, day); Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

/// Convert unix seconds to a UTC civil timestamp.
pub fn civil_from_unix(secs: i64) -> Civil {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    Civil {
        year,
        month,
        day,
        // 1970-01-01 was a Thursday (weekday 4 with 0 = Sunday)
        weekday: ((days + 4).rem_euclid(7)) as u32,
        hour: (rem / 3600) as u32,
        min: ((rem % 3600) / 60) as u32,
        sec: (rem % 60) as u32,
    }
}

/// Fixed-format timestamp used by ls -l and stat.
pub fn fmt_mtime(secs: i64) -> String {
    let c = civil_from_unix(secs);
    format!("{:04}-{:02}-{:02} {:02}:{:02}", c.year, c.month, c.day, c.hour, c.min)
}

const DAY_NAMES: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const DAY_NAMES_FULL: [&str; 7] =
    ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const MONTH_NAMES: [&str; 12] =
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const MONTH_NAMES_FULL: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// Format a civil timestamp with a strftime-lite +FORMAT string.
pub fn fmt_civil(fmt: &str, secs: i64) -> String {
    let c = civil_from_unix(secs);
    let mut out = String::new();
    let mut chars = fmt.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('Y') => out.push_str(&format!("{:04}", c.year)),
            Some('m') => out.push_str(&format!("{:02}", c.month)),
            Some('d') => out.push_str(&format!("{:02}", c.day)),
            Some('e') => out.push_str(&format!("{:2}", c.day)),
            Some('H') => out.push_str(&format!("{:02}", c.hour)),
            Some('M') => out.push_str(&format!("{:02}", c.min)),
            Some('S') => out.push_str(&format!("{:02}", c.sec)),
            Some('a') => out.push_str(DAY_NAMES[c.weekday as usize % 7]),
            Some('A') => out.push_str(DAY_NAMES_FULL[c.weekday as usize % 7]),
            Some('b') | Some('h') => out.push_str(MONTH_NAMES[(c.month as usize - 1) % 12]),
            Some('B') => out.push_str(MONTH_NAMES_FULL[(c.month as usize - 1) % 12]),
            Some('s') => out.push_str(&format!("{secs}")),
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

/// date: print the current (UTC) date; -u accepted, +FORMAT supported,
/// -d @SECONDS renders a fixed epoch.
pub fn date(argv: &[String]) -> i32 {
    let mut fmt: Option<String> = None;
    let mut fixed: Option<i64> = None;
    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "-u" || a == "--utc" {
            // already UTC-only by design
        } else if a == "-d" {
            i += 1;
            let Some(v) = argv.get(i) else { return usage("date", "-d needs an argument") };
            let Some(epoch) = v.strip_prefix('@') else {
                return usage("date", "only '@SECONDS' dates are supported");
            };
            match epoch.parse::<i64>() {
                Ok(n) => fixed = Some(n),
                Err(_) => return fail("date", &format!("invalid epoch: {v}")),
            }
        } else if let Some(f) = a.strip_prefix('+') {
            fmt = Some(f.to_string());
        } else if a.starts_with('-') && a.len() > 1 {
            return usage("date", &format!("unsupported option: {a}"));
        } else {
            return usage("date", "unexpected operand");
        }
        i += 1;
    }
    let secs: i64 = match fixed {
        Some(n) => n,
        None => match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs() as i64,
            Err(_) => return fail("date", "system clock before the epoch"),
        },
    };
    match fmt {
        Some(f) => println!("{}", fmt_civil(&f, secs)),
        None => println!("{}", fmt_civil("%Y-%m-%dT%H:%M:%S+0000", secs)),
    }
    EXIT_OK
}

// -------------------------------------------------------------- whoami ----

/// Resolve a username from a /proc/self/status snapshot and an
/// /etc/passwd snapshot. Returns None when the uid has no passwd entry;
/// the caller then prints the numeric uid. Pure and unit-testable.
pub fn username_from_status(status: &str, passwd: &str) -> Option<String> {
    let uid_line = status.lines().find(|l| l.starts_with("Uid:"))?;
    let real_uid = uid_line.split(':').nth(1)?.split_whitespace().next()?.to_string();
    for entry in passwd.lines() {
        let fields: Vec<&str> = entry.split(':').collect();
        if fields.len() >= 3 && fields[2] == real_uid {
            return Some(fields[0].to_string());
        }
    }
    None
}

/// whoami: the effective username (numeric uid as fallback).
pub fn whoami(_argv: &[String]) -> i32 {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let passwd = fs::read_to_string("/etc/passwd").unwrap_or_default();
    match username_from_status(&status, &passwd) {
        Some(name) => {
            println!("{name}");
            EXIT_OK
        }
        None => {
            let uid_line = status.lines().find(|l| l.starts_with("Uid:")).unwrap_or("");
            let uid = uid_line
                .split(':')
                .nth(1)
                .and_then(|r| r.split_whitespace().next())
                .unwrap_or("unknown");
            println!("{uid}");
            EXIT_OK
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whoami_resolves_real_uid() {
        let status = "Name:\tls\nUid:\t1000\t1000\t1000\t1000\n";
        let passwd = "root:x:0:0:root:/root:/bin/sh\namelia:x:1000:1000::/home/amelia:/bin/sh\n";
        assert_eq!(username_from_status(status, passwd).as_deref(), Some("amelia"));
    }

    #[test]
    fn whoami_falls_back_when_uid_has_no_entry() {
        let status = "Name:\tsh\nUid:\t65534\t65534\t65534\t65534\n";
        let passwd = "root:x:0:0:root:/root:/bin/sh\n";
        assert_eq!(username_from_status(status, passwd), None);
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90").unwrap(), 90.0);
        assert_eq!(parse_duration("2m").unwrap(), 120.0);
        assert_eq!(parse_duration("1.5h").unwrap(), 5400.0);
        assert!(parse_duration("-3").is_err());
        assert!(parse_duration("abc").is_err());
    }

    #[test]
    fn id_parsing() {
        let (uid, gid, groups) = parse_ids(
            "Uid:\t1000\t1000\t1000\t1000\nGid:\t100\t100\t100\t100\nGroups:\t24,27,1000\n",
        );
        assert_eq!(uid, 1000);
        assert_eq!(gid, 100);
        assert_eq!(groups, vec![24, 27, 1000]);
    }

    #[test]
    fn epoch_civil() {
        let c = civil_from_unix(0);
        assert_eq!((c.year, c.month, c.day), (1970, 1, 1));
        assert_eq!(c.weekday, 4); // Thursday
        let c = civil_from_unix(86_399);
        assert_eq!((c.hour, c.min, c.sec), (23, 59, 59));
        let c = civil_from_unix(1_709_164_800);
        assert_eq!((c.year, c.month, c.day), (2024, 2, 29));
        let c = civil_from_unix(-1);
        assert_eq!((c.year, c.month, c.day), (1969, 12, 31));
        assert_eq!(c.weekday, 3); // Wednesday
    }

    #[test]
    fn date_formatting() {
        assert_eq!(fmt_civil("%Y-%m-%d", 0), "1970-01-01");
        assert_eq!(fmt_civil("%H:%M:%S", 86_399), "23:59:59");
        assert_eq!(fmt_civil("%a %b %e", 0), "Thu Jan  1");
        assert_eq!(fmt_civil("%s%%", 5), "5%");
        assert_eq!(fmt_mtime(1_709_164_800), "2024-02-29 00:00");
    }

    #[test]
    fn true_false_statuses() {
        assert_eq!(r#true(&args(&[])), 0);
        assert_eq!(r#false(&args(&[])), 1);
    }
}
