// SPDX-License-Identifier: MPL-2.0
#![forbid(unsafe_code)]
//! Process and kernel tools: dmesg, free, ps, kill.
//!
//! All data comes from /proc and /dev/kmsg; parsing is factored into pure
//! functions so the shapes are unit-tested even where the source files are
//! machine-specific.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};

use crate::{fail, usage, EXIT_OK};

// ---------------------------------------------------------------- dmesg ----

/// Render one kernel log record ("lvl,seq,usec;message") in kernel style.
fn format_record(line: &str) -> Option<String> {
    let (meta, msg) = line.split_once(';')?;
    let mut fields = meta.split(',');
    let _level = fields.next()?;
    let _seq = fields.next()?;
    let usec: u64 = fields.next()?.parse().ok()?;
    let ts = usec as f64 / 1_000_000.0;
    Some(format!("[{:>12.6}] {}", ts, msg.trim_end()))
}

/// dmesg: print the kernel ring buffer backlog (non-blocking poll on
/// /dev/kmsg; the reader exits once the backlog is drained).
pub fn dmesg(argv: &[String]) -> i32 {
    for a in argv {
        if a.starts_with('-') && a.len() > 1 {
            return usage("dmesg", &format!("unsupported option: {a}"));
        }
    }
    let file = match fs::File::open("/dev/kmsg") {
        Ok(f) => f,
        Err(e) => return fail("dmesg", &format!("cannot open /dev/kmsg: {e}")),
    };
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut code = EXIT_OK;
    let mut buf = [0u8; 8192];
    loop {
        match (&file).read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let text = String::from_utf8_lossy(&buf[..n]);
                for line in text.lines() {
                    if let Some(rendered) = format_record(line) {
                        let _ = out.write_all(rendered.as_bytes());
                        let _ = out.write_all(b"\n");
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => {
                code = fail("dmesg", &format!("read: {e}"));
                break;
            }
        }
    }
    let _ = out.flush();
    code
}

// ----------------------------------------------------------------- free ----

fn parse_meminfo(text: &str) -> BTreeMap<String, u64> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(':') else { continue };
        let val = rest
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<u64>().ok());
        if let Some(v) = val {
            map.insert(key.trim().to_string(), v);
        }
    }
    map
}

/// Human-readable kibibyte count (free -h style, always UTC-free, fixed).
fn human_kib(kib: u64) -> String {
    const UNITS: [&str; 4] = ["Ki", "Mi", "Gi", "Ti"];
    let mut v = kib as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    format!("{:.1}{}", v, UNITS[unit])
}

fn render_free(map: &BTreeMap<String, u64>, flag: char) -> String {
    let total = *map.get("MemTotal").unwrap_or(&0);
    let available = map.get("MemAvailable").copied();
    let free = *map.get("MemFree").unwrap_or(&0);
    let buffers = *map.get("Buffers").unwrap_or(&0);
    let cached = *map.get("Cached").unwrap_or(&0);
    let sreclaim = map.get("SReclaimable").copied().unwrap_or(0);
    let shared = *map.get("Shmem").unwrap_or(&0);
    let used = match available {
        Some(a) => total.saturating_sub(a),
        None => total.saturating_sub(free + buffers + cached),
    };
    let buff_cache = buffers + cached + sreclaim - shared;
    let avail = available.unwrap_or(free + buffers + cached);

    let scale = |v: u64| -> String {
        match flag {
            'h' => human_kib(v),
            'b' => format!("{}", v * 1024),
            'm' => format!("{}", v / 1024),
            'g' => format!("{}", v / (1024 * 1024)),
            _ => format!("{v}"),
        }
    };
    let row = |label: &str, vals: [u64; 5]| -> String {
        format!(
            "{label}: {:>10} {:>12} {:>12} {:>12} {:>12}\n",
            scale(vals[0]),
            scale(vals[1]),
            scale(vals[2]),
            scale(vals[3]),
            scale(vals[4])
        )
    };
    let mut out = String::new();
    out.push_str("               total        used        free      shared  buff/cache   available\n");
    out.push_str(&row("Mem", [total, used, free, shared, buff_cache]));
    out.push_str(&row("Swap", [0, 0, 0, 0, 0]));
    out.push_str(&format!("(available: {})\n", scale(avail)));
    out
}

/// free: report memory usage from /proc/meminfo; -b -k -m -g -h.
pub fn free(argv: &[String]) -> i32 {
    let mut flag = 'k';
    for a in argv {
        let flags = a.strip_prefix('-').unwrap_or("");
        if a == "--" {
            continue;
        }
        if a.starts_with('-') && a.len() > 1 && flags.chars().all(|c| "bkmgh".contains(c)) {
            if let Some(c) = flags.chars().last() {
                flag = c;
            }
        } else {
            return usage("free", &format!("unsupported option: {a}"));
        }
    }
    let text = match fs::read_to_string("/proc/meminfo") {
        Ok(t) => t,
        Err(e) => return fail("free", &format!("cannot read /proc/meminfo: {e}")),
    };
    let map = parse_meminfo(&text);
    print!("{}", render_free(&map, flag));
    EXIT_OK
}

// ------------------------------------------------------------------- ps ----

/// Parse /proc/PID/stat into (comm, state, ppid).
fn parse_stat(text: &str) -> Option<(String, char, u32)> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    let comm = text[open + 1..close].to_string();
    let rest = text[close + 1..].split_whitespace().collect::<Vec<_>>();
    let state = rest.first()?.chars().next()?;
    let ppid: u32 = rest.get(1)?.parse().ok()?;
    Some((comm, state, ppid))
}

/// Extract VmRSS (kB) from /proc/PID/status, if present.
fn parse_status_rss(text: &str) -> Option<u64> {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn pid_digits(name: &str) -> Option<u32> {
    if !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()) {
        name.parse().ok()
    } else {
        None
    }
}

/// ps: snapshot of all processes: PID, PPID, state, RSS and command.
pub fn ps(argv: &[String]) -> i32 {
    for a in argv {
        let flags = a.strip_prefix('-').unwrap_or("");
        if a == "--" {
            continue;
        }
        if a.starts_with('-') && a.len() > 1 && flags.chars().all(|c| "efaux".contains(c)) {
            // accepted: we always snapshot every process
        } else {
            return usage("ps", &format!("unsupported option: {a}"));
        }
    }
    let mut rows: Vec<(u32, u32, char, u64, String)> = Vec::new();
    let entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(e) => return fail("ps", &format!("cannot read /proc: {e}")),
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(pid) = pid_digits(&name) else { continue };
        let stat_text = match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(t) => t,
            Err(_) => continue, // process exited during the scan
        };
        let Some((comm, state, ppid)) = parse_stat(&stat_text) else { continue };
        let rss = fs::read_to_string(format!("/proc/{pid}/status"))
            .as_deref()
            .ok()
            .and_then(parse_status_rss)
            .unwrap_or(0);
        let cmd = match fs::read(format!("/proc/{pid}/cmdline")) {
            Ok(bytes) if !bytes.is_empty() => bytes
                .split(|&b| b == 0)
                .filter(|p| !p.is_empty())
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .collect::<Vec<_>>()
                .join(" "),
            _ => format!("[{comm}]"),
        };
        rows.push((pid, ppid, state, rss, cmd));
    }
    rows.sort_by_key(|r| r.0);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let _ = writeln!(out, "    PID    PPID S     RSS COMMAND");
    for (pid, ppid, state, rss, cmd) in rows {
        let _ = writeln!(out, "{pid:>6} {ppid:>6} {state} {rss:>6} {cmd}");
    }
    let _ = out.flush();
    EXIT_OK
}

// ----------------------------------------------------------------- kill ----

/// POSIX signal names indexed by number (index 0 unused).
const SIGNALS: [&str; 32] = [
    "", "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL", "USR1", "SEGV",
    "USR2", "PIPE", "ALRM", "TERM", "STKFLT", "CHLD", "CONT", "STOP", "TSTP", "TTIN", "TTOU",
    "URG", "XCPU", "XFSZ", "VTALRM", "PROF", "WINCH", "IO", "PWR", "SYS",
];

fn signal_number(name: &str) -> Option<i32> {
    let upper = name.trim_start_matches("SIG").to_ascii_uppercase();
    (1..32).find(|&n| SIGNALS[n] == upper).map(|n| n as i32)
}

/// kill: send a signal (default TERM) or list signals with -l.
pub fn kill(argv: &[String]) -> i32 {
    let mut sig: i32 = 15;
    let mut list = false;
    let mut pids: Vec<u32> = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "-l" {
            list = true;
        } else if a == "-s" {
            i += 1;
            let Some(name) = argv.get(i) else { return usage("kill", "-s needs a signal") };
            match signal_number(name).or_else(|| name.parse().ok()) {
                Some(n) if (1..32).contains(&n) => sig = n,
                _ => return fail("kill", &format!("unknown signal: {name}")),
            }
        } else if a.starts_with('-') && a.len() > 1 && !pids.is_empty() {
            return usage("kill", "signals must precede pids");
        } else if a.starts_with('-') && a.len() > 1 && a != "--" {
            match signal_number(&a[1..]).or_else(|| a[1..].parse().ok()) {
                Some(n) if (1..32).contains(&n) => sig = n,
                _ => return usage("kill", &format!("unknown signal: {a}")),
            }
        } else if a == "--" {
        } else {
            match a.parse::<u32>() {
                Ok(pid) => pids.push(pid),
                Err(_) => return usage("kill", &format!("not a pid: {a}")),
            }
        }
        i += 1;
    }
    if list {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        if let Some(one) = pids.first() {
            let name = SIGNALS.get(*one as usize).copied().unwrap_or("");
            let _ = writeln!(out, "{name}");
        } else {
            for n in 1..32 {
                let _ = write!(out, "{:>8}", SIGNALS[n]);
                if n % 8 == 0 {
                    let _ = writeln!(out);
                }
            }
            let _ = writeln!(out);
        }
        return EXIT_OK;
    }
    if pids.is_empty() {
        return usage("kill", "missing pid");
    }
    let mut code = EXIT_OK;
    for pid in pids {
        if let Err(e) = namikaze_ffi::kill_signal(pid as i32, sig) {
            code = fail("kill", &format!("({sig}) {pid}: {e}"));
        }
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kmsg_records() {
        assert_eq!(
            format_record("6,120,9513017;- ccid4 4-1: device not present\n"),
            Some(String::from("[    9.513017] - ccid4 4-1: device not present"))
        );
        assert_eq!(format_record("garbage"), None);
        assert_eq!(format_record("6,1,1;booted"), Some(String::from("[    0.000001] booted")));
    }

    #[test]
    fn meminfo_parsing() {
        let text = "MemTotal:       16094236 kB\nMemFree:         8422100 kB\n\
                    MemAvailable:   12000324 kB\nBuffers:          212344 kB\nCached:          3120004 kB\n\
                    SwapTotal:             0 kB\n";
        let map = parse_meminfo(text);
        assert_eq!(map.get("MemTotal"), Some(&16_094_236));
        assert_eq!(map.get("MemAvailable"), Some(&12_000_324));
        let rendered = render_free(&map, 'k');
        assert!(rendered.contains("Mem"));
        assert!(rendered.contains("16094236"));
    }

    #[test]
    fn human_units() {
        assert_eq!(human_kib(500), "500.0Ki");
        assert_eq!(human_kib(2048), "2.0Mi");
        assert_eq!(human_kib(1024 * 1024 * 3), "3.0Gi");
    }

    #[test]
    fn stat_and_status() {
        let text = "1234 (systemd-u) S 1 1234 1234 0 -1 4194560 ... 0 0 0 0 100 50 0 0 20 0 1 0 999999 1234567 8901";
        let (comm, state, ppid) = parse_stat(text).unwrap();
        assert_eq!(comm, "systemd-u");
        assert_eq!(state, 'S');
        assert_eq!(ppid, 1);
        assert_eq!(parse_status_rss("Name:\tx\nVmRSS:\t     1234 kB\n"), Some(1234));
        assert_eq!(parse_status_rss("Name:\tx\n"), None);
        assert_eq!(pid_digits("999"), Some(999));
        assert_eq!(pid_digits("acpi"), None);
    }

    #[test]
    fn signal_tables() {
        assert_eq!(signal_number("TERM"), Some(15));
        assert_eq!(signal_number("SIGKILL"), Some(9));
        assert_eq!(signal_number("hup"), Some(1));
        assert_eq!(signal_number("BOGUS"), None);
        assert!(signal_number("KILL").is_some());
        assert!(signal_number("NOPE").is_none());
    }
}
