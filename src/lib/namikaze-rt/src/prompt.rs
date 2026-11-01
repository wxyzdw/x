// SPDX-License-Identifier: MPL-2.0
//! Terminal prompts for non-secret input. Passphrases are handled by
//! `namikaze-ffi::read_password` (raw terminal control); everything here is
//! plain line-based interaction that never panics on EOF.

use std::io::{BufRead, Write};

/// Ask a free-form question; returns the trimmed answer (empty on EOF).
pub fn ask(prompt: &str) -> String {
    print!("{prompt} ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let stdin = std::io::stdin();
    let mut lock = stdin.lock();
    match lock.read_line(&mut line) {
        Ok(0) => String::new(),
        Ok(_) => line.trim().to_string(),
        Err(_) => String::new(),
    }
}

/// Yes/no confirmation. `default` applies to a bare Enter. EOF returns the
/// default so scripted first-boot runs do not hang.
pub fn confirm(prompt: &str, default: bool) -> bool {
    let hint = if default { "[Y/n]" } else { "[y/N]" };
    let answer = ask(&format!("{prompt} {hint}"));
    match answer.to_ascii_lowercase().as_str() {
        "" => default,
        "y" | "yes" => true,
        "n" | "no" => false,
        _ => default,
    }
}

/// Choose one option from a numbered list. Returns the selected index.
pub fn choose(prompt: &str, options: &[&str], default: usize) -> usize {
    for (i, o) in options.iter().enumerate() {
        let marker = if i == default { ">" } else { " " };
        println!("  {marker} {i}) {o}");
    }
    loop {
        let raw = ask(&format!("{prompt} [{default}]"));
        if raw.is_empty() {
            return default;
        }
        if let Ok(i) = raw.parse::<usize>() {
            if i < options.len() {
                return i;
            }
        }
        println!("  please enter a number between 0 and {}", options.len() - 1);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn module_compiles_and_links() {
        // The interactive functions need a TTY; CI only asserts linkage.
        let _ = super::ask;
        let _ = super::confirm;
        let _ = super::choose;
    }
}
