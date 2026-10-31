// SPDX-License-Identifier: MPL-2.0
//! The tiny command line parser shared by every NamikazeOS binary.
//!
//! Deliberately minimal: subcommands, `--flag`, `--opt value`,
//! `--opt=value`, free arguments and `-h/--help`. Each binary keeps its own
//! help text next to its dispatch, which keeps `--help` honest and greppable.

/// Parsed command line for one invocation.
#[derive(Debug, Clone, Default)]
pub struct Cli {
    raw: Vec<String>,
}

impl Cli {
    /// Capture argv (excluding argv[0]). Prints help and exits when the
    /// user asked for `-h`/`--help` and `about` is provided.
    pub fn capture() -> Cli {
        Cli { raw: std::env::args().skip(1).collect() }
    }

    /// True when the user passed `-h` or `--help`.
    pub fn wants_help(&self) -> bool {
        self.raw.iter().any(|a| a == "-h" || a == "--help")
    }

    /// The first free argument, interpreted as the subcommand.
    pub fn sub(&self) -> Option<&str> {
        self.raw.first().map(|s| s.as_str())
    }

    /// All arguments except the leading subcommand.
    pub fn tail(&self) -> &[String] {
        self.raw.get(1..).unwrap_or(&[])
    }

    /// True when `--name` (or `-name`) is present.
    pub fn flag(&self, name: &str) -> bool {
        let long = format!("--{name}");
        let short = format!("-{name}");
        self.raw.iter().any(|a| a == &long || a == &short)
    }

    /// Value of the last `--name value` / `--name=value` occurrence.
    pub fn value(&self, name: &str) -> Option<String> {
        let long = format!("--{name}");
        let mut it = self.raw.iter();
        while let Some(a) = it.next() {
            if let Some(rest) = a.strip_prefix(&format!("{long}=")) {
                return Some(rest.to_string());
            }
            if a == &long {
                return it.next().cloned();
            }
        }
        None
    }

    /// Value of `--name` or the provided default.
    pub fn value_or(&self, name: &str, default: &str) -> String {
        self.value(name).unwrap_or_else(|| default.to_string())
    }

    /// Parse `--name` as an unsigned integer with a friendly error.
    pub fn value_parse<T: std::str::FromStr>(&self, name: &str) -> crate::Result<Option<T>> {
        match self.value(name) {
            None => Ok(None),
            Some(v) => v
                .parse::<T>()
                .map(Some)
                .map_err(|_| crate::Error::Invalid(format!("--{name}: cannot parse {v:?}"))),
        }
    }

    /// Free (non-flag) arguments after the subcommand, in order. The caller
    /// names the options that consume a value (`["port", "out"]`); every
    /// other `--flag` is boolean and must not eat the next token.
    pub fn free(&self, value_opts: &[&str]) -> Vec<String> {
        let mut out = Vec::new();
        let mut skip_value = false;
        for a in &self.raw {
            if skip_value {
                skip_value = false;
                continue;
            }
            if a == "--" {
                continue;
            }
            if let Some(long) = a.strip_prefix("--") {
                let name = long.split('=').next().unwrap_or(long);
                if !a.contains('=') && value_opts.contains(&name) {
                    skip_value = true;
                }
                continue;
            }
            if a.starts_with('-') && a.len() > 1 {
                continue;
            }
            out.push(a.clone());
        }
        out
    }

    /// Free arguments after the first (the subcommand itself).
    pub fn free_after_sub(&self, value_opts: &[&str]) -> Vec<String> {
        self.free(value_opts).into_iter().skip(1).collect()
    }

    /// Print a usage block to stderr and exit with EX_USAGE (64).
    pub fn usage_exit(&self, lines: &[&str]) -> ! {
        for l in lines {
            eprintln!("{l}");
        }
        std::process::exit(64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(args: &[&str]) -> Cli {
        Cli { raw: args.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn sub_flag_value() {
        let c = cli(&["apply", "--json", "--port", "8080", "--out=/tmp/x", "extra"]);
        assert_eq!(c.sub(), Some("apply"));
        assert!(c.flag("json"));
        assert_eq!(c.value("port").as_deref(), Some("8080"));
        assert_eq!(c.value("out").as_deref(), Some("/tmp/x"));
        let vo = ["port", "out"];
        assert_eq!(c.free(&vo), vec!["apply", "extra"]);
        assert_eq!(c.free_after_sub(&vo), vec!["extra"]);
    }

    #[test]
    fn missing_values() {
        let c = cli(&["run"]);
        assert!(c.value("port").is_none());
        assert!(!c.flag("json"));
        assert!(c.value_parse::<u16>("port").unwrap().is_none());
        let bad = cli(&["run", "--port", "xx"]);
        assert!(bad.value_parse::<u16>("port").is_err());
        assert_eq!(c.free(&["port"]), vec!["run"]);
    }
}
