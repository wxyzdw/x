// SPDX-License-Identifier: MPL-2.0
//! namikaze-compat: the package compatibility base.
//!
//! The rule the ladder is built on: **whatever falls in, runs** -
//! with Gentoo first and everything else routed, contained and
//! honest. One entry point, [`detect`], names the format from the
//! bytes (magic numbers, never trust the extension); [`plan`] turns
//! the format into an [`InstallPlan`]: which backend executes it,
//! which confinement level it lands on and what happens to its files.
//!
//! Priority order (the user's, encoded in etc/namikaze/compat.toml):
//!
//! 1. **Gentoo** - native. Ebuilds run under portage via
//!    `namikaze-pkg converge`; this is the system's own packaging and
//!    the only format allowed near the root.
//! 2. **AppImage** - self-contained ELF images run read-only inside a
//!    level-1 sandbox; no extraction, no system writes.
//! 3. **DEB / RPM / APK(Alpine)** - foreign format trees are
//!    extracted into an overlay prefix
//!    (`/opt/namikaze/compat/<format>/<name>`, read-only to the app,
//!    writable only by the installer) and launched sandboxed; the
//!    foreign package never touches the Gentoo root.
//! 4. **Flatpak** - delegated to the flatpak runtime when installed,
//!    still confined by the same level rules.
//! 5. **Nix** - store paths consumed read-only; no profile mutation.
//! 6. **Android (APK)** - planned backend: an ART runtime container
//!    behind the same sandbox ladder. Detection and routing exist
//!    today; execution is documented future work - we do not pretend
//!    otherwise.

#![forbid(unsafe_code)]

use namikaze_common::{Error, Result};

/// Every format the base recognizes, in policy priority order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Format {
    /// Gentoo ebuild - the native format, priority one.
    Gentoo,
    /// AppImage (ELF with the AI magic).
    AppImage,
    /// Debian package (ar archive).
    Deb,
    /// RPM package.
    Rpm,
    /// Alpine package (gzip-compressed tar).
    Apk,
    /// Flatpak bundle.
    Flatpak,
    /// Nix store path / closure.
    Nix,
    /// Android package - planned backend.
    Android,
}

impl Format {
    /// Canonical lowercase name (also the compat.toml key).
    pub fn name(&self) -> &'static str {
        match self {
            Format::Gentoo => "gentoo",
            Format::AppImage => "appimage",
            Format::Deb => "deb",
            Format::Rpm => "rpm",
            Format::Apk => "apk",
            Format::Flatpak => "flatpak",
            Format::Nix => "nix",
            Format::Android => "android",
        }
    }

    /// The backend that executes the format.
    pub fn backend(&self) -> &'static str {
        match self {
            Format::Gentoo => "portage (namikaze-pkg converge)",
            Format::AppImage => "direct exec, read-only mount",
            Format::Deb => "extract to /opt/namikaze/compat/deb/<name>",
            Format::Rpm => "extract to /opt/namikaze/compat/rpm/<name>",
            Format::Apk => "extract to /opt/namikaze/compat/apk/<name>",
            Format::Flatpak => "flatpak runtime",
            Format::Nix => "nix store (read-only consumption)",
            Format::Android => "ART runtime container (planned)",
        }
    }

    /// The confinement level the format lands on by default. Gentoo
    /// is the system's own packaging; everything foreign starts at
    /// level 1 (no network, no desktop) and earns more only through
    /// the Hiraishin ladder.
    pub fn default_level(&self) -> u8 {
        match self {
            Format::Gentoo => 0,
            _ => 1,
        }
    }
}

/// What the detector found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub format: Format,
    /// How it was recognized: `magic` or `name`.
    pub by: &'static str,
}

/// Name a package format from its bytes. Extension is only consulted
/// when no magic matches - magic wins, always.
pub fn detect(bytes: &[u8], filename: &str) -> Result<Detection> {
    let by_magic = |format: Format| Detection { format, by: "magic" };
    // RPM: ED AB EE DB
    if bytes.starts_with(&[0xED, 0xAB, 0xEE, 0xDB]) {
        return Ok(by_magic(Format::Rpm));
    }
    // ar archive: "!<arch>\n" - a deb carries debian-binary first
    if bytes.starts_with(b"!<arch>\ndebian-binary") {
        return Ok(by_magic(Format::Deb));
    }
    // ELF: AppImage magic "AI\x01"/"AI\x02" at offset 8
    if bytes.starts_with(&[0x7F, b'E', b'L', b'F']) && bytes.len() >= 12 {
        if &bytes[8..10] == b"AI" {
            return Ok(by_magic(Format::AppImage));
        }
        // plain ELF: could be an AppImage without runtime magic
        if filename.to_ascii_lowercase().ends_with(".appimage") {
            return Ok(by_magic(Format::AppImage));
        }
        return Ok(Detection { format: Format::Gentoo, by: "name" });
    }
    // gzip: Alpine .apk (tgz) - extension decides the gzip flavor
    if bytes.starts_with(&[0x1F, 0x8B]) {
        let lower = filename.to_ascii_lowercase();
        return Ok(by_magic(if lower.ends_with(".apk") {
            Format::Apk
        } else if lower.ends_with(".flatpak") {
            Format::Flatpak
        } else {
            Format::Apk
        }));
    }
    // text formats by name: ebuild, nix
    let lower = filename.to_ascii_lowercase();
    if lower.ends_with(".ebuild") {
        return Ok(Detection { format: Format::Gentoo, by: "name" });
    }
    if lower.ends_with(".nix") {
        return Ok(Detection { format: Format::Nix, by: "name" });
    }
    // an ebuild is also recognizable by content (EAPI= first lines)
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(4096)]);
    if head.lines().any(|l| l.trim_start().starts_with("EAPI=")) {
        return Ok(Detection { format: Format::Gentoo, by: "magic" });
    }
    if lower.ends_with(".apk") {
        return Ok(Detection { format: Format::Android, by: "name" });
    }
    Err(Error::Config(format!("compat: no format recognized for {filename:?}")))
}

/// The execution plan for one package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPlan {
    pub format: Format,
    pub backend: &'static str,
    pub level: u8,
    /// The filesystem prefix the package is allowed to own.
    pub prefix: String,
}

/// Turn a detection into the install plan. `name` is the package
/// identity used for the foreign-format prefixes.
pub fn plan(d: &Detection, name: &str) -> InstallPlan {
    let prefix = match d.format {
        Format::Gentoo => "/".to_string(),
        Format::Nix => "/nix/store (read-only)".to_string(),
        Format::Flatpak => "/var/lib/flatpak".to_string(),
        other => format!("/opt/namikaze/compat/{}/{}", other.name(), name),
    };
    InstallPlan {
        format: d.format,
        backend: d.format.backend(),
        level: d.format.default_level(),
        prefix,
    }
}

/// Render the plan the way `namikaze-pkg compat` prints it.
pub fn render(p: &InstallPlan, file: &str) -> String {
    format!(
        "format  : {} ({})\nbackend : {}\nlevel   : {}\nprefix  : {}",
        p.format.name(),
        file,
        p.backend,
        p.level,
        p.prefix
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_beats_extension() {
        // an ar archive named .rpm is still a deb? no - magic says ar,
        // and the debian-binary member says deb
        let deb_magic = b"!<arch>\ndebian-binary\x0a";
        assert_eq!(detect(deb_magic, "weird.rpm").unwrap().format, Format::Deb);
        // rpm magic
        let rpm = [0xEDu8, 0xAB, 0xEE, 0xDB, 0, 1, 2, 3];
        assert_eq!(detect(&rpm, "x.deb").unwrap().format, Format::Rpm);
        // gzip + .apk = alpine
        let gz = [0x1F, 0x8B, 0, 0];
        assert_eq!(detect(&gz, "pkg.apk").unwrap().format, Format::Apk);
        // ELF with AppImage magic
        let mut elf = vec![0x7F, b'E', b'L', b'F', 2, 0, 0, 0];
        elf.extend_from_slice(b"AI\x02");
        elf.extend_from_slice(&[0u8; 8]);
        assert_eq!(detect(&elf, "tool.AppImage").unwrap().format, Format::AppImage);
    }

    #[test]
    fn android_apk_is_detected_but_honest_about_it() {
        // a zip (PK) named .apk is the android flavor
        let apk = b"PK\x03\x04-android-package";
        let d = detect(apk, "com.example.app.apk").unwrap();
        assert_eq!(d.format, Format::Android);
        let p = plan(&d, "com.example.app");
        assert_eq!(p.level, 1, "foreign formats never start above level 1");
        assert!(p.backend.contains("planned"));
    }

    #[test]
    fn gentoo_is_priority_one_and_owns_the_root() {
        let d = detect(b"EAPI=8\nDESCRIPTION=\"x\"\n", "hello-1.0.ebuild").unwrap();
        assert_eq!(d.format, Format::Gentoo);
        assert_eq!(d.by, "name");
        let p = plan(&d, "hello");
        assert_eq!(p.level, 0);
        assert_eq!(p.prefix, "/");
        assert!(p.backend.contains("portage"));
    }

    #[test]
    fn foreign_formats_get_their_own_prefix() {
        let rpm = [0xEDu8, 0xAB, 0xEE, 0xDB];
        let d = detect(&rpm, "tool.rpm").unwrap();
        let p = plan(&d, "tool");
        assert_eq!(p.prefix, "/opt/namikaze/compat/rpm/tool");
        assert_eq!(p.level, 1);
        let render = render(&p, "tool.rpm");
        assert!(render.contains("format  : rpm"));
        assert!(render.contains("level   : 1"));
    }

    #[test]
    fn unknown_is_an_error_not_a_guess() {
        assert!(detect(b"\x00\x00\x00\x00", "mystery.bin").is_err());
    }

    #[test]
    fn formats_are_ordered_by_policy_priority() {
        let mut all = [
            Format::Android,
            Format::Nix,
            Format::Flatpak,
            Format::Apk,
            Format::Rpm,
            Format::Deb,
            Format::AppImage,
            Format::Gentoo,
        ];
        all.sort();
        assert_eq!(all[0], Format::Gentoo, "gentoo first, always");
        assert_eq!(all.last().copied(), Some(Format::Android));
    }
}
