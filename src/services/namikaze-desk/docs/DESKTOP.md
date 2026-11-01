# NamikazeOS desktop: the Niri Wayland session

v3.0.0 ships exactly one graphical session: niri, a scrollable-tiling
Wayland compositor written in Rust. This document maps the session stack,
the generated files, the keybinds and the troubleshooting path.

## Why niri

- Rust codebase, matching the NamikazeOS Rust Edition toolchain story.
- Scrollable-tiling model: columns live on an endless horizontal strip, so
  there is no floating-window state to manage or leak.
- Strict Wayland core; X11 apps run only through the built-in
  xwayland-satellite integration, on demand, per application.
- Small config surface; every value the session needs is rendered by
  namikaze-desk from one structured default set.

## Session stack

| Role          | Component                             | Package                              |
|---------------|---------------------------------------|--------------------------------------|
| Compositor    | niri                                  | gui-wm/niri                          |
| Session entry | namikaze-session                      | sys-namikaze/namikaze-desk           |
| Greeter       | agreety (greetd)                      | gui-apps/greetd                      |
| Terminal      | foot                                  | gui-apps/foot                        |
| Launcher      | fuzzel                                | gui-apps/fuzzel                      |
| Bar           | waybar (niri/workspaces, niri/window) | gui-apps/waybar                      |
| Notifications | mako                                  | gui-apps/mako                        |
| Lock / idle   | swaylock + swayidle                   | gui-apps/swaylock, gui-apps/swayidle |
| Screenshots   | niri screenshot actions + grim/slurp  | gui-apps/grim, gui-apps/slurp        |
| Portals       | xdg-desktop-portal-gtk + -gnome       | gui-libs/xdg-desktop-portal-gtk/gnome|
| Clipboard     | wl-copy / wl-paste                    | gui-apps/wl-clipboard                |
| Audio         | pipewire + wireplumber (wpctl)        | media-sound/pipewire, wireplumber    |
| Backlight     | brightnessctl                         | sys-power/brightnessctl              |

## Bootstrap chain

OpenRC default runlevel -> greetd (vt 7, PAM: faillock + namikaze-sentinel)
-> agreety -> /usr/bin/namikaze-session (exports the Wayland environment,
creates ~/.config and ~/Pictures/Screenshots) -> dbus-run-session -> niri.

Autologin (single-user kiosk mode): set [desktop].autologin = true in
/etc/namikaze/system.toml and switch /etc/greetd/config.toml to the
[initial_session] variant (see `namikaze-desk print greetd` for the shape;
the crate test documents both modes).

## Generated files

`namikaze-desk apply "$HOME"` writes all per-user artifacts:

| Path                                      | Purpose                                    |
|-------------------------------------------|--------------------------------------------|
| ~/.config/niri/config.kdl                 | compositor: input, layout, focus-ring, binds |
| ~/.config/waybar/config.json              | bar layout with niri modules               |
| ~/.config/waybar/style.css                | bar theme                                  |
| ~/.config/fuzzel/fuzzel.ini               | launcher                                   |
| ~/.config/mako/config                     | notifications                              |
| ~/.config/foot/foot.ini                   | terminal                                   |
| ~/.config/xdg-desktop-portal/portals.conf | portal routing (gtk default, gnome cast)   |

System-side files: /etc/greetd/config.toml, /usr/bin/namikaze-session,
/etc/init.d/namikaze-desk (applies the set to /etc/skel and /root once per
boot), /etc/init.d/greetd (greeter daemon on vt 7, elogind-backed seats) and
the PAM chains /etc/pam.d/greetd (faillock + optional sentinel + unix) and
/etc/pam.d/swaylock (screen unlock). For an existing user run:

    namikaze-desk apply "$HOME"

## Keybinds (Mod = Super)

| Keys                              | Action                              |
|-----------------------------------|-------------------------------------|
| Mod+Return, Mod+T                 | terminal (foot)                     |
| Mod+D                             | launcher (fuzzel)                   |
| Mod+Q                             | close window                        |
| Mod+F                             | fullscreen window                   |
| Mod+C                             | center column                       |
| Mod+V                             | toggle floating                     |
| Mod+Shift+E                       | quit session                        |
| Mod+Shift+L                       | lock screen (swaylock -f)           |
| Mod+arrows, Mod+H, Mod+L          | focus column / window               |
| Mod+Ctrl+arrows                   | move column / window                |
| Mod+Page Up / Page Down           | focus workspace up / down           |
| Mod+Ctrl+Page Up / Page Down      | move workspace up / down            |
| Mod+Shift+Page Up / Page Down     | move column to workspace up / down  |
| Mod+1 .. Mod+9                    | focus workspace N                   |
| Mod+Shift+1 .. Mod+Shift+9        | move column to workspace N          |
| Mod+Minus / Equal / Shift+Equal   | column width -10% / +10% / 100%     |
| Print / Ctrl+Print / Alt+Print    | screen / region / window screenshot |
| XF86 audio keys                   | wpctl volume and mute               |
| XF86 brightness keys              | brightnessctl backlight step        |

The table is plain data (key_binds() in namikaze-desk); every action is
checked against a fixed allowlist by unit tests, so a niri action rename
breaks the build, never the session.

## Privacy defaults

- machine-id is ephemeral and the hostname is random per boot ([privacy]).
- No telemetry, no crash reporter; portals are limited to the gtk/gnome
  pair and mako renders text only (icons=0).
- Wayland hard-isolates clients: no screen capture without the portal, no
  global hotkey sniffing, no cross-client input injection.
- fuzzel runs with icons=no so application lists stay text-only.

## Troubleshooting

- Config syntax: niri validate -c ~/.config/niri/config.kdl
- Live state: niri msg windows, niri msg outputs, niri msg workspaces
- Session binaries: namikaze-desk doctor (exit 1 when something is missing)
- rc-service namikaze-desk status re-runs the skel render; logger tag
  namikaze-desk carries the service output.
- Keyboard layout: set kb_layout in [desktop] (xkb layout string, e.g. "tr")
  and re-run namikaze-desk apply "$HOME".
