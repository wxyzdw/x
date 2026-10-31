# Distributed under the terms of the Mozilla Public License v2.0
# Maintained by `cargo xtask ebuilds` from the sector layout.

EAPI=8

DESCRIPTION="Niri Wayland session factory (config renderer and doctor)"
HOMEPAGE="https://github.com/wxyzdw/x"
SRC_URI=""
S="${WORKDIR}"
LICENSE="MPL-2.0"
SLOT="0"
KEYWORDS="~amd64 ~arm64 ~arm ~riscv64 ~loongarch ~ppc64 ~s390"
RESTRICT="strip"
IUSE=""

RDEPEND="
    gui-wm/niri
    gui-apps/foot
    gui-apps/fuzzel
    gui-apps/waybar
    gui-apps/mako
    gui-apps/swaylock
    gui-apps/swayidle
    gui-apps/greetd
    sys-auth/elogind
"

# The CI build stage compiles the workspace checkout and stages release
# binaries into ${WORKDIR}/bin before this ebuild runs.
src_install() {
    exeinto /usr/bin
    doexe "${WORKDIR}/bin/namikaze-desk" || die "missing built binary for namikaze-desk"
    exeinto /usr/bin
    newexe "${FILESDIR}/namikaze-session" namikaze-session
    insinto /etc/greetd
    newins "${FILESDIR}/greetd-config.toml" config.toml
    newinitd "${FILESDIR}/namikaze-desk.initd" namikaze-desk
    newinitd "${FILESDIR}/greetd.initd" greetd
    insinto /etc/pam.d
    newins "${FILESDIR}/greetd.pamd" greetd
    newins "${FILESDIR}/swaylock.pamd" swaylock
}
