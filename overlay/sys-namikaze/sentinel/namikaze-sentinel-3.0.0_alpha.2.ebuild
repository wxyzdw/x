# Distributed under the terms of the Mozilla Public License v2.0
# Maintained by `cargo xtask ebuilds` from the sector layout.

EAPI=8

DESCRIPTION="Wrong-passphrase camera policy (opt-in)"
HOMEPAGE="https://git.disroot.org/anbu141"
SRC_URI=""
S="${WORKDIR}"
LICENSE="MPL-2.0"
SLOT="0"
KEYWORDS="~amd64 ~arm64 ~arm ~riscv64 ~loongarch ~ppc64 ~s390"
RESTRICT="strip"
IUSE=""

# The CI build stage compiles the workspace checkout and stages release
# binaries into ${WORKDIR}/bin before this ebuild runs.
src_install() {
    exeinto /usr/bin
    doexe "${WORKDIR}/bin/namikaze-sentinel" || die "missing built binary for namikaze-sentinel"
}
