# Distributed under the terms of the Mozilla Public License v2.0
# Adapted from Plan 9 from Bell Labs (MIT license) into the Rust workspace.

EAPI=8

DESCRIPTION="Plan 9 plumber: rules-driven plumb message router over 9P2000"
HOMEPAGE="https://github.com/wxyzdw/x"
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
    doexe "${WORKDIR}/bin/namikaze-plumber" || die "missing built binary for namikaze-plumber"
}
