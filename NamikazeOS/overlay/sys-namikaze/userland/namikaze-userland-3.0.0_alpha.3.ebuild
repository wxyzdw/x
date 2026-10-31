# Distributed under the terms of the Mozilla Public License v2.0
# Maintained by `cargo xtask ebuilds` from the sector layout.

EAPI=8

DESCRIPTION="Rust core userland (single multi-call binary + tool symlinks)"
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
    doexe "${WORKDIR}/bin/namikaze-userland" || die "missing built binary for namikaze-userland"
    dodir /usr/lib/namikaze/userland/bin
    for t in basename cat chmod clear cmp comm cp cut date dirname dmesg echo env expand false fold free head hostname id kill ln ls mkdir mktemp mv nproc paste printenv ps pwd readlink rm rmdir seq sha256sum sleep sort stat tail tee touch tr true tty uname uniq wc which whoami; do
        dosym /usr/bin/namikaze-userland /usr/lib/namikaze/userland/bin/$t
    done
    insinto /etc/profile.d
    newins "${FILESDIR}/userland-profile.sh" 90-namikaze-userland.sh
}
