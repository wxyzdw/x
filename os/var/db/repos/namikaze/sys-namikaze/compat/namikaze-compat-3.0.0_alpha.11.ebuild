# Distributed under the terms of the Mozilla Public License v2.0
# The package compatibility base: detect, plan and route foreign
# packages into the sandbox ladder - Gentoo first, always.

EAPI=8

DESCRIPTION="NamikazeOS package compatibility base (Gentoo-first format routing)"
HOMEPAGE="https://github.com/wxyzdw/x"
SRC_URI=""
S="${WORKDIR}"
LICENSE="MPL-2.0"
SLOT="0"
KEYWORDS="~amd64 ~arm64 ~arm ~riscv64 ~loongarch ~ppc64 ~s390"
RESTRICT="strip"
IUSE=""

DEPEND="sys-namikaze/namikaze-pkg"

# Foreign-format overlay prefixes: read-only to applications, writable
# only by the installer; the sandbox ladder gates every launch.
src_install() {
    keepdir /opt/namikaze/compat/deb
    keepdir /opt/namikaze/compat/rpm
    keepdir /opt/namikaze/compat/apk
    keepdir /opt/namikaze/compat/android
}
