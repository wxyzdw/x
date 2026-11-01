# Distributed under the terms of the Mozilla Public License v2.0
# The NamikazeIMG release artifact: one GPT partition, fully sealed.

EAPI=8

DESCRIPTION="NamikazeIMG: single-partition fully-encrypted NamikazeOS disk image"
HOMEPAGE="https://github.com/wxyzdw/x"
SRC_URI=""
S="${WORKDIR}"
LICENSE="MPL-2.0"
SLOT="0"
KEYWORDS="~amd64 ~arm64 ~arm ~riscv64 ~loongarch ~ppc64 ~s390"
RESTRICT="strip"
IUSE=""

# The image itself is a pipeline artifact (dist/NamikazeOS-<v>-oneimg.img),
# staged into ${WORKDIR} by the CI build step before this ebuild runs.
src_install() {
    insinto /usr/lib/namikaze
    doins "${WORKDIR}/image/NamikazeOS-oneimg.img" || die "missing staged NamikazeIMG image"
}
