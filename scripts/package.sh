#!/usr/bin/env bash
# Builds distributable VeilNet packages from dist/ (Linux/macOS host).
#
#   ./scripts/package.sh                          # tarball for this platform
#   ./scripts/package.sh --format all|tar|deb|rpm|zip
#   VERSION=1.2.3 ./scripts/package.sh --format deb
#   ./scripts/package.sh --out ./release --no-build
#
# VERSION defaults to `git describe --tags --always --dirty` (else 0.1.0-dev).
# SOURCE_DATE_EPOCH defaults to the last commit timestamp for reproducible
# archives (tar --sort-name --mtime, deb/rpm metadata).
# Formats whose tools are absent are skipped with a clear note, never an
# error: dpkg-deb (.deb), rpmbuild (.rpm), zip (Windows .zip), hdiutil (macOS
# .dmg — steps printed, only runnable on macOS).
set -euo pipefail
cd "$(dirname "$0")/.."

FORMAT="tar"
OUT="release"
DO_BUILD=1

while [ $# -gt 0 ]; do
  case "$1" in
    --format) FORMAT="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --no-build) DO_BUILD=0; shift ;;
    --help|-h) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "Unknown flag: $1 (see --help)" >&2; exit 2 ;;
  esac
done

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)}"
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH="$(git log -1 --format=%ct 2>/dev/null || date +%s)"
fi
export VERSION SOURCE_DATE_EPOCH

if [ "$DO_BUILD" = "1" ]; then
  ./scripts/build.sh
fi

for b in veilnet veilnet-node veilnet-service; do
  if [ ! -x "dist/$b" ]; then
    echo "Missing dist/$b. Remove --no-build or run ./scripts/build.sh first." >&2
    exit 1
  fi
done

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
esac
TAG="$VERSION-$OS-$ARCH"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$OUT" "$STAGE/veilnet-$TAG/bin" "$STAGE/veilnet-$TAG/packaging" "$STAGE/veilnet-$TAG/docs"

cp dist/veilnet dist/veilnet-node dist/veilnet-service "$STAGE/veilnet-$TAG/bin/"
[ -f dist/VERSION ] && cp dist/VERSION "$STAGE/veilnet-$TAG/VERSION"
[ -f dist/BUILDINFO ] && cp dist/BUILDINFO "$STAGE/veilnet-$TAG/BUILDINFO"
cp deploy/packaging/veilnet.service deploy/packaging/veilnet-node.service "$STAGE/veilnet-$TAG/packaging/"
cp deploy/packaging/com.veilnet.service.plist deploy/packaging/com.veilnet.node.plist "$STAGE/veilnet-$TAG/packaging/"
cp docs/INSTALL.md README.md "$STAGE/veilnet-$TAG/docs/" 2>/dev/null || true

MTIME="@${SOURCE_DATE_EPOCH}"
# GNU tar gets a reproducible archive (--sort=name --mtime --owner); bsdtar
# (Git for Windows, some BSDs) lacks these, so probe once and fall back to
# plain tar rather than failing the whole packaging run.
if tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="$MTIME" -cf /dev/null --version >/dev/null 2>&1; then
  TARFLAGS=(--sort=name --owner=0 --group=0 --numeric-owner --mtime="$MTIME")
else
  TARFLAGS=()
fi

# make_tar <output.tgz> <dir> <member>: reproducible when supported.
make_tar() {
  if [ "${#TARFLAGS[@]}" -eq 0 ]; then
    echo 'note: tar lacks reproducible flags (--sort/--mtime/--owner); archive timestamps will vary.' >&2
  fi
  tar "${TARFLAGS[@]}" -czf "$1" -C "$2" "$3"
}

want() {
  case "$FORMAT" in
    all) return 0 ;;
    "$1") return 0 ;;
    *) return 1 ;;
  esac
}

if want tar; then
  make_tar "$OUT/veilnet-$TAG.tar.gz" "$STAGE" "veilnet-$TAG"
  echo "Wrote $OUT/veilnet-$TAG.tar.gz"
fi

if want deb; then
  if command -v dpkg-deb >/dev/null 2>&1; then
    DEBARCH="$ARCH"
    case "$ARCH" in
      amd64) DEBARCH="amd64" ;;
      arm64) DEBARCH="arm64" ;;
      *) DEBARCH="all" ;;
    esac
    ROOT="$STAGE/debroot"
    mkdir -p "$ROOT/DEBIAN" "$ROOT/usr/local/bin" "$ROOT/lib/systemd/system" "$ROOT/usr/share/doc/veilnet"
    cp dist/veilnet dist/veilnet-node dist/veilnet-service "$ROOT/usr/local/bin/"
    cp deploy/packaging/veilnet.service deploy/packaging/veilnet-node.service "$ROOT/lib/systemd/system/"
    cp docs/INSTALL.md README.md "$ROOT/usr/share/doc/veilnet/" 2>/dev/null || true
    DATE="$(date -u -d "@${SOURCE_DATE_EPOCH}" +%a,\ %d\ %b\ %Y\ %T\ +0000 2>/dev/null || date -u -r "${SOURCE_DATE_EPOCH}" +%a,\ %d\ %b\ %Y\ %T\ +0000)"
    cat > "$ROOT/DEBIAN/control" <<EOF
Package: veilnet
Version: $VERSION
Section: net
Priority: optional
Architecture: $DEBARCH
Depends: wireguard-tools, nftables | iptables
Maintainer: VeilNet <ops@example.invalid>
Description: Decentralized privacy VPN (WireGuard data plane, DERO control plane)
 DERO coordinates payments and sessions; it never carries user traffic.
EOF
    cat > "$ROOT/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
systemctl daemon-reload 2>/dev/null || true
systemctl enable veilnet.service 2>/dev/null || true
EOF
    chmod 0755 "$ROOT/DEBIAN/postinst"
    dpkg-deb --build "$ROOT" "$OUT/veilnet-$TAG.deb"
    echo "Wrote $OUT/veilnet-$TAG.deb"
  else
    echo 'Skipping .deb: dpkg-deb not found (Debian/Ubuntu: sudo apt-get install -y dpkg-dev).'
  fi
fi

if want rpm; then
  if command -v rpmbuild >/dev/null 2>&1; then
    RPMROOT="$STAGE/rpmbuild"
    mkdir -p "$RPMROOT"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
    make_tar "$RPMROOT/SOURCES/veilnet-$VERSION.tar.gz" "$STAGE" "veilnet-$TAG"
    sed -e "s/@VERSION@/$VERSION/g" deploy/packaging/rpm/veilnet.spec > "$RPMROOT/SPECS/veilnet.spec"
    rpmbuild --define "_topdir $RPMROOT" --define "dist_version $VERSION" -bb "$RPMROOT/SPECS/veilnet.spec"
    cp "$RPMROOT"/RPMS/*/*.rpm "$OUT/" 2>/dev/null || true
    echo "Wrote RPM(s) to $OUT/"
  else
    echo 'Skipping .rpm: rpmbuild not found (Fedora/RHEL: sudo dnf install -y rpm-build; openSUSE: sudo zypper install -y rpm-build).'
    echo '  The tarball above plus deploy/packaging/rpm/veilnet.spec is everything a maintainer needs to run rpmbuild.'
  fi
fi

if want zip; then
  if command -v zip >/dev/null 2>&1; then
    rm -f "$OUT/veilnet-$TAG.zip"
    (cd "$STAGE" && zip -X -r "$OLDPWD/$OUT/veilnet-$TAG.zip" "veilnet-$TAG")
    echo "Wrote $OUT/veilnet-$TAG.zip"
  else
    echo 'Skipping .zip: zip not found. On Windows instead: Compress-Archive -Path dist\*.exe -DestinationPath veilnet-$TAG.zip'
  fi
fi

if want dmg; then
  cat <<EOF
DMG (macOS disk image) is only built on macOS. On a Mac, after ./scripts/build.sh:
  hdiutil create -volname "VeilNet $VERSION" -srcfolder "$STAGE/veilnet-$TAG" -ov -format UDZO "$OUT/veilnet-$TAG.dmg"
EOF
fi

echo 'Done.'
