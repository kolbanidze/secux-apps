pkgname=secux-security-manager
pkgver=0.0.1
pkgrel=1
pkgdesc="Security Manager"
arch=('x86_64')
url="https://github.com/kolbanidze/secux-apps"
license=('MIT')
depends=(python3 python-gobject gtk4 libadwaita python-pexpect)
makedepends=()
source=("security-manager.tar.gz")
sha256sums=('70e5db2fdba8ce181c51465d649ad62df0520aa389c31dc1c771c4371f13f709')
options=('!debug')

package() {
  mkdir -p "$pkgdir/usr/local/bin/"

  cp -a "$srcdir/security-manager" "$pkgdir/usr/local/bin/"

  install -Dm644 "$srcdir/security-manager/scripts/security-manager.desktop" "$pkgdir/usr/share/applications/security-manager.desktop"
}
