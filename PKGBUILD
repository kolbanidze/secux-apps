pkgname=secux-security-manager
pkgver=0.0.4
pkgrel=1
pkgdesc="Security Manager"
arch=('x86_64')
url="https://github.com/kolbanidze/secux-apps"
license=('MIT')
depends=(python3 python-gobject gtk4 libadwaita python-pexpect)
makedepends=()
source=("security-manager.tar.gz")
sha256sums=('39c40522152dabde371afc50ac041bbee4604d25533928db3cbe203b79bc69db')
options=('!debug')

package() {
  mkdir -p "$pkgdir/usr/local/bin/"

  cp -a "$srcdir/security-manager" "$pkgdir/usr/local/bin/"

  install -Dm644 "$srcdir/security-manager/security-manager.desktop" "$pkgdir/usr/share/applications/security-manager.desktop"
}
