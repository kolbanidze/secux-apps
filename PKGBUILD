pkgname=secux-security-manager
pkgver=0.4.0
pkgrel=1
pkgdesc="Security Manager"
arch=('x86_64')
url="https://github.com/kolbanidze/secux-apps"
license=('MIT')
depends=(python3 python-gobject gtk4 libadwaita python-pexpect python-qrcode tpm2-tools libpam-google-authenticator)
makedepends=()
source=("security-manager.tar.gz")
sha256sums=('ee83c686b3da069fe645b1d8381d69fde2b9ad01bf77013eb67ef115b76e4cb4')
options=('!strip' '!debug')

package() {
  mkdir -p "$pkgdir/usr/local/bin/"

  cp -a "$srcdir/security-manager" "$pkgdir/usr/local/bin/"
  
  install -Dm644 "$srcdir/security-manager/icons/org.secux.securitymanager.svg" "$pkgdir/usr/share/icons/hicolor/scalable/apps/org.secux.securitymanager.svg"
  install -Dm644 "$srcdir/security-manager/security-manager.desktop" "$pkgdir/usr/share/applications/security-manager.desktop"
}
