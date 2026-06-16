pkgname=secux-security-manager
pkgver=0.6.3
pkgrel=1
pkgdesc="Security Manager"
arch=('x86_64')
url="https://github.com/kolbanidze/secux-apps"
license=('MIT')
depends=(python3 python-gobject gtk4 libadwaita python-pexpect python-qrcode libpam-google-authenticator python-requests python-tpm2-pytss python-pefile jq)
makedepends=()
source=("security-manager.tar.gz")
sha256sums=('f92ccab3608c2f27b6fb193d2a09a83ac6f02ad0237a86d194760b99229b2ccc')
options=('!strip' '!debug')

package() {
  mkdir -p "$pkgdir/usr/local/bin/"

  cp -a "$srcdir/security-manager" "$pkgdir/usr/local/bin/"
  
  install -Dm644 "$srcdir/security-manager/icons/org.secux.securitymanager.svg" "$pkgdir/usr/share/icons/hicolor/scalable/apps/org.secux.securitymanager.svg"
  install -Dm644 "$srcdir/security-manager/security-manager.desktop" "$pkgdir/usr/share/applications/security-manager.desktop"
}
