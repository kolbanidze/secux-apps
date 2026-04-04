pkgname=secux-security-manager
pkgver=0.5.1
pkgrel=1
pkgdesc="Security Manager"
arch=('x86_64')
url="https://github.com/kolbanidze/secux-apps"
license=('MIT')
depends=(python3 python-gobject gtk4 libadwaita python-pexpect python-qrcode libpam-google-authenticator python-requests python-tpm2-pytss python-pefile)
makedepends=()
source=("security-manager.tar.gz")
sha256sums=('29f67e11d7cbebc1d7663749c75da5fc59cc7a1aace186fb18d79fcc9b82b58e')
options=('!strip' '!debug')

package() {
  mkdir -p "$pkgdir/usr/local/bin/"

  cp -a "$srcdir/security-manager" "$pkgdir/usr/local/bin/"
  
  install -Dm644 "$srcdir/security-manager/icons/org.secux.securitymanager.svg" "$pkgdir/usr/share/icons/hicolor/scalable/apps/org.secux.securitymanager.svg"
  install -Dm644 "$srcdir/security-manager/security-manager.desktop" "$pkgdir/usr/share/applications/security-manager.desktop"
}
