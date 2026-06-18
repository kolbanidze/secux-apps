pkgname=secux-security-manager
pkgver=0.6.4
pkgrel=1
pkgdesc="Security Manager"
arch=('x86_64')
url="https://github.com/kolbanidze/secux-apps"
license=('MIT')
depends=(python3 python-gobject gtk4 libadwaita python-pexpect python-qrcode libpam-google-authenticator python-requests python-tpm2-pytss python-pefile jq)
makedepends=()
source=("security-manager.tar.gz")
sha256sums=('49df29640e426cf6d87ced44ae29ccd23a9277ef737d743568849942ea272981')
options=('!strip' '!debug')

package() {
  mkdir -p "$pkgdir/usr/local/bin/"

  cp -a "$srcdir/security-manager" "$pkgdir/usr/local/bin/"
  
  install -Dm644 "$srcdir/security-manager/icons/org.secux.securitymanager.svg" "$pkgdir/usr/share/icons/hicolor/scalable/apps/org.secux.securitymanager.svg"
  install -Dm644 "$srcdir/security-manager/security-manager.desktop" "$pkgdir/usr/share/applications/security-manager.desktop"
}
