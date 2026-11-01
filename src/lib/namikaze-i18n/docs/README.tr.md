# NamikazeOS 3.0.0-alpha.3 - Türkçe özeti

NamikazeOS, gizlilik ve anonimlik odaklı bir işletim sistemidir: Gentoo
stage3 tabanı, tamamen Rust ile yazılmış kullanıcı alanı ve değiştirilmemiş
ana hattın (mainline) Linux LTS çekirdeği. Tek ISO ile her makinede açılır.

## Bu sürümdeki yenilikler

- **Sektör organizasyonu**: 33 crate, 10 sektöre ayrıldı (core, boot,
  hardware, live, security, network, pkg, desk, data, install).
- **Canlı kalıcı sistem**: ISO canlı açılır; tüm değişiklikler LUKS2
  (argon2id) kalıcı bölümde saklanır. Yalnızca parolayı oluşturan kullanıcı
  açabilir. Modlar: persist (varsayılan), volatile (iz bırakmaz), ram,
  session.
- **Atomik sistem güncellemeleri**: `namikaze-secupdate`, SHA-256 doğrulamalı
  görüntü paketlerini aşamalı yuvarlama (slot) ile güvenli değiştirir;
  çevrimdışı geri alma (rollback) desteklidir.
- **Geniş cihaz uyumluluğu**: `namikaze-hal` kart veritabanı (20 profil),
  8 mimari (x86_64, aarch64, armv7, armv6, riscv64, loongarch64, ppc64le,
  s390x) ve tek çekirdek + çok DTB stratejisi. Detay: `services/namikaze-hal/docs/HARDWARE.md`.
- **Linux çekirdeği**: ana hat LTS, kernel.org'dan imzalı doğrulamayla
  çekilir; katkı yalnızca yapılandırma parçalarıdır (bkz. `kernel/README.md`)
  (KSPP sertleştirme + mimari kapsamı). kernel-check zorunlu
  çekirdek seçeneklerini denetler.
- **MPL-2.0**: lisans Mozilla Public License 2.0 olarak sabitlendi; tüm
  kaynaklarda SPDX etiketi ve license-guard denetimi var.

## Kalıcılık ilkesi

Yanlış parola girilmesi veriyi asla yok etmez; gizler (P9). Beş deneme ve
artan bekleme sonrasında sistem kalıcı olmadan açılır. Kalıcı hacim, header
yedeği yazılmadığı için diskte görünmez durumda kalır. Detay: `tools/namikaze-persist/docs/PERSISTENCE.md`.

## Hızlı başlangıç

```
cargo build --release --workspace
cargo run -p namikaze -- guard
cargo run -p namikaze -- kernel-fragments
cargo run -p xtask -- kernel-check dist/kernel-configs/x86_64.config
cargo run -p xtask -- sbom
cargo run -p xtask -- iso
```

Uçtan uca rehber: `tools/namikaze-install/docs/QUICKSTART.md`.
Tam belgeler: `README.md`, `services/namikaze-hal/docs/HARDWARE.md`,
`tools/namikaze-persist/docs/PERSISTENCE.md`,
`services/namikaze-sentinel/docs/SECURITY.md`.
