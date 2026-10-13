# WolfOS P0 — Hızlı başlangıç

Bu sürüm deneysel Rust kernel'dir ve gerçek disklere kurulmaz.

Ubuntu / WSL2 üzerinde Rust nightly, x86_64-unknown-none hedefi, make, git, xorriso, qemu-system-x86_64 ve python3 gereklidir.

Adımlar:
1. make doctor
2. make test (yalnızca dosya/yapı kontrolleri)
3. make smoke (gerçek QEMU açılış testi)
4. make run-graphics (framebuffer görüntüsü)

Başarılı smoke çıktısı WOLFOS_BOOT_OK satırını ve QEMU çıkış kodu 33'ü gerektirir.
Asla dd, diskpart, format veya gerçek SSD'ye yazma işlemi kullanılmaz.
