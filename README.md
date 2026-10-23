# php2shell

Single-file Bash tool for **php2shell** (CVE-2026-109618 / CVE-2026-109619) and the related **CVE-2026-115560** on hosting servers: **cPanel, Plesk, ISPmanager**, plus CloudLinux alt-php, LiteSpeed lsphp, distro PHP, Remi SCL and DirectAdmin. On each PHP installation it **installs the patch where one exists** and **applies the official mitigations where none does**. Works on one server or across a fleet over SSH.

[English](#english) · [Türkçe](#türkçe)

## Quick start · Hızlı başlangıç

One command does everything. It shows the plan once and asks a single confirmation: upgrade all packages, apply the needed mitigation, restart PHP, then run the general check and IOC sweep.
Tek komut her şeyi yapar. Planı bir kez gösterip tek onay ister: tüm paketleri günceller, gereken önlemi uygular, PHP'yi yeniden başlatır, ardından genel kontrol ve IOC taraması yapar.

```bash
curl -fsSL https://raw.githubusercontent.com/cagritopuz/php2shell/main/php2shell_fix.sh | sudo bash -s -- --all
```

- Unattended / cron · Gözetimsiz / cron: `--all --yes`
- Many servers · Çok sunucu: `bash php2shell_fix.sh --hosts hosts.txt --all` (asks once, locally · tek onay, yerelde sorulur)
- Look first, change nothing · Önce sadece bak: `--audit`

> ⚠️ Unofficial tool, provided under MIT with no warranty. Run `--check` first.
> Resmi olmayan bir araçtır; MIT lisanslıdır, garanti verilmez. Önce `--check` çalıştırın.

| Branch | Fixed in (php.net, 2026-10-21) |
|---|---|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |
| 8.1 and older | no upstream release. Source-only backports exist in php-src (`PHP-7.4/8.0/8.1-CVE-2026-109618-109619`); vendor builds such as CloudLinux alt-php and distro LTS may ship them |

> 🆕 **CVE-2026-115560** (php.net informational advisory, 2026-10-23): another RCE path through session upload progress. It is **not fixed by the 2026-10-21 releases**; the fix comes with the next regular release. It needs all three: `session.serialize_handler` = `php_binary` or `php_serialize` in config, the app switching it to `php` via `ini_set()` before `session_start()`, and `session.upload_progress.enabled` on. php.net recommends `session.upload_progress.enabled=0` until then, so the script **keeps that setting on every installation, patched or not**. When the fix ships, run with `FIXED_VERSIONS_UP="8.5=… 8.4=… 8.3=… 8.2=…"` (or a newer script) and `--upgrade` removes it.
>
> 🆕 **CVE-2026-115560** (php.net bilgilendirmesi, 23 Ekim 2026): session upload progress üzerinden başka bir RCE yolu. **21 Ekim yamaları bunu kapatmıyor**; yama bir sonraki rutin sürümde gelecek. Açığın tetiklenmesi için üç koşulun birlikte olması gerekiyor: yapılandırmada `session.serialize_handler` değerinin `php_binary` ya da `php_serialize` olması, uygulamanın `session_start()` öncesinde `ini_set()` ile bunu `php`'ye çevirmesi ve `session.upload_progress.enabled` ayarının açık olması. php.net o zamana kadar `session.upload_progress.enabled=0` öneriyor; script bu yüzden bu ayarı **yamalı olsun olmasın her kurulumda kapalı tutar**. Yama çıkınca script'i `FIXED_VERSIONS_UP` ile ya da yeni sürümüyle `--upgrade` modunda çalıştırın; ayar o zaman kaldırılır.

---

## English

### What `--upgrade` does (recommended)

1. **Upgrades** installed PHP packages (`ea-php*`, `alt-php*`, `plesk-php*`, `isp-php*`, `lsphp*`, `php*`, `libapache2-mod-php*`) via dnf, yum or apt. With `--full-upgrade`, it upgrades **all** system packages instead.
   - dnf/yum run with `--skip-broken`, so one package with a dependency problem does not block the others. dnf also gets `best=False`: it takes the newest installable build instead of stopping with the `--nobest` / `--allowerasing` hint. `--allowerasing` is never used, because it can remove other packages. apt waits up to 10 minutes for the dpkg lock, for example while unattended-upgrades is running.
   - **Plesk**: also runs `plesk installer --select-release-current --upgrade-installed-components`, because Plesk manages its PHP handlers itself.
   - **DirectAdmin**: PHP is compiled by CustomBuild, so it runs `./build update && ./build php`. This can take a while.
   - The report lists versionlock / `apt-mark hold` entries and yum `exclude=` rules that keep PHP packages back.
2. **Decides per installation:**
   - **PATCHED**: the version is at or above the fixed release.
   - **BACKPORTED**: the version number is old, but the package changelog lists the CVE (distro or CloudLinux backport).
   - CVE-2026-115560 is tracked separately (`PENDING` until its fix ships).
   - **Fully patched** (both): this script's mitigation is removed.
   - **PHP2Shell patched, CVE-2026-115560 pending**: only `session.upload_progress.enabled = Off` is kept.
   - **UNPATCHED / EOL**: the full mitigation is applied as a php.ini-level drop-in, `zz-php2shell-mitigation.ini`, in every ini scan dir.
3. **Restarts PHP workers**:
   - php-fpm services are restarted.
   - lsphp workers are killed, because a LiteSpeed graceful restart keeps the old config.
   - Apache gets a graceful restart when mod_php is loaded.
   - The CageFS skeleton is updated.

Mitigation contents, from the php.net advisory: *"There are no complete mitigations, updating is the only safe choice."*

| Setting | CVE | When |
|---|---|---|
| `session.upload_progress.enabled = Off` | 109619, 115560 | until both are patched |
| `fatal_error_backtraces = Off` | 109619 | PHP 8.5+, until PHP2Shell is patched |
| `memory_limit = -1`, `post_max_size = 32M`, `upload_max_filesize = 30M` | 109618 | only with `--strict` |

`--strict` caveats:
- `memory_limit=-1` needs a cgroup or LVE memory boundary.
- Apps can still raise `memory_limit` with `ini_set()`. Set `php_admin_value[memory_limit]` in FPM pools for full effect.
- The 32M post size cap can break large uploads.

### Usage

Run it without arguments in a terminal to get an **interactive menu**. Its first entry is the **general check** (`--audit`, read-only). It refreshes package metadata, then reports patch status for both CVEs, why each still-unpatched installation is unpatched, PHP workers still running a replaced (pre-upgrade) binary, per-directory overrides, code switching `session.serialize_handler`, and the IOC sweep. The menu asks for the language (English/Türkçe) and the action, asks about strict mode and the IOC scan, and confirms before changing anything. Output language otherwise follows the system locale (`tr_*` → Turkish), or set it with `--lang=en|tr` or `PHP2SHELL_LANG`.

```bash
# single server (root)
curl -fsSLO https://raw.githubusercontent.com/cagritopuz/php2shell/main/php2shell_fix.sh
bash php2shell_fix.sh                    # interactive menu
bash php2shell_fix.sh --all              # DO EVERYTHING, one confirmation (--yes: none)
bash php2shell_fix.sh --audit            # general check of everything, read-only (start here)
bash php2shell_fix.sh --check            # quick report only (default without a terminal)
bash php2shell_fix.sh --upgrade          # patch where possible, mitigate the rest
bash php2shell_fix.sh --full-upgrade     # same, but upgrade ALL system packages
bash php2shell_fix.sh --upgrade --strict # + CVE-2026-109618 OOM mitigations
bash php2shell_fix.sh --apply            # mitigation everywhere, no upgrade
bash php2shell_fix.sh --rollback         # remove all mitigations
bash php2shell_fix.sh --upgrade --scan=7 # + read-only IOC sweep

# fleet (from your workstation, SSH key auth)
cat > hosts.txt <<'EOF'
# host            port   user
web1.example.com
web2.example.com  2222   root
EOF
bash php2shell_fix.sh --hosts hosts.txt --upgrade
```

| Exit code | Meaning |
|---|---|
| 0 | every installation patched or backported (PHP2Shell and CVE-2026-115560) |
| 1 | unpatched installations exist (including CVE-2026-115560 pending), all mitigated |
| 2 | EOL installation without backport, or unpatched without mitigation |
| 3 | error (fleet mode: 255 = SSH failure) |

Logs go to `/root/php2shell_fix_<time>.log`. Backups of modified files go to `/root/php2shell_backup_<time>/`.

### Caveats

- If the vendor repo has not published the patched build yet, the installation stays mitigated. Re-run `--upgrade` later.
- **Installed but not active:** after a package upgrade, PHP-FPM / lsphp / mod_php keep running the old binary until they restart. The report lists such processes and exits with code 2 until they are restarted; `--upgrade` restarts them.
- For every installation that is still unpatched, the summary says **why**: either *a newer build IS in the repo but not installed* (the upgrade failed or the package is held back, so check the package manager output), or *there is no newer build in the configured repos* (the vendor has not published one yet, or its repo is missing or disabled).
- CloudLinux (alt-php and its ea-php builds) and Ubuntu ship the fix **without bumping the version**; for example, CloudLinux ea-php84 stays at `8.4.26-2.elX.cloudlinux.1`. The script detects these builds from the CVE IDs in the package changelog and reports them as `BACKPORTED`.
- Plesk rebuilt its EOL branches (8.0/8.1) without a version bump, and the changelog may not name the CVEs. Those builds stay mitigated, and the report prints their build date so you can check it against Plesk's advisory.
- CLI verification does not fully guarantee web SAPI behaviour. Check critical sites with `ini_get()` over the web.
- CloudLinux PHP Selector/CageFS users may load a separate ini dir. Verify on a customer site.
- `session.upload_progress.enabled` is `PHP_INI_PERDIR`, so users can re-enable it in `.user.ini` or `.htaccess`. `--scan` lists such overrides, and also lists code that switches `session.serialize_handler` at runtime (CVE-2026-115560 precondition). An FPM `php_admin_flag` cannot be overridden.
- The report flags installations whose configured `session.serialize_handler` is `php_binary` or `php_serialize` while upload progress is still enabled.

---

## Türkçe

### `--upgrade` ne yapar (önerilen)

1. **Günceller:** kurulu PHP paketlerini (`ea-php*`, `alt-php*`, `plesk-php*`, `isp-php*`, `lsphp*`, `php*`, `libapache2-mod-php*`) dnf, yum veya apt ile. `--full-upgrade` ile bunların yerine **tüm** sistem paketlerini günceller.
   - dnf/yum `--skip-broken` ile çalışır; bağımlılık sorunu olan tek bir paket diğerlerinin kurulmasını engellemez. dnf'ye ayrıca `best=False` verilir: `--nobest` / `--allowerasing` uyarısıyla durmak yerine kurulabilen en yeni build'i seçer. `--allowerasing` hiç kullanılmaz, çünkü başka paketleri silebilir. apt, dpkg kilidi için 10 dakikaya kadar bekler (örneğin unattended-upgrades çalışıyorsa).
   - **Plesk**: PHP handler'larını kendisi yönettiği için ayrıca `plesk installer --select-release-current --upgrade-installed-components` çalıştırılır.
   - **DirectAdmin**: PHP CustomBuild ile derlendiği için `./build update && ./build php` çalıştırılır. Bu uzun sürebilir.
   - Rapor, PHP paketlerini geride tutan versionlock / `apt-mark hold` kayıtlarını ve yum `exclude=` kurallarını gösterir.
2. **Her kurulum için karar verir:**
   - **PATCHED:** sürüm, yamalı sürüm veya üstü.
   - **BACKPORTED:** sürüm numarası eski ama paket changelog'unda CVE geçiyor (dağıtım ya da CloudLinux backport'u).
   - CVE-2026-115560 ayrıca takip edilir; yaması çıkana kadar durumu `PENDING` görünür.
   - **İkisi de yamalı:** script'in koyduğu önlem kaldırılır.
   - **PHP2Shell yamalı, CVE-2026-115560 bekliyor:** sadece `session.upload_progress.enabled = Off` kalır.
   - **UNPATCHED / EOL:** her ini scan dizinine `zz-php2shell-mitigation.ini` adında php.ini seviyesinde tam önlem dosyası yazılır.
3. **PHP süreçlerini yeniden başlatır:**
   - php-fpm servisleri restart edilir.
   - lsphp süreçleri sonlandırılır, çünkü LiteSpeed'in graceful restart'ı eski config'i korur.
   - mod_php yüklüyse Apache'ye graceful restart yapılır.
   - CageFS skeleton güncellenir.

Önlemin içeriği yukarıdaki tabloyla aynı. php.net'e göre tam bir önlem yoktur; tek güvenli yol güncellemektir.

`--strict` dikkat noktaları:
- `memory_limit=-1` için cgroup ya da LVE bellek sınırı şart.
- Uygulamalar `ini_set()` ile `memory_limit` değerini yine yükseltebilir. Tam etki için FPM pool'larına `php_admin_value[memory_limit]` ekleyin.
- 32M'lik post sınırı büyük yüklemeleri bozabilir.

### Kullanım

- Argümansız, terminalden çalıştırınca **etkileşimli menü** açılır. Menünün ilk seçeneği **genel kontrol**dür (`--audit`, salt-okunur). Önce paket listelerini yeniler, sonra raporlar: iki CVE için yama durumu, hâlâ yamasız kurulumların sebebi, eski (güncelleme öncesi) binary'yle çalışmaya devam eden PHP süreçleri, dizin bazlı override'lar, `session.serialize_handler`'ı değiştiren kodlar ve IOC taraması.
- **Kurulu ama etkin değil:** paket güncellendikten sonra PHP-FPM / lsphp / mod_php yeniden başlatılana kadar eski binary'yi çalıştırmaya devam eder. Rapor bu süreçleri listeler ve yeniden başlatılana kadar 2 koduyla çıkar; `--upgrade` bunları yeniden başlatır. Menü önce dili (English/Türkçe) ve işlemi sorar, sonra strict modu ve IOC taramasını sorar. Bir şeyi değiştirmeden önce onay ister. Menü dışında çıktı dili sistem diline göre seçilir (`tr_*` → Türkçe); `--lang=tr` bayrağıyla ya da `PHP2SHELL_LANG=tr` ortam değişkeniyle de ayarlanabilir.
- Tek sunucuda root olarak: `bash php2shell_fix.sh --upgrade`. Terminal yoksa (cron, pipe) varsayılan mod `--check`'tir, sadece rapor verir.
- Filo için: `bash php2shell_fix.sh --hosts hosts.txt --upgrade`. `hosts.txt`'te her satır `host [port] [kullanıcı]` biçimindedir. Bağlantı SSH anahtarıyla yapılır. Script uzak sunucuda geçici bir dosyaya yazılıp çalıştırılır ve sonra silinir.
- Vendor reposu yamalı build'i henüz yayınlamadıysa kurulum önlemli kalır. `--upgrade`'i daha sonra tekrar çalıştırın.
- Hâlâ yamasız olan her kurulum için özet bölümü **sebebini** yazar. Ya *repoda daha yeni build var ama kurulmamış* (güncelleme hata vermiş ya da paket bekletiliyor; paket yöneticisi çıktısına bakın) ya da *tanımlı repolarda daha yeni build yok* (vendor henüz yayınlamamış ya da reposu eksik/kapalı).
- Tüm sistemi güncellemek için: `bash php2shell_fix.sh --full-upgrade`. Menüde de "Güncelle" seçeneğinden sonra bu sorulur.
- `session.upload_progress.enabled` ayarı `PHP_INI_PERDIR` olduğu için kullanıcılar `.user.ini` ya da `.htaccess` ile geri açabilir. `--scan` bu tür ayarları listeler. Ayrıca `session.serialize_handler`'ı kod içinde `ini_set` ile değiştiren uygulamaları da listeler (CVE-2026-115560 ön koşulu). FPM pool'undaki `php_admin_flag` ayarı ezilemez.

## License

MIT — see [LICENSE](LICENSE).
