#!/usr/bin/env bash
# =====================================================================
#  php2shell_fix.sh — php2shell (CVE-2026-109618 / CVE-2026-109619)
#  https://github.com/cagritopuz/php2shell  ·  MIT License
#
#  Finds every PHP installation on cPanel / Plesk / ISPmanager servers
#  (plus CloudLinux alt-php, LiteSpeed lsphp, distro PHP, Remi SCL and
#  DirectAdmin), installs patched builds where the vendor ships them and
#  applies the official partial mitigations where no patch is available
#  (EOL branches, or repos that have not published the fix yet).
#  Single file: runs on one server or across a fleet over SSH.
#  English / Türkçe output; interactive menu when started without args.
#
#  Fixed upstream (php.net, 2026-10-21): 8.5.12 · 8.4.27 · 8.3.36 · 8.2.35
#  8.1 and older: no upstream release (source-only backports in php-src
#  branches PHP-{7.4,8.0,8.1}-CVE-2026-109618-109619; vendors such as
#  CloudLinux alt-php / distros may ship them — detected via changelog).
#
#  Usage:
#    php2shell_fix.sh              interactive menu (in a terminal), else --check
#    php2shell_fix.sh --all        EVERYTHING, one confirmation (--yes: none):
#                                  full upgrade + mitigate + restart + --audit
#    php2shell_fix.sh --audit      general check, read-only: report, why still
#                                  unpatched, stale PHP workers, overrides, IOC sweep
#    php2shell_fix.sh --check      report only, changes nothing
#    php2shell_fix.sh --upgrade    RECOMMENDED: upgrade PHP packages, then per
#                                  installation: fully patched → remove our
#                                  mitigation, otherwise keep/apply what is still
#                                  needed; restart PHP
#    php2shell_fix.sh --full-upgrade   same, but upgrades ALL system packages
#    php2shell_fix.sh --apply      apply mitigation everywhere (no upgrade)
#    php2shell_fix.sh --rollback   remove the drop-ins this script wrote + reload
#  Flags: --yes  --strict  --scan[=DAYS]  --no-reload  --lang=en|tr  --menu
#         --hosts FILE   (fleet mode over SSH; FILE lines: host [port] [user])
#
#  CVE-2026-115560 (php.net informational advisory, 2026-10-23): another RCE path
#  via session upload progress, NOT fixed by the 2026-10-21 releases (fix comes
#  with the next regular release). So session.upload_progress stays disabled on
#  every installation — patched or not — until FIXED_VERSIONS_UP says otherwise.
#
#  Mitigation (official php.net advisories — not a complete fix), written as a
#  php.ini-level drop-in (never .user.ini / ini_set) + worker restart:
#    session.upload_progress.enabled = Off      (CVE-2026-109619, CVE-2026-115560)
#    fatal_error_backtraces = Off               (CVE-2026-109619, PHP 8.5+)
#    --strict: memory_limit=-1, post_max_size=32M, upload_max_filesize=30M
#                                               (CVE-2026-109618)
#
#  Exit codes: 0 every installation patched (upstream or vendor backport)
#              1 unpatched installations exist, but all are mitigated
#              2 EOL without backport, or unpatched WITHOUT mitigation
#              3 error   (fleet mode: 255 = SSH connection failure)
# =====================================================================
set -o pipefail
umask 022
ORIG_LOCALE="${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}"
export LC_ALL=C
PHPQ=(-d display_errors=0 -d display_startup_errors=0)   # keep broken-extension warnings out of parsed output

FIXED_VERSIONS="${FIXED_VERSIONS:-8.5=8.5.12 8.4=8.4.27 8.3=8.3.36 8.2=8.2.35}"
CVE_RE='CVE-2026-10961[89]'
# CVE-2026-115560 (php.net informational advisory 2026-10-23): another RCE path via
# session upload progress, NOT fixed by the 2026-10-21 releases; fix comes "with the
# next regular release". Until then session.upload_progress.enabled=0 stays on every
# installation. Fill in once released, e.g. "8.5=8.5.13 8.4=8.4.28 8.3=8.3.37 8.2=8.2.36".
FIXED_VERSIONS_UP="${FIXED_VERSIONS_UP:-}"
CVE_RE_UP='CVE-2026-115560'
DROPIN_NAME="zz-php2shell-mitigation.ini"
INI_MARK_BEGIN='; >>> php2shell-mitigation'
INI_MARK_END='; <<< php2shell-mitigation'

# ---------------------------------------------------------------------
#  Language: --lang > PHP2SHELL_LANG > system locale (tr_* → tr) > en
# ---------------------------------------------------------------------
UI_LANG="${PHP2SHELL_LANG:-}"
[ -z "$UI_LANG" ] && case "$ORIG_LOCALE" in tr*|TR*) UI_LANG=tr ;; *) UI_LANG=en ;; esac
for a in "$@"; do case "$a" in --lang=*) UI_LANG="${a#*=}" ;; esac; done
case "$UI_LANG" in tr|en) ;; *) UI_LANG=en ;; esac
L() { if [ "$UI_LANG" = tr ]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }   # L "english" "türkçe"

usage() {
  if [ "$UI_LANG" = tr ]; then cat <<'EOF'
Kullanım:
  php2shell_fix.sh              etkileşimli menü (terminalde), değilse --check
  php2shell_fix.sh --all        HER ŞEYİ YAP, tek onayla: tüm paketleri güncelle + önlem + PHP restart
                                + genel kontrol + IOC (gözetimsiz: --all --yes)
  php2shell_fix.sh --audit      GENEL KONTROL (salt-okunur): rapor + neden yamasız + eski binary ile
                                çalışan PHP + override'lar + IOC taraması (paket listelerini yeniler)
  php2shell_fix.sh --check      sadece rapor, hiçbir şeyi değiştirmez
  php2shell_fix.sh --upgrade    ÖNERİLEN: PHP paketlerini güncelle; tamamen yamalı kurulumdan
                                önlemi kaldır, diğerlerinde gereken önlemi koru/uygula; PHP restart
  php2shell_fix.sh --full-upgrade  --upgrade + PHP dışındaki TÜM sistem paketlerini de güncelle
  php2shell_fix.sh --apply      her kuruluma önlem uygula (güncelleme yok)
  php2shell_fix.sh --rollback   bu script'in yazdığı önlemleri kaldır + reload
Bayraklar:
  -y, --yes       --all onayını sorma (cron / gözetimsiz kullanım)
  --strict        CVE-2026-109618 (OOM) önlemleri de: memory_limit=-1, post_max_size=32M,
                  upload_max_filesize=30M. ⚠ cgroup/LVE bellek sınırı şart; ini_set() ile
                  ezilebilir; büyük yüklemeleri bozabilir
  --scan[=GÜN]    salt-okunur IOC taraması (varsayılan 3 gün)
  --no-reload     PHP süreçlerini yeniden başlatma
  --lang=en|tr    çıktı dili (varsayılan: sistem dili)
  --menu          etkileşimli menüyü zorla aç
  --hosts DOSYA   filo modu: her satır "host [port] [kullanıcı]", SSH anahtarıyla
PHP2Shell (CVE-2026-109618/-109619) ve CVE-2026-115560'ı (upload progress; 21 Ekim yamaları
kapatmıyor → FIXED_VERSIONS_UP ayarlanana kadar upload_progress her yerde kapalı kalır) kapsar.
Çıkış kodu: 0 hepsi yamalı | 1 yamasız var ama hepsinde önlem | 2 EOL/önlemsiz | 3 hata
EOF
  else cat <<'EOF'
Usage:
  php2shell_fix.sh              interactive menu (in a terminal), else --check
  php2shell_fix.sh --all        DO EVERYTHING with one confirmation: upgrade all packages + mitigate +
                                restart PHP + general check + IOC (unattended: --all --yes)
  php2shell_fix.sh --audit      GENERAL CHECK (read-only): report + why still unpatched + stale PHP
                                workers + overrides + IOC sweep (refreshes package metadata)
  php2shell_fix.sh --check      report only, changes nothing
  php2shell_fix.sh --upgrade    RECOMMENDED: upgrade PHP packages; remove the mitigation
                                from fully patched installs, keep/apply what is still needed
                                elsewhere; restart PHP
  php2shell_fix.sh --full-upgrade  --upgrade + also upgrade ALL other system packages
  php2shell_fix.sh --apply      apply mitigation everywhere (no upgrade)
  php2shell_fix.sh --rollback   remove the mitigation this script wrote + reload
Flags:
  -y, --yes       do not ask the --all confirmation (cron / unattended)
  --strict        also CVE-2026-109618 (OOM) mitigations: memory_limit=-1, post_max_size=32M,
                  upload_max_filesize=30M. ⚠ needs a cgroup/LVE memory limit; can be
                  overridden via ini_set(); may break large uploads
  --scan[=DAYS]   read-only IOC sweep (default 3 days)
  --no-reload     do not restart PHP workers
  --lang=en|tr    output language (default: system locale)
  --menu          force the interactive menu
  --hosts FILE    fleet mode: lines "host [port] [user]", SSH key auth
Covers PHP2Shell (CVE-2026-109618/-109619) and CVE-2026-115560 (upload progress; not fixed
by the 2026-10-21 releases → upload_progress stays off everywhere until FIXED_VERSIONS_UP is set).
Exit codes: 0 all patched | 1 unpatched but all mitigated | 2 EOL/unmitigated | 3 error
EOF
  fi
}

MODE=check; ALL=0; ASSUME_YES=0; AUDIT=0; FULL_UPGRADE=0; STRICT=0; DO_SCAN=0; SCAN_DAYS=3; DO_RELOAD=1; HOSTS_FILE=""; FORCE_MENU=0
ARGC=$#
while [ $# -gt 0 ]; do
  case "$1" in
    --all)       MODE=upgrade; ALL=1; AUDIT=1; FULL_UPGRADE=1; DO_SCAN=1 ;;
    -y|--yes)    ASSUME_YES=1 ;;
    --check)     MODE=check ;;
    --audit|--full-check) MODE=check; AUDIT=1; DO_SCAN=1 ;;
    --apply)     MODE=apply ;;
    --upgrade|--auto) MODE=upgrade ;;
    --full-upgrade) MODE=upgrade; FULL_UPGRADE=1 ;;
    --rollback)  MODE=rollback ;;
    --strict)    STRICT=1 ;;
    --scan)      DO_SCAN=1 ;;
    --scan=*)    DO_SCAN=1; SCAN_DAYS="${1#*=}" ;;
    --no-reload) DO_RELOAD=0 ;;
    --lang=*)    ;;   # handled above
    --menu)      FORCE_MENU=1 ;;
    --hosts)     HOSTS_FILE="$2"; shift ;;
    --hosts=*)   HOSTS_FILE="${1#*=}" ;;
    -h|--help)   usage; exit 0 ;;
    *) echo "$(L "Unknown argument: $1 (see --help)" "Bilinmeyen argüman: $1 (--help'e bak)")" >&2; exit 3 ;;
  esac
  shift
done
case "$SCAN_DAYS" in ''|*[!0-9]*) echo "$(L "--scan=DAYS must be a number" "--scan=GÜN sayı olmalı")" >&2; exit 3 ;; esac

if [ -t 1 ]; then R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[1m'; N=$'\e[0m'; else R= G= Y= B= N=; fi
section() { printf '\n%s== %s ==%s\n' "$B" "$1" "$N"; }
info()    { printf '  %s\n' "$*"; }
ok()      { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
warn()    { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
bad()     { printf '  %s✗%s %s\n' "$R" "$N" "$*"; }

# ---------------------------------------------------------------------
#  Interactive menu: only without arguments and with a terminal
#  (fleet runs, cron and "ssh … bash -s" always pass explicit flags)
# ---------------------------------------------------------------------
ask() {   # ask "prompt" "default" → answer on stdout
  local a
  printf '%s' "$1" > /dev/tty
  read -r a < /dev/tty || a=""
  printf '%s' "${a:-$2}"
}
yesno() {   # yesno "question" → 0 on yes (default No)
  case "$(ask "$1 $(L "[y/N]" "[e/H]") " n)" in y|Y|yes|e|E|evet) return 0 ;; esac; return 1
}
# --all: show the whole plan once and ask a single confirmation (--yes skips it).
# Without a terminal (cron, pipes, fleet remote side) --yes is required.
confirm_all() {   # $1 = hosts file in fleet mode, empty for this server
  [ $ALL -eq 1 ] || return 0
  [ $ASSUME_YES -eq 1 ] && return 0
  if ! { : < /dev/tty; } 2>/dev/null; then
    echo "$(L "--all asks for one confirmation: run it in a terminal, or add --yes for unattended use." \
              "--all bir kez onay ister: terminalden çalıştır ya da gözetimsiz kullanım için --yes ekle.")" >&2
    exit 3
  fi
  {
    echo
    printf '%s%s%s\n' "$B" "$(L "Everything below will be done${1:+ on every server in $1}:" "Aşağıdakilerin hepsi yapılacak${1:+ ($1 içindeki her sunucuda)}:")" "$N"
    echo "  1. $(L "Upgrade ALL system packages (PHP fixes included; Plesk installer / DirectAdmin CustomBuild where present)" \
                   "TÜM sistem paketleri güncellenir (PHP yamaları dahil; varsa Plesk installer / DirectAdmin CustomBuild)")"
    echo "  2. $(L "Per PHP installation: fully patched → remove the mitigation, otherwise apply what is still needed" \
                   "Her PHP kurulumunda: tamamen yamalıysa önlem kaldırılır, değilse hâlâ gereken önlem uygulanır")"
    echo "  3. $(L "Restart PHP-FPM / lsphp / Apache (mod_php) — a short interruption is possible" \
                   "PHP-FPM / lsphp / Apache (mod_php) yeniden başlatılır — kısa bir kesinti olabilir")"
    echo "  4. $(L "General check + IOC sweep (last $SCAN_DAYS days) and a final report" \
                   "Genel kontrol + IOC taraması (son $SCAN_DAYS gün) ve son rapor")"
    [ $STRICT -eq 1 ] && echo "  +  strict: memory_limit=-1, post_max_size=32M, upload_max_filesize=30M"
    echo "  $(L "Backups: /root/php2shell_backup_<time>/   Log: /root/php2shell_fix_<time>.log" \
                "Yedekler: /root/php2shell_backup_<zaman>/   Log: /root/php2shell_fix_<zaman>.log")"
    echo
  } > /dev/tty
  yesno "$(L "Continue?" "Devam edilsin mi?")" || { echo "$(L "Cancelled." "İptal edildi.")" > /dev/tty; exit 0; }
}
run_menu() {
  local c d
  printf '\n%sphp2shell_fix — CVE-2026-109618 / CVE-2026-109619 / CVE-2026-115560%s\n' "$B" "$N" > /dev/tty
  c=$(ask "Language / Dil:  1) English  2) Türkçe  [$([ "$UI_LANG" = tr ] && echo 2 || echo 1)]: " "")
  case "$c" in 1) UI_LANG=en ;; 2) UI_LANG=tr ;; esac
  {
    echo
    echo "  1) $(L "DO EVERYTHING — upgrade all, mitigate, restart, check  (one confirmation)" "HER ŞEYİ YAP — hepsini güncelle, önlem al, yeniden başlat, kontrol et  (tek onay)")"
    echo "  2) $(L "General check — everything, read-only" "Genel kontrol — her şey, salt-okunur")"
    echo "  3) $(L "Quick check — report only" "Hızlı kontrol — sadece rapor")"
    echo "  4) $(L "Upgrade + keep/apply the mitigation still needed" "Güncelle + hâlâ gereken önlemi koru/uygula")"
    echo "  5) $(L "Apply mitigation to every installation (no upgrade)" "Her kuruluma önlem uygula (güncelleme yok)")"
    echo "  6) $(L "Rollback — remove this script's mitigation" "Geri al — bu script'in önlemlerini kaldır")"
    echo "  7) $(L "Run on multiple servers (fleet over SSH)" "Birden çok sunucuda çalıştır (SSH filo)")"
    echo "  0) $(L "Exit" "Çıkış")"
  } > /dev/tty
  c=$(ask "$(L "Choice" "Seçim") [1]: " 1)
  case "$c" in
    0) exit 0 ;;
    7) HOSTS_FILE=$(ask "$(L "Hosts file (lines: host [port] [user])" "Sunucu listesi dosyası (satır: host [port] [kullanıcı])") [hosts.txt]: " hosts.txt)
       [ -f "$HOSTS_FILE" ] || { echo "$(L "File not found: $HOSTS_FILE" "Dosya bulunamadı: $HOSTS_FILE")" > /dev/tty; exit 3; }
       d=$(ask "$(L "Action on every server: 1) Everything  2) General check  3) Quick check  4) Upgrade+mitigate  5) Apply  6) Rollback" "Her sunucuda işlem: 1) Her şey  2) Genel kontrol  3) Hızlı kontrol  4) Güncelle+önlem  5) Önlem uygula  6) Geri al") [1]: " 1)
       c=$d ;;
  esac
  case "$c" in
    1) MODE=upgrade; ALL=1; AUDIT=1; FULL_UPGRADE=1; DO_SCAN=1 ;;
    2) MODE=check; AUDIT=1; DO_SCAN=1 ;;
    3) MODE=check ;;
    4) MODE=upgrade ;;
    5) MODE=apply ;;
    6) MODE=rollback ;;
    *) echo "$(L "Invalid choice" "Geçersiz seçim")" > /dev/tty; exit 3 ;;
  esac
  [ $ALL -eq 1 ] && return 0   # "everything": no further questions, confirm_all shows the plan
  if [ "$MODE" = upgrade ]; then
    yesno "$(L "Also upgrade ALL other system packages (full upgrade, not only PHP)?" "PHP dışındaki TÜM sistem paketleri de güncellensin mi (tam güncelleme)?")" && FULL_UPGRADE=1
  fi
  if [ "$MODE" = upgrade ] || [ "$MODE" = apply ]; then
    {
      echo
      echo "  $(L "Strict mode adds the CVE-2026-109618 (OOM) mitigations:" "Strict mod CVE-2026-109618 (OOM) önlemlerini de ekler:")"
      echo "  memory_limit=-1, post_max_size=32M, upload_max_filesize=30M"
      echo "  ${Y}!${N} $(L "needs a cgroup/LVE memory limit; may break uploads larger than 30M" "cgroup/LVE bellek sınırı şart; 30M'den büyük yüklemeleri bozabilir")"
    } > /dev/tty
    yesno "$(L "Enable strict mode?" "Strict mod açılsın mı?")" && STRICT=1
  fi
  if [ $DO_SCAN -eq 0 ] && [ "$MODE" != rollback ]; then
    yesno "$(L "Also run the read-only IOC scan?" "Salt-okunur IOC taraması da yapılsın mı?")" && DO_SCAN=1
  fi
  if [ $DO_SCAN -eq 1 ]; then
    SCAN_DAYS=$(ask "$(L "Scan files changed in the last N days" "Son kaç günde değişen dosyalar taransın") [3]: " 3)
    case "$SCAN_DAYS" in ''|*[!0-9]*) SCAN_DAYS=3 ;; esac
  fi
  if [ "$MODE" != check ]; then
    echo > /dev/tty
    yesno "$(L "Mode: $MODE$([ $FULL_UPGRADE -eq 1 ] && echo " +full")$([ $STRICT -eq 1 ] && echo " +strict")${HOSTS_FILE:+ on servers in $HOSTS_FILE} — PHP config will be changed and workers restarted. Continue?" \
               "Mod: $MODE$([ $FULL_UPGRADE -eq 1 ] && echo " +full")$([ $STRICT -eq 1 ] && echo " +strict")${HOSTS_FILE:+ ($HOSTS_FILE sunucularında)} — PHP ayarları değişecek ve süreçler yeniden başlatılacak. Devam?")" \
      || { echo "$(L "Cancelled." "İptal edildi.")" > /dev/tty; exit 0; }
  fi
}
if { [ $ARGC -eq 0 ] || [ $FORCE_MENU -eq 1 ]; } && [ -t 1 ] && { : < /dev/tty; } 2>/dev/null; then
  run_menu
fi

# ---------------------------------------------------------------------
#  Fleet mode: send this file to each host over SSH (remote temp file), then summarize
# ---------------------------------------------------------------------
if [ -n "$HOSTS_FILE" ]; then
  [ -f "$HOSTS_FILE" ] || { echo "$(L "hosts file not found: $HOSTS_FILE" "sunucu listesi bulunamadı: $HOSTS_FILE")" >&2; exit 3; }
  SELF="${BASH_SOURCE[0]}"
  [ -f "$SELF" ] || { echo "$(L "Fleet mode needs the script as a file (not curl | bash)." "Filo modu için script'i dosyadan çalıştır (curl | bash ile değil).")" >&2; exit 3; }
  OUT="./php2shell_logs_$(date +%Y%m%d_%H%M%S)"; mkdir -p "$OUT" || exit 3
  confirm_all "$HOSTS_FILE"   # asked once here; remotes get --yes
  # explicit flags → the remote side never opens the menu
  if [ $ALL -eq 1 ]; then
    RARGS=(--all --yes "--lang=$UI_LANG")
  else
    RARGS=("--$MODE" "--lang=$UI_LANG")
    [ $AUDIT -eq 1 ]        && RARGS+=(--audit)
    [ $FULL_UPGRADE -eq 1 ] && RARGS+=(--full-upgrade)
  fi
  [ $STRICT -eq 1 ]    && RARGS+=(--strict)
  [ $DO_SCAN -eq 1 ]   && RARGS+=("--scan=$SCAN_DAYS")
  [ $DO_RELOAD -eq 0 ] && RARGS+=(--no-reload)
  # The script is first written to a remote temp file and run with stdin=/dev/null:
  # with "bash -s" any command that reads stdin (apt, cagefsctl, …) could swallow the
  # rest of the script. The temp file is removed afterwards. POSIX sh syntax on purpose
  # (root's login shell may not be bash).
  RENV="FIXED_VERSIONS=$(printf '%q' "$FIXED_VERSIONS") FIXED_VERSIONS_UP=$(printf '%q' "$FIXED_VERSIONS_UP")"
  RCMD="t=\$(mktemp /tmp/php2shell_fix.XXXXXX) && cat > \"\$t\" && $RENV bash \"\$t\" $(printf '%q ' "${RARGS[@]}") </dev/null; rc=\$?; rm -f \"\$t\"; exit \$rc"
  SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=15)
  SUMMARY=(); WORST=0
  while read -r host port user _; do
    case "$host" in ''|\#*) continue ;; esac
    port="${port:-22}"; user="${user:-root}"
    section "$user@$host:$port"
    if ! ssh -n "${SSH_OPTS[@]}" -p "$port" "$user@$host" true 2>/dev/null; then
      bad "$(L "SSH connection failed" "SSH bağlantısı kurulamadı")"; rc=255
    else
      # strip \r in case the file was checked out with CRLF line endings
      ssh "${SSH_OPTS[@]}" -p "$port" "$user@$host" "$RCMD" \
          < <(tr -d '\r' < "$SELF") 2>&1 | tee "$OUT/$host.log"
      rc=${PIPESTATUS[0]}
    fi
    case "$rc" in
      0)   d="${G}$(L "PATCHED" "YAMALI")${N}" ;;
      1)   d="${Y}$(L "MITIGATED, AWAITING PATCH" "ÖNLEM AKTİF, YAMA BEKLİYOR")${N}" ;;
      2)   d="${R}$(L "AT RISK: EOL / unmitigated install" "RİSK: EOL / önlemsiz kurulum")${N}" ;;
      255) d="${R}$(L "SSH connection failure" "SSH bağlantı hatası")${N}" ;;
      *)   d="${R}$(L "script error" "script hatası") ($rc)${N}" ;;
    esac
    SUMMARY+=("$(printf '  %-34s %3s  %s' "$host" "$rc" "$d")")
    [ "$rc" -gt "$WORST" ] && WORST=$rc
  done < "$HOSTS_FILE"
  section "$(L "FLEET SUMMARY" "FİLO ÖZETİ") ($(L "logs" "loglar"): $OUT)"
  printf '  %-34s %3s  %s\n' "$(L HOST SUNUCU)" "RC" "$(L STATUS DURUM)"
  printf '%s\n' "${SUMMARY[@]}"
  exit "$WORST"
fi

[ "$(id -u)" -eq 0 ] || { echo "$(L "Must run as root (or use --hosts for fleet mode)." "Root olarak çalıştırılmalı (ya da --hosts ile filo modu).")" >&2; exit 3; }
confirm_all ""

TS=$(date +%Y%m%d_%H%M%S)
LOG="/root/php2shell_fix_${TS}.log"
BACKUP_DIR="/root/php2shell_backup_${TS}"
exec > >(tee -a "$LOG") 2>&1

# ---------------------------------------------------------------------
#  Environment
# ---------------------------------------------------------------------
OS_NAME=$( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}" )
PANELS=()
[ -d /usr/local/cpanel ] && PANELS+=("cPanel $(cat /usr/local/cpanel/version 2>/dev/null)")
if [ -d /usr/local/psa ] || [ -d /opt/psa ]; then
  PANELS+=("Plesk $(awk '{print $1}' /usr/local/psa/version /opt/psa/version 2>/dev/null | head -n1)")
fi
[ -d /usr/local/mgr5 ] && PANELS+=("ISPmanager")
[ -d /usr/local/directadmin ] && PANELS+=("DirectAdmin")
[ -d /usr/local/lsws ] && PANELS+=("LiteSpeed $(cat /usr/local/lsws/VERSION 2>/dev/null)")
{ [ -f /etc/cloudlinux-release ] || grep -qi cloudlinux /etc/os-release 2>/dev/null; } && PANELS+=("CloudLinux")

section "php2shell_fix — $(hostname -f 2>/dev/null || hostname) — $(L mode mod): $(if [ $ALL -eq 1 ]; then L "all (everything)" "all (her şey)"; else echo "$MODE"; [ $AUDIT -eq 1 ] && L " (general check)" " (genel kontrol)"; fi)"
info "OS      : $OS_NAME"
info "Panel   : ${PANELS[*]:-$(L "(none detected)" "(tespit edilemedi)")}"
info "Log     : $LOG"
info "$(L "Fixed in" "Yamalı  "): $FIXED_VERSIONS  (php.net 2026-10-21)"
[ $STRICT -eq 1 ] && info "Strict  : $(L "on (adds CVE-2026-109618 OOM mitigations)" "açık (CVE-2026-109618 OOM önlemleri eklenir)")"

# ---------------------------------------------------------------------
#  Version helpers
# ---------------------------------------------------------------------
ver_ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$2" ]; }   # $1 >= $2
clean_ver() { local v="${1%%[-+~ ]*}"; echo "$v"; }
branch_of() { echo "$1" | cut -d. -f1,2; }
fixed_for() {   # fixed_for BRANCH [TABLE]
  local kv
  for kv in ${2-$FIXED_VERSIONS}; do [ "${kv%%=*}" = "$1" ] && { echo "${kv#*=}"; return 0; }; done
  return 1
}
# CVE-2026-115560: PATCHED (version ≥ FIXED_VERSIONS_UP) | BACKPORTED (changelog) | PENDING
up_status() {   # up_status VERSION PKGBIN
  local v br fx
  v=$(clean_ver "$1"); br=$(branch_of "$v")
  if fx=$(fixed_for "$br" "$FIXED_VERSIONS_UP") && ver_ge "$v" "$fx"; then echo PATCHED
  elif vendor_backported "$2" "$CVE_RE_UP"; then echo BACKPORTED
  else echo PENDING
  fi
}
# PATCHED | UNPATCHED | EOL | UNKNOWN
patch_status() {
  local v br fx
  v=$(clean_ver "$1"); br=$(branch_of "$v")
  if fx=$(fixed_for "$br"); then
    ver_ge "$v" "$fx" && echo PATCHED || echo UNPATCHED
  elif ! ver_ge "$br" "8.2"; then
    echo EOL
  else
    echo UNKNOWN
  fi
}
kind_of() {
  case "$1" in
    /opt/cpanel/*)                 echo "cPanel EA4" ;;
    /opt/alt/*)                    echo "CloudLinux alt-php" ;;
    /opt/plesk/*)                  echo "Plesk" ;;
    /opt/php[0-9]*)                echo "ISPmanager" ;;
    /usr/local/lsws/*)             echo "LiteSpeed lsphp" ;;
    /opt/remi/*|/etc/opt/remi/*)   echo "Remi SCL" ;;
    /usr/local/php[0-9]*)          echo "DirectAdmin" ;;
    /etc/php*|/usr/bin/*|/usr/sbin/*) echo "Distro" ;;
    *)                             echo "Other" ;;
  esac
}
php_bin_ver() { env -u PHP_INI_SCAN_DIR timeout 15 "$1" -n "${PHPQ[@]}" -r 'echo PHP_VERSION;' 2>/dev/null; }
# "UP|HANDLER": UP 1 = enabled (exposed) | 0 = disabled | NA = no session extension;
# HANDLER = session.serialize_handler (php_binary / php_serialize = CVE-2026-115560 precondition)
php_session_ini() {
  env -u PHP_INI_SCAN_DIR timeout 15 "$1" "${PHPQ[@]}" -r '$v=ini_get("session.upload_progress.enabled"); echo $v===false?"NA":($v?"1":"0"),"|",(string)ini_get("session.serialize_handler");' 2>/dev/null
}
# Distros / CloudLinux / LTS vendors backport fixes under the old version
# number → look for the CVE in the owning package's changelog.
declare -A VB_CACHE CL_CACHE
pkg_changelog() {   # changelog text of the package owning $1 (cached)
  local bin="$1" pkg f
  if [ -z "${CL_CACHE[$bin]+x}" ]; then
    CL_CACHE[$bin]=""
    # e.g. CloudLinux ea-php84 8.4.26-2.elX.cloudlinux.1 / alt-php82: fixed, version unchanged
    if command -v rpm >/dev/null 2>&1 && pkg=$(rpm -qf "$bin" 2>/dev/null | head -n1) && [ -n "$pkg" ]; then
      CL_CACHE[$bin]=$(rpm -q --changelog "$pkg" 2>/dev/null | grep -E 'CVE-[0-9]{4}-[0-9]+')
    elif command -v dpkg >/dev/null 2>&1 && pkg=$(dpkg -S "$bin" 2>/dev/null | head -n1 | cut -d: -f1) && [ -n "$pkg" ]; then
      for f in /usr/share/doc/"$pkg"/changelog.Debian.gz /usr/share/doc/"$pkg"/changelog.gz; do
        [ -f "$f" ] && { CL_CACHE[$bin]=$(zgrep -E 'CVE-[0-9]{4}-[0-9]+' "$f" 2>/dev/null); break; }
      done
    fi
  fi
  printf '%s' "${CL_CACHE[$bin]}"
}
vendor_backported() {   # vendor_backported BIN [CVE_REGEX]
  [ -n "$1" ] || return 1
  local t; t=$(pkg_changelog "$1")
  # here-string, not a pipe: with pipefail, "… | grep -q" can report a false "no match"
  # when grep exits early on a large changelog and the writer gets SIGPIPE
  grep -qE "${2:-$CVE_RE}" <<<"$t"
}
# Drop-in content. $1 = target index, $2 = full | needed
#   full   : every official mitigation (--apply, or PHP2Shell not patched)
#   needed : PHP2Shell patched but CVE-2026-115560 pending → upload_progress line only
dropin_body() {
  local i=$1 br full=0
  br=$(branch_of "$(clean_ver "${T_VER[$i]}")")
  { [ "$2" = full ] || ! is_patched "$i"; } && full=1
  printf '%s\n' \
    "; php2shell (CVE-2026-109618 / CVE-2026-109619) + CVE-2026-115560 temporary mitigation" \
    "; written by php2shell_fix.sh — per php.net this is NOT a complete fix; upgrade PHP." \
    "; Remove with \"php2shell_fix.sh --rollback\" (or --upgrade does it once fully patched)." \
    "session.upload_progress.enabled = Off"
  if [ $full -eq 1 ]; then
    ver_ge "$br" "8.5" && echo "fatal_error_backtraces = Off"
    [ $STRICT -eq 1 ] && printf '%s\n' "memory_limit = -1" "post_max_size = 32M" "upload_max_filesize = 30M"
  fi
  return 0
}

# ---------------------------------------------------------------------
#  Upgrade (runs BEFORE discovery so the report shows new versions)
# ---------------------------------------------------------------------
PKG_RE='^(ea-php[0-9]+|alt-php[0-9]+|plesk-php[0-9]+|isp-php[0-9]+|lsphp[0-9]+|libapache2-mod-php[0-9.]*|php[0-9.]*)(-|$)'
PM=""
command -v dnf >/dev/null 2>&1 && PM=dnf
[ -z "$PM" ] && command -v yum >/dev/null 2>&1 && PM=yum
[ -z "$PM" ] && command -v apt-get >/dev/null 2>&1 && PM=apt
APT_OPTS=(-o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef)
do_upgrade() {
  if [ $FULL_UPGRADE -eq 1 ]; then
    section "$(L "Full system package upgrade" "Tüm sistem paketlerinin güncellemesi")"
  else
    section "$(L "PHP package upgrade" "PHP paket güncellemesi")"
  fi
  local pkgs=() rc=0 x
  case "$PM" in
    dnf|yum)
      mapfile -t pkgs < <(rpm -qa --qf '%{NAME}\n' 2>/dev/null | grep -E "$PKG_RE" | sort -u)
      # vendors are rolling fixes out hour by hour → don't trust cached metadata
      "$PM" clean expire-cache >/dev/null 2>&1 </dev/null
      "$PM" -y makecache >/dev/null 2>&1 </dev/null
      # --skip-broken: one package with a dependency problem must not block all the others.
      # dnf best=False: take the newest *installable* build instead of aborting with the
      # "try --nobest / --allowerasing" hint. --allowerasing is deliberately NOT used:
      # it may remove other packages to resolve conflicts.
      local pmo=(-y --skip-broken)
      [ "$PM" = dnf ] && pmo+=(--setopt=best=False)
      if [ $FULL_UPGRADE -eq 1 ]; then
        "$PM" "${pmo[@]}" upgrade </dev/null || rc=1
      elif [ ${#pkgs[@]} -gt 0 ]; then
        info "$PM: ${#pkgs[@]} $(L packages paket) (${pkgs[0]} …)"
        "$PM" "${pmo[@]}" upgrade "${pkgs[@]}" </dev/null || rc=1
      else
        warn "$(L "No PHP packages found to upgrade." "Güncellenecek PHP paketi bulunamadı.")"
      fi
      # things that silently keep packages back
      x=$(grep -hE '^[[:space:]]*exclude[[:space:]]*=' /etc/yum.conf /etc/dnf/dnf.conf /etc/yum.repos.d/*.repo 2>/dev/null \
          | grep -oE '[^ =,]*php[^ ,]*' | sort -u | tr '\n' ' ')
      [ -n "$x" ] && info "$(L "yum/dnf exclude rules mentioning php (packages matching them are never upgraded): $x" \
                               "php içeren yum/dnf exclude kuralları (eşleşen paketler hiç güncellenmez): $x")"
      x=$("$PM" -q versionlock list 2>/dev/null | grep -iE 'php' | tr '\n' ' ')
      [ -n "$x" ] && warn "$(L "versionlock holds PHP packages: $x" "versionlock PHP paketlerini kilitliyor: $x")"
      ;;
    apt)
      mapfile -t pkgs < <(dpkg-query -W -f='${Package} ${Status}\n' 2>/dev/null \
                           | awk '$NF=="installed"{print $1}' | grep -E "$PKG_RE" | sort -u)
      apt-get "${APT_OPTS[@]}" update -q >/dev/null </dev/null || warn "$(L "apt-get update reported errors (a repo may be unreachable)" "apt-get update hata verdi (bir repo erişilemiyor olabilir)")"
      if [ $FULL_UPGRADE -eq 1 ]; then
        DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get -y -q "${APT_OPTS[@]}" upgrade </dev/null || rc=1
      elif [ ${#pkgs[@]} -gt 0 ]; then
        info "apt: ${#pkgs[@]} $(L packages paket) (${pkgs[0]} …)"
        DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install -y -q --only-upgrade "${APT_OPTS[@]}" "${pkgs[@]}" </dev/null || rc=1
      else
        warn "$(L "No PHP packages found to upgrade." "Güncellenecek PHP paketi bulunamadı.")"
      fi
      x=$(apt-mark showhold 2>/dev/null | grep -E "$PKG_RE" | tr '\n' ' ')
      [ -n "$x" ] && warn "$(L "packages on hold (never upgraded): $x — release with: apt-mark unhold <pkg>" \
                               "bekletilen (hold) paketler, hiç güncellenmez: $x — açmak için: apt-mark unhold <paket>")"
      ;;
    *) bad "$(L "No supported package manager (dnf/yum/apt)" "Desteklenen paket yöneticisi yok (dnf/yum/apt)")"; rc=1 ;;
  esac
  [ $rc -eq 0 ] || bad "$(L "package manager reported an error — see the output above / $LOG" "paket yöneticisi hata verdi — yukarıdaki çıktıya / $LOG dosyasına bak")"

  # Panels that manage PHP outside (or not only through) the OS package manager
  if command -v plesk >/dev/null 2>&1; then
    info "$(L "Plesk: updating installed components (incl. PHP handlers) with plesk installer…" \
              "Plesk: kurulu bileşenler (PHP handler'ları dahil) plesk installer ile güncelleniyor…")"
    plesk installer --select-release-current --upgrade-installed-components </dev/null \
      && ok "$(L "plesk installer done" "plesk installer tamam")" \
      || { bad "$(L "plesk installer failed" "plesk installer hata verdi")"; rc=1; }
  fi
  if [ -x /usr/local/directadmin/custombuild/build ]; then
    info "$(L "DirectAdmin: PHP is compiled by CustomBuild — running './build update' and './build php' (can take a while)…" \
              "DirectAdmin: PHP CustomBuild ile derleniyor — './build update' ve './build php' çalıştırılıyor (uzun sürebilir)…")"
    ( cd /usr/local/directadmin/custombuild && ./build update && ./build php ) </dev/null \
      && ok "$(L "CustomBuild PHP rebuild done" "CustomBuild PHP derlemesi tamam")" \
      || { bad "$(L "CustomBuild failed — check custombuild output above" "CustomBuild hata verdi — yukarıdaki çıktıya bak")"; rc=1; }
  fi
  [ $rc -eq 0 ] && ok "$(L "Upgrade step done (versions stay the same where the vendor has not published a fix yet)" \
                            "Güncelleme adımı tamam (vendor yamayı yayınlamadıysa sürüm aynı kalır)")"
  return $rc
}
# Why is an installation still unpatched? Newer build in the repo (= install failed / held)
# or no newer build at all (= vendor has not published it / repo missing).
repo_candidate() {   # repo_candidate BIN → "pkg installed→candidate" when a newer build exists
  local bin="$1" pkg cur cand
  [ -n "$bin" ] || return 1
  case "$PM" in
    dnf|yum)
      pkg=$(rpm -qf --qf '%{NAME}\n' "$bin" 2>/dev/null | head -n1) || return 1
      [ -n "$pkg" ] || return 1
      cur=$(rpm -q --qf '%{VERSION}-%{RELEASE}\n' "$pkg" 2>/dev/null | head -n1)
      # dnf4 + dnf5: "list --upgrades"; yum (EL7): "list updates"
      cand=$( { if [ "$PM" = dnf ]; then dnf -q list --upgrades "$pkg"; else yum -q list updates "$pkg"; fi; } 2>/dev/null | awk -v p="$pkg" 'index($1, p".")==1 {print $2}' | tail -n1) ;;
    apt)
      pkg=$(dpkg -S "$bin" 2>/dev/null | head -n1 | cut -d: -f1)
      [ -n "$pkg" ] || return 1
      read -r cur cand < <(apt-cache policy "$pkg" 2>/dev/null | awk '/Installed:/{i=$2} /Candidate:/{c=$2} END{print i, c}') ;;
    *) return 1 ;;
  esac
  [ -n "$cand" ] && [ "$cand" != "$cur" ] && [ "$cand" != "(none)" ] && { echo "$pkg $cur → $cand"; return 0; }
  return 1
}
repo_pkg_name() {   # owning package name of BIN (for messages)
  case "$PM" in
    dnf|yum) rpm -qf --qf '%{NAME}\n' "$1" 2>/dev/null | head -n1 ;;
    apt)     dpkg -S "$1" 2>/dev/null | head -n1 | cut -d: -f1 ;;
  esac
}
# General check: refresh package metadata so "newer build in the repo?" is current.
# Touches only the package-manager cache, never installed packages or PHP config.
refresh_metadata() {
  section "$(L "Refreshing package metadata (installed packages are not touched)" "Paket listeleri yenileniyor (kurulu paketlere dokunulmaz)")"
  case "$PM" in
    dnf|yum)
      "$PM" clean expire-cache >/dev/null 2>&1 </dev/null
      "$PM" -q makecache >/dev/null 2>&1 </dev/null && ok "$PM makecache" \
        || warn "$(L "$PM makecache failed — a repository may be unreachable or misconfigured" "$PM makecache hata verdi — bir repo erişilemiyor ya da hatalı olabilir")" ;;
    apt)
      apt-get "${APT_OPTS[@]}" update -q >/dev/null 2>&1 </dev/null && ok "apt-get update" \
        || warn "$(L "apt-get update failed — a repository may be unreachable or misconfigured" "apt-get update hata verdi — bir repo erişilemiyor ya da hatalı olabilir")" ;;
  esac
}
# Processes still running a binary that an upgrade has replaced ("… (deleted)"):
# the new, patched build is installed but NOT active until they restart.
stale_workers() {   # → "<count> <binary>" lines; $1 = php | web
  local p exe
  for p in /proc/[0-9]*; do
    exe=$(readlink "$p/exe" 2>/dev/null) || continue
    case "$exe" in *" (deleted)") ;; *) continue ;; esac
    exe="${exe% (deleted)}"
    case "$1:${exe##*/}" in
      php:php*|php:lsphp*) echo "$exe" ;;
      web:httpd*|web:apache2*|web:litespeed*|web:lshttpd*|web:nginx*) echo "$exe" ;;
    esac
  done | sort | uniq -c | awk '{print $1" "$2}'
}
[ $AUDIT -eq 1 ] && [ "$MODE" != upgrade ] && refresh_metadata
[ "$MODE" = upgrade ] && { do_upgrade || UPGRADE_FAILED=1; }

# ---------------------------------------------------------------------
#  Discovery: one target = one ini scan dir (or php.ini if there is none)
# ---------------------------------------------------------------------
T_DIR=(); T_VER=(); T_BIN=(); T_INI=(); T_KIND=(); T_PKGBIN=(); T_ST=()
declare -A SEEN_DIR SEEN_BIN
add_target() {   # dir ver bin ini [binary used for the package-changelog check]
  local key="${1:-ini:$4}"
  [ -n "${SEEN_DIR[$key]}" ] && return 0
  SEEN_DIR[$key]=1
  T_DIR+=("$1"); T_VER+=("$2"); T_BIN+=("$3"); T_INI+=("$4"); T_KIND+=("$(kind_of "${3:-$1}")")
  T_PKGBIN+=("${5:-$3}")
}
probe_bin() {
  local b out ver scan ini d dirs=()
  b=$(readlink -f "$1" 2>/dev/null) || return 0
  [ -f "$b" ] && [ -x "$b" ] || return 0
  [ -n "${SEEN_BIN[$b]}" ] && return 0
  SEEN_BIN[$b]=1
  out=$(env -u PHP_INI_SCAN_DIR timeout 15 "$b" "${PHPQ[@]}" -r \
        'echo PHP_VERSION,"|",PHP_CONFIG_FILE_SCAN_DIR,"|",(string)php_ini_loaded_file();' 2>/dev/null) || return 0
  IFS='|' read -r ver scan ini <<<"$out"
  [ -n "$ver" ] || return 0
  if [ -n "$scan" ]; then
    IFS=':' read -ra dirs <<<"$scan"
    for d in "${dirs[@]}"; do
      [ -n "$d" ] && add_target "$(readlink -m "$d")" "$ver" "$b" "$ini"
    done
  else
    add_target "" "$ver" "$b" "$ini"
  fi
}

for b in /opt/cpanel/ea-php*/root/usr/bin/php \
         /opt/alt/php*/usr/bin/php \
         /opt/plesk/php/*/bin/php \
         /opt/php*/bin/php \
         /usr/local/lsws/lsphp*/bin/php \
         /opt/remi/php*/root/usr/bin/php \
         /usr/local/php*/bin/php \
         /usr/bin/php /usr/bin/php[0-9]* /usr/local/bin/php; do
  [ -e "$b" ] && probe_bin "$b"
done

# Debian/Ubuntu layout: every SAPI (fpm, apache2, cgi, litespeed…) has its own conf.d
for d in /etc/php/*/*/conf.d /usr/local/lsws/lsphp*/etc/php/*/*/conf.d; do
  [ -d "$d" ] || continue
  d=$(readlink -m "$d")
  br=$(echo "$d" | sed -nE 's#.*/php/([0-9]+\.[0-9]+)/.*#\1#p')
  v=""; pb=""
  case "$d" in
    /usr/local/lsws/*) lb="${d%%/etc/*}/bin/php"; [ -x "$lb" ] && { v=$(php_bin_ver "$lb"); pb="$lb"; } ;;
    *) [ -x "/usr/bin/php$br" ] && v=$(php_bin_ver "/usr/bin/php$br")
       for c in "/usr/bin/php$br" "/usr/sbin/php-fpm$br" "/usr/bin/php-cgi$br"; do [ -x "$c" ] && { pb="$c"; break; }; done ;;
  esac
  add_target "$d" "${v:-$br}" "" "" "$pb"
done

if [ ${#T_DIR[@]} -eq 0 ]; then
  section "$(L Result Sonuç)"; warn "$(L "No PHP installation found on this server." "Bu sunucuda PHP kurulumu bulunamadı.")"; exit 0
fi

# Patch status per target: upstream version first, then vendor backport (changelog)
T_UP=()
for i in "${!T_DIR[@]}"; do
  [ -n "${T_PKGBIN[$i]}" ] && pkg_changelog "${T_PKGBIN[$i]}" >/dev/null   # fill the cache in this shell
  st=$(patch_status "${T_VER[$i]}")
  [ "$st" != PATCHED ] && vendor_backported "${T_PKGBIN[$i]}" && st=BACKPORTED
  T_ST+=("$st")
  T_UP+=("$(up_status "${T_VER[$i]}" "${T_PKGBIN[$i]}")")
done
is_patched()    { case "${T_ST[$1]}" in PATCHED|BACKPORTED) return 0 ;; esac; return 1; }   # PHP2Shell
up_patched()    { [ "${T_UP[$1]}" != PENDING ]; }                                         # CVE-2026-115560
fully_patched() { is_patched "$1" && up_patched "$1"; }

# ---------------------------------------------------------------------
#  Apply / Rollback
# ---------------------------------------------------------------------
backup_file() {
  mkdir -p "$BACKUP_DIR" && cp -a --parents "$1" "$BACKUP_DIR/" 2>/dev/null
}
apply_target() {
  local i=$1 dir="${T_DIR[$1]}" ini="${T_INI[$1]}" f body
  body=$(dropin_body "$1" "${2:-full}")
  if [ -n "$dir" ]; then
    f="$dir/$DROPIN_NAME"
    if [ -f "$f" ] && [ "$(cat "$f")" = "$body" ]; then
      info "$(L "present : $f" "zaten var: $f")"; return 0
    fi
    mkdir -p "$dir" && printf '%s\n' "$body" > "$f" && chmod 644 "$f" \
      && ok "$(L "written : $f" "yazıldı  : $f")" || { bad "$(L "failed  : $f" "yazılamadı: $f")"; return 1; }
  elif [ -n "$ini" ] && [ -f "$ini" ]; then
    backup_file "$ini"
    # replace an older block (e.g. re-run with --strict) instead of stacking blocks
    grep -qF "$INI_MARK_BEGIN" "$ini" && sed -i "\#^${INI_MARK_BEGIN}\$#,\#^${INI_MARK_END}\$#d" "$ini"
    printf '\n%s\n%s\n%s\n' "$INI_MARK_BEGIN" "$body" "$INI_MARK_END" >> "$ini" \
      && ok "$(L "appended: $ini (no scan dir → block at end of php.ini)" "eklendi  : $ini (scan dizini yok → php.ini sonuna blok)")" \
      || { bad "$(L "failed  : $ini" "yazılamadı: $ini")"; return 1; }
  else
    bad "${T_BIN[$i]}: $(L "neither a scan dir nor a php.ini → fix manually" "ne scan dizini ne php.ini var → elle müdahale gerekli")"; return 1
  fi
}
rollback_target() {
  local dir="${T_DIR[$1]}" ini="${T_INI[$1]}" f
  if [ -n "$dir" ]; then
    f="$dir/$DROPIN_NAME"
    if [ -f "$f" ] && grep -q 'php2shell_fix.sh' "$f"; then
      backup_file "$f"; rm -f "$f" && ok "$(L "removed : $f" "kaldırıldı: $f")"
    fi
  elif [ -n "$ini" ] && [ -f "$ini" ] && grep -qF "$INI_MARK_BEGIN" "$ini"; then
    backup_file "$ini"
    sed -i "\#^${INI_MARK_BEGIN}\$#,\#^${INI_MARK_END}\$#d" "$ini" && ok "$(L "removed : block in $ini" "kaldırıldı: $ini içindeki blok")"
  fi
}
st_label() {   # internal status → display label (ASCII so the table stays aligned)
  case "$1" in
    PATCHED)    L "PATCHED" "YAMALI" ;;
    BACKPORTED) L "BACKPORTED" "BACKPORT" ;;
    UNPATCHED)  L "UNPATCHED" "YAMASIZ" ;;
    EOL)        echo "EOL" ;;
    *)          L "UNKNOWN" "BILINMIYOR" ;;
  esac
}

CHANGED=0; HARD_RESTART=0
case "$MODE" in
  upgrade)
    section "$(L "Per installation: fully patched → remove mitigation · otherwise → keep/apply what is still needed" \
                 "Kurulum bazında: tamamen yamalı → önlemi kaldır · değilse → hâlâ gereken önlemi koru/uygula")"
    for i in "${!T_DIR[@]}"; do
      if fully_patched "$i"; then
        info "$(st_label "${T_ST[$i]}"): ${T_KIND[$i]} ${T_VER[$i]}"
        rollback_target "$i"
      else
        # PHP2Shell patched but CVE-2026-115560 pending → only upload_progress stays off
        is_patched "$i" && info "$(st_label "${T_ST[$i]}") + CVE-2026-115560 $(L pending bekliyor): ${T_KIND[$i]} ${T_VER[$i]}"
        apply_target "$i" needed || APPLY_FAILED=1
      fi
    done
    CHANGED=1; HARD_RESTART=1 ;;   # new binaries → restart workers, not just reload
  apply)
    section "$(L "Applying mitigation to every installation" "Her kuruluma önlem uygulanıyor")"
    for i in "${!T_DIR[@]}"; do apply_target "$i" || APPLY_FAILED=1; done
    CHANGED=1 ;;
  rollback)
    section "$(L "Rollback" "Geri alma")"
    for i in "${!T_DIR[@]}"; do
      fully_patched "$i" || warn "${T_KIND[$i]} ${T_VER[$i]} $(L "is NOT fully patched (PHP2Shell / CVE-2026-115560) — removing the mitigation re-exposes it" \
                                                              "tamamen yamalı DEĞİL (PHP2Shell / CVE-2026-115560) — önlem kaldırılınca açık yeniden etkin olur")"
      rollback_target "$i"
    done
    CHANGED=1 ;;
esac
if [ $STRICT -eq 1 ] && { [ "$MODE" = apply ] || [ "$MODE" = upgrade ]; }; then
  command -v lvectl >/dev/null 2>&1 \
    || warn "$(L "--strict: memory_limit=-1 without a cgroup/LVE memory limit lets one request exhaust RAM — add one (e.g. systemd MemoryMax on the FPM service)" \
                 "--strict: cgroup/LVE bellek sınırı olmadan memory_limit=-1 tek bir isteğin tüm RAM'i tüketmesine izin verir — sınır ekle (ör. FPM servisine systemd MemoryMax)")"
  warn "$(L "--strict: apps can still raise memory_limit via ini_set(); for full effect also set php_admin_value[memory_limit]=-1 in FPM pools / vhost config" \
            "--strict: uygulamalar memory_limit'i ini_set() ile yine yükseltebilir; tam etki için FPM pool / vhost ayarına php_admin_value[memory_limit]=-1 ekle")"
fi

# ---------------------------------------------------------------------
#  Reload: php-fpm (graceful), lsphp (kill → respawns with fresh config),
#  mod_php (apache graceful). php-cgi/suPHP read the ini on every request.
# ---------------------------------------------------------------------
reload_php() {
  section "$(L "Reloading PHP workers" "PHP süreçleri yeniden başlatılıyor")"
  local u ac any=0
  while read -r u; do
    [ -n "$u" ] || continue
    if { [ $HARD_RESTART -eq 0 ] && systemctl reload "$u" 2>/dev/null; } || systemctl restart "$u" 2>/dev/null; then
      ok "fpm: $u"
    else
      bad "fpm: $u $(L "could not be reloaded" "yeniden başlatılamadı")"
    fi
    any=1
  done < <(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null \
           | awk '{print $1}' | grep -E 'php.*fpm')
  # LiteSpeed: a graceful restart keeps existing lsphp workers on the old config → kill them
  if pgrep -x 'lsphp[0-9]*' >/dev/null 2>&1; then
    pkill -x 'lsphp[0-9]*' && ok "$(L "lsphp workers terminated (respawn with fresh config on next request)" \
                                     "lsphp süreçleri sonlandırıldı (ilk istekte yeni ayarla açılır)")"
    any=1
  fi
  for ac in apachectl apache2ctl; do
    command -v "$ac" >/dev/null 2>&1 || continue
    if [ "$("$ac" -M 2>/dev/null | grep -ciE 'php[0-9]*_module')" -gt 0 ]; then
      "$ac" -k graceful 2>/dev/null && ok "apache graceful (mod_php)"; any=1
    fi
    break
  done
  if command -v cagefsctl >/dev/null 2>&1; then
    info "$(L "Updating CageFS skeleton (cagefsctl --force-update)…" "CageFS skeleton güncelleniyor (cagefsctl --force-update)…")"
    cagefsctl --force-update >/dev/null 2>&1 </dev/null && ok "$(L "CageFS updated" "CageFS güncellendi")" \
      || warn "$(L "cagefsctl --force-update failed" "cagefsctl --force-update hata verdi")"
  fi
  [ $any -eq 1 ] || info "$(L "no running php-fpm / lsphp / mod_php (CGI needs no reload)" "çalışan php-fpm / lsphp / mod_php yok (CGI için gerekmez)")"
}
if [ $CHANGED -eq 1 ]; then
  if [ $DO_RELOAD -eq 1 ]; then reload_php
  else warn "$(L "--no-reload: changes take effect only after PHP workers are restarted" "--no-reload: değişiklikler PHP süreçleri yeniden başlayınca etkili olur")"; fi
fi

# ---------------------------------------------------------------------
#  Report + verification
# ---------------------------------------------------------------------
section "$(L "Inventory and status" "Envanter ve durum")"
printf '  %-20s %-10s %-11s %-11s %-14s %s\n' "$(L TYPE TUR)" "$(L VERSION SURUM)" "PHP2SHELL" "CVE-115560" "$(L MITIGATION ONLEM)" "$(L "INI DIR" "INI DIZINI")"
N_EOL=0; N_UNPATCHED=0; N_EXPOSED=0; N_VENDOR=0; N_UP_PENDING=0; PLESK_NOTES=(); SER_RISK=()
for i in "${!T_DIR[@]}"; do
  ver="${T_VER[$i]}"; st="${T_ST[$i]}"; handler=""
  if [ -n "${T_BIN[$i]}" ]; then
    IFS='|' read -r upv handler <<<"$(php_session_ini "${T_BIN[$i]}")"
    case "$upv" in
      0)  mc=ACTIVE ;;
      1)  mc=NONE ;;
      NA) mc=NOSESS ;;
      *)  mc=UNK ;;   # binary did not answer → judge by the drop-in below
    esac
  fi
  if [ -n "${T_BIN[$i]}" ] && [ "$mc" != UNK ]; then
    :
  elif [ -f "${T_DIR[$i]}/$DROPIN_NAME" ]; then
    mc=FILE
  else
    mc=NONE
  fi
  case "$mc" in
    ACTIVE) mit=$(L ACTIVE AKTIF) ;;
    FILE)   mit=$(L "ACTIVE(file)" "AKTIF(dosya)") ;;
    NONE)   mit=$(L NONE YOK) ;;
    NOSESS) mit=$(L "no session" "session yok") ;;
    *)      mit="?" ;;
  esac
  case "$st" in
    PATCHED|BACKPORTED) col=$G ;;
    UNPATCHED) col=$Y; N_UNPATCHED=$((N_UNPATCHED+1)) ;;
    EOL)       col=$R; N_EOL=$((N_EOL+1)) ;;
    *)         col=$Y; N_UNPATCHED=$((N_UNPATCHED+1)) ;;
  esac
  if up_patched "$i"; then ucol=$G; ulbl=$(st_label "${T_UP[$i]}")
  else ucol=$Y; ulbl=$(L PENDING BEKLIYOR); N_UP_PENDING=$((N_UP_PENDING+1)); fi
  # exposed = a CVE is still open here and upload_progress is not disabled
  fully_patched "$i" || { [ "$mc" = NONE ] && N_EXPOSED=$((N_EXPOSED+1)); }
  # CVE-2026-115560 precondition #1 met (php_binary / php_serialize) while upload_progress is on
  case "$handler" in
    php_binary|php_serialize) up_patched "$i" || { [ "$mc" = NONE ] && SER_RISK+=("${T_KIND[$i]} $ver ($handler)"); } ;;
  esac
  [ "${T_KIND[$i]}" = "Distro" ] && ! is_patched "$i" && N_VENDOR=$((N_VENDOR+1))
  # Plesk rebuilt EOL branches without a version bump and its changelog may not name the CVEs
  if [ "${T_KIND[$i]}" = "Plesk" ] && ! is_patched "$i" && [ -n "${T_BIN[$i]}" ]; then
    PLESK_NOTES+=("$ver $("${T_BIN[$i]}" -v 2>/dev/null | grep -o 'built: [^)]*' | head -n1)")
  fi
  kind="${T_KIND[$i]}"; [ "$kind" = Distro ] && kind=$(L Distro Dagitim)
  printf '  %-20s %-10s %s%-11s%s %s%-11s%s %-14s %s\n' "$kind" "$ver" "$col" "$(st_label "$st")" "$N" \
         "$ucol" "$ulbl" "$N" "$mit" "${T_DIR[$i]:-${T_INI[$i]} (php.ini)}"
done

section "$(L Summary Özet)"
mapfile -t STALE_PHP < <(stale_workers php)
mapfile -t STALE_WEB < <(stale_workers web)
N_STALE=${#STALE_PHP[@]}
if [ $N_STALE -gt 0 ]; then
  bad "$(L "PHP processes still run a binary replaced by an upgrade — the installed fix is NOT active until they restart (run --upgrade, it restarts them):" \
           "PHP süreçleri güncellemeyle değiştirilmiş eski binary'yi çalıştırıyor — kurulan yama yeniden başlatılana kadar ETKİN DEĞİL (--upgrade çalıştır, yeniden başlatır):")"
  for l in "${STALE_PHP[@]}"; do info "    ${l#* }  ($(L processes süreç): ${l%% *})"; done
fi
if [ ${#STALE_WEB[@]} -gt 0 ]; then
  warn "$(L "Web server still runs a replaced binary — restart it to load the update:" "Web sunucusu hâlâ değiştirilmiş eski binary'yi çalıştırıyor — güncellemenin yüklenmesi için yeniden başlat:")"
  for l in "${STALE_WEB[@]}"; do info "    ${l#* }"; done
fi
[ $N_EOL -gt 0 ]       && bad  "$(L "$N_EOL EOL installation(s) (8.1 and older) without a vendor backport — no upstream release: keep the mitigation, migrate sites to 8.2+ or isolate them (WAF/VPN)" \
                                    "$N_EOL EOL kurulum (8.1 ve altı) vendor backport'u yok — resmi yama gelmeyecek: önlem kalsın, siteleri 8.2+'ya taşı ya da izole et (WAF/VPN)")"
[ $N_EXPOSED -gt 0 ]   && bad  "$(L "$N_EXPOSED installation(s) with an open CVE and session.upload_progress still ENABLED → run with --upgrade (or --apply)" \
                                    "$N_EXPOSED kurulumda açık CVE var ve session.upload_progress hâlâ AÇIK → --upgrade (ya da --apply) ile çalıştır")"
for s in "${SER_RISK[@]}"; do
  bad "$(L "CVE-2026-115560 precondition met: $s with upload_progress enabled" "CVE-2026-115560 ön koşulu sağlanıyor: $s ve upload_progress açık")"
done
[ $N_UNPATCHED -gt 0 ] && warn "$(L "$N_UNPATCHED supported installation(s) still without the PHP2Shell fix — the vendor repo may not have it yet; re-run --upgrade later" \
                                    "$N_UNPATCHED desteklenen kurulumda PHP2Shell yaması hâlâ yok — vendor reposu henüz yayınlamamış olabilir; --upgrade'i sonra tekrar çalıştır")"
# Why is it still unpatched? → newer build in the repo (install failed / held back)
# or no newer build at all (vendor has not published it / repo missing or disabled)
declare -A SEEN_PKG
for i in "${!T_DIR[@]}"; do
  is_patched "$i" && continue
  pb="${T_PKGBIN[$i]}"; [ -n "$pb" ] || continue
  pn=$(repo_pkg_name "$pb"); [ -n "$pn" ] || continue
  [ -n "${SEEN_PKG[$pn]}" ] && continue
  SEEN_PKG[$pn]=1
  if c=$(repo_candidate "$pb"); then
    bad "$(L "$c — a newer build IS in the repo but not installed → run --upgrade and check the package manager output" \
             "$c — repoda daha yeni build VAR ama kurulmamış → --upgrade çalıştır ve paket yöneticisi çıktısına bak")"
  else
    warn "$(L "$pn: no newer build in the configured repos — the vendor has not published it yet, or its repo is missing/disabled" \
              "$pn: tanımlı repolarda daha yeni build yok — vendor henüz yayınlamamış ya da reposu eksik/kapalı")"
  fi
done
[ $N_UP_PENDING -gt 0 ] && warn "$(L "$N_UP_PENDING installation(s) await the CVE-2026-115560 fix (next regular PHP release) — session.upload_progress stays disabled until then; once released, set FIXED_VERSIONS_UP (or use a newer script) and re-run --upgrade" \
                                     "$N_UP_PENDING kurulum CVE-2026-115560 yamasını bekliyor (bir sonraki rutin PHP sürümü) — o zamana kadar session.upload_progress kapalı kalır; yama çıkınca FIXED_VERSIONS_UP ayarla (ya da script'in yeni sürümünü kullan) ve --upgrade'i tekrar çalıştır")"
[ $N_VENDOR -gt 0 ]    && warn "$(L "$N_VENDOR distro PHP build(s) with no CVE entry in the package changelog — the distro may not have shipped the fix yet" \
                                    "$N_VENDOR dağıtım PHP'sinin paket changelog'unda CVE kaydı yok — dağıtım yamayı henüz yayınlamamış olabilir")"
for n in "${PLESK_NOTES[@]}"; do
  warn "Plesk PHP $n — $(L "Plesk ships EOL fixes without a version bump; compare the build date with Plesk's CVE-2026-109618 advisory (mitigation stays applied either way)" \
                           "Plesk EOL yamalarını sürüm numarası değiştirmeden yayınlıyor; build tarihini Plesk'in CVE-2026-109618 duyurusuyla karşılaştır (önlem her durumda yerinde kalır)")"
done
[[ " ${T_KIND[*]} " == *" CloudLinux alt-php "* ]] \
  && warn "$(L "CloudLinux alt-php: PHP Selector/CageFS users may load a separate ini dir → verify with ini_get on a customer site over the web" \
               "CloudLinux alt-php: PHP Selector/CageFS kullanıcıları ayrı ini dizini kullanabilir → bir müşteri sitesinde web'den ini_get ile doğrula")"
[ -n "$APPLY_FAILED" ]   && bad "$(L "Mitigation could not be written to some targets (see above)" "Bazı hedeflere önlem yazılamadı (yukarıya bak)")"
[ -n "$UPGRADE_FAILED" ] && bad "$(L "Package upgrade failed (log: $LOG)" "Paket güncellemesi başarısız (log: $LOG)")"
info "$(L "Note: CLI verification does not fully guarantee web SAPI behaviour; check critical sites via phpinfo/ini_get over the web." \
          "Not: CLI doğrulaması web SAPI davranışını tam garanti etmez; kritik sitelerde web'den phpinfo/ini_get ile kontrol et.")"
info "$(L "Note: session.upload_progress.enabled is PHP_INI_PERDIR — users can re-enable it via .user.ini/.htaccess; --scan lists such overrides (FPM php_admin_flag cannot be overridden)." \
          "Not: session.upload_progress.enabled PHP_INI_PERDIR'dir — kullanıcılar .user.ini/.htaccess ile geri açabilir; --scan bu ayarları listeler (FPM php_admin_flag ezilemez).")"
info "$(L "Note: per php.net there is no complete mitigation — updating is the only safe choice." \
          "Not: php.net'e göre tam bir önlem yok — tek güvenli yol güncellemek.")"
[ -d "$BACKUP_DIR" ] && info "$(L Backups Yedekler): $BACKUP_DIR"

# ---------------------------------------------------------------------
#  IOC sweep (optional, read-only)
# ---------------------------------------------------------------------
do_scan() {
  section "$(L "IOC sweep (last $SCAN_DAYS days, read-only)" "IOC taraması (son $SCAN_DAYS gün, salt-okunur)")"
  local roots=() r tmp hits
  for r in /home /var/www; do [ -d "$r" ] && roots+=("$r"); done
  tmp=$(mktemp)

  info "[1] $(L "PHP files changed in the last $SCAN_DAYS days" "Son $SCAN_DAYS günde değişen PHP dosyaları")"
  if [ ${#roots[@]} -gt 0 ]; then
    find "${roots[@]}" -xdev -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.php[0-9]' -o -name '*.phar' \) \
         -mtime -"$SCAN_DAYS" -not -path '*/cache/*' -not -path '*/node_modules/*' 2>/dev/null > "$tmp"
    info "    $(L "total: $(wc -l < "$tmp") files (can be normal after CMS/plugin updates)" "toplam: $(wc -l < "$tmp") dosya (CMS/eklenti güncellemesi sonrası normal olabilir)")"
    hits=$(tr '\n' '\0' < "$tmp" | xargs -0 -r grep -lIE \
      'eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)|assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)|\$_(POST|GET|REQUEST|COOKIE)\s*\[[^]]+\]\s*\(|preg_replace\s*\(.*/e["'\'']' 2>/dev/null | head -n 100)
    if [ -n "$hits" ]; then
      bad "    $(L "files with suspicious signatures (first 100):" "şüpheli imza içeren dosyalar (ilk 100):")"; printf '%s\n' "$hits" | sed 's/^/      /'
    else
      ok "    $(L "no known web shell signatures in recently changed files" "yeni değişen dosyalarda bilinen web shell imzası yok")"
    fi
  fi

  info "[2] $(L "Shells/tools spawned by web workers" "Web süreçlerinden açılan shell/araçlar")"
  declare -A PCOMM
  local pid comm ppid user args found=0
  while read -r pid comm; do PCOMM[$pid]=$comm; done < <(ps -eo pid=,comm=)
  while read -r pid ppid user comm args; do
    case "$comm" in sh|bash|dash|zsh|ksh|python*|perl|ruby|nc|ncat|socat|curl|wget|busybox) ;; *) continue ;; esac
    case "${PCOMM[$ppid]}" in
      php-fpm*|lsphp*|php-cgi*|httpd|apache2)
        warn "    pid=$pid user=$user parent=${PCOMM[$ppid]}($ppid): $args"; found=1 ;;
    esac
  done < <(ps -eo pid=,ppid=,user=,comm=,args=)
  [ $found -eq 0 ] && ok "    $(L "no shell/tool currently running under a web worker" "şu an web süreci altında çalışan shell/araç yok")"

  info "[3] $(L "Crontabs changed in the last $SCAN_DAYS days" "Son $SCAN_DAYS günde değişen crontab'lar")"
  find /var/spool/cron /etc/cron.d -type f -mtime -"$SCAN_DAYS" 2>/dev/null | sed 's/^/      /'

  info "[4] $(L "Overrides that may re-enable upload_progress (FPM pools / .user.ini / .htaccess / php.ini)" \
                "upload_progress'i geri açabilecek ayarlar (FPM pool / .user.ini / .htaccess / php.ini)")"
  {
    find /etc/php-fpm.d /etc/php/*/fpm/pool.d /opt/cpanel/ea-php*/root/etc/php-fpm.d \
         /opt/plesk/php/*/etc/php-fpm.d /opt/php*/etc/php-fpm.d /etc/opt/remi/php*/php-fpm.d \
         -maxdepth 1 -type f -name '*.conf' 2>/dev/null
    [ ${#roots[@]} -gt 0 ] && find "${roots[@]}" -xdev -maxdepth 7 -type f \
         \( -name '.user.ini' -o -name '.htaccess' -o -name 'php.ini' \) 2>/dev/null
  } | tr '\n' '\0' | xargs -0 -r grep -HniE 'session\.upload_progress\.enabled[^;#]*(1|on|true|yes)' 2>/dev/null \
    | sed 's/^/      /' | head -n 50

  info "[5] $(L "Code that switches session.serialize_handler at runtime (CVE-2026-115560 precondition #2)" \
                "session.serialize_handler'ı çalışma anında değiştiren kod (CVE-2026-115560 ön koşulu #2)")"
  [ ${#roots[@]} -gt 0 ] && grep -rlsIE --include='*.php' \
       "(ini_set|ini_alter)[[:space:]]*\([[:space:]]*['\"]session\.serialize_handler" "${roots[@]}" 2>/dev/null \
    | head -n 50 | sed 's/^/      /'
  rm -f "$tmp"
}
[ $DO_SCAN -eq 1 ] && do_scan

# ---------------------------------------------------------------------
#  Exit code
# ---------------------------------------------------------------------
if [ -n "$APPLY_FAILED" ] || [ $N_EOL -gt 0 ] || [ $N_EXPOSED -gt 0 ] || [ $N_STALE -gt 0 ]; then exit 2
elif [ $N_UNPATCHED -gt 0 ] || [ $N_UP_PENDING -gt 0 ]; then exit 1
else exit 0
fi
