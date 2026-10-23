#!/usr/bin/env bash
# =============================================================================
# check-php2shell.sh — Vérification PHP2Shell (CVE-2026-109618 / CVE-2026-109619)
#
# LECTURE SEULE : ne modifie rien, ne redémarre rien, ne supprime rien.
# Cible : Debian / Ubuntu (arborescence /etc/php/<version>/<sapi>),
#         PHP de la distribution ou du dépôt sury.
#
# Usage : sudo ./check-php2shell.sh [racine_web ...]     (défaut : /var/www)
#         ssh root@serveur 'bash -s' < check-php2shell.sh
#         ssh root@serveur 'bash -s -- /var/www /srv/sites' < check-php2shell.sh
#
# Code retour (compatible Centreon/Nagios) :
#   0 = OK, 1 = WARNING, 2 = CRITICAL, 3 = UNKNOWN
#
# Vérifie, pour chaque version de PHP installée :
#   1. présence du correctif (version amont ou rétroportage dans le changelog)
#   2. valeur EFFECTIVE de session.upload_progress.enabled pour chaque SAPI
#      (fpm, apache2/mod_php, cgi), surcharges pool.d comprises
#   3. processus redémarrés après la mise à jour et la modif de config
# Puis, globalement :
#   4. surcharges dans /etc/apache2, .htaccess et .user.ini
#   5. fichiers de session contenant du code PHP ou des données upload_progress
#   6. signatures d'exploitation dans les logs
#   7. fichiers suspects dans les racines web, /tmp, crontab www-data
# =============================================================================
set -u
export LC_ALL=C

SINCE="2026-10-20"                      # début de la fenêtre d'exposition
CVE1="CVE-2026-109618"
CVE2="CVE-2026-109619"
declare -A FIXED=([8.2]="8.2.35" [8.3]="8.3.36" [8.4]="8.4.27" [8.5]="8.5.12")
WEBUSER="www-data"

if [ $# -gt 0 ]; then WEBROOTS=("$@"); else WEBROOTS=(/var/www); fi

NB_KO=0; NB_WARN=0
if [ -t 1 ]; then R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[1m'; N=$'\e[0m'
else R=""; G=""; Y=""; B=""; N=""; fi
ok()    { printf '  %s[OK]%s   %s\n' "$G" "$N" "$*"; }
warn()  { printf '  %s[WARN]%s %s\n' "$Y" "$N" "$*"; NB_WARN=$((NB_WARN+1)); }
ko()    { printf '  %s[KO]%s   %s\n' "$R" "$N" "$*"; NB_KO=$((NB_KO+1)); }
info()  { printf '         %s\n' "$@"; }
titre() { printf '\n%s== %s ==%s\n' "$B" "$*" "$N"; }

[ "$(id -u)" -eq 0 ] || { echo "UNKNOWN : à lancer en root (lecture de /proc, sessions, logs)." >&2; exit 3; }

NOW=$(date +%s)

# Epoch de démarrage du plus ancien des PID donnés
oldest_start() {
  local pid e min=$NOW
  for pid in "$@"; do
    e=$(ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ')
    [ -n "$e" ] && [ $((NOW - e)) -lt "$min" ] && min=$((NOW - e))
  done
  echo "$min"
}
# Plus récente date de modification parmi des fichiers
newest_mtime() {
  local f t max=0
  for f in "$@"; do
    [ -e "$f" ] || continue
    t=$(stat -c %Y "$f"); [ "$t" -gt "$max" ] && max=$t
  done
  echo "$max"
}
fmt() { date -d "@$1" '+%Y-%m-%d %H:%M:%S'; }
ENABLE_RE='[=[:space:]](1|on|true|yes)[[:space:]]*$'

# shellcheck 
. /etc/os-release 2>/dev/null
titre "$(hostname -f 2>/dev/null || hostname) — ${PRETTY_NAME:-OS inconnu} — $(date '+%Y-%m-%d %H:%M')"

mapfile -t VERSIONS < <(find /etc/php -mindepth 1 -maxdepth 1 -type d -name '[0-9]*' -printf '%f\n' 2>/dev/null | sort -V)
if [ ${#VERSIONS[@]} -eq 0 ]; then
  if command -v php >/dev/null 2>&1; then
    ko "PHP présent ($(php -r 'echo PHP_VERSION;' 2>/dev/null)) hors arborescence /etc/php/<version> : vérification manuelle nécessaire"
    exit 2
  fi
  echo "  Aucun PHP détecté sur ce serveur."
  exit 0
fi

declare -A SAVE_PATHS=()

# -----------------------------------------------------------------------------
for v in "${VERSIONS[@]}"; do
  titre "PHP $v"
  bin=$(command -v "php$v" 2>/dev/null || true)
  pkgv=$(dpkg-query -W -f='${Version}' "php$v-common" 2>/dev/null || true)
  if [ -z "$pkgv" ] && [ -z "$bin" ]; then
    info "Résidu de configuration (paquets désinstallés) — ignoré"
    continue
  fi
  upv=""
  [ -n "$bin" ] && upv=$("$bin" -n -r 'echo PHP_VERSION;' 2>/dev/null)
  info "Paquet php$v-common : ${pkgv:-?}   —   PHP_VERSION : ${upv:-?}"

  # --- 1. Correctif -----------------------------------------------------------
  chlog="/usr/share/doc/php$v-common/changelog.Debian.gz"
  c1=0; c2=0
  if [ -r "$chlog" ]; then
    c1=$(zgrep -c "$CVE1" "$chlog" 2>/dev/null); c2=$(zgrep -c "$CVE2" "$chlog" 2>/dev/null)
  fi
  fixed=${FIXED[$v]:-}
  if [ -n "$fixed" ] && [ -n "$upv" ] && dpkg --compare-versions "$upv" ge "$fixed"; then
    ok "Correctif présent ($upv >= $fixed)"
  elif [ "${c1:-0}" -gt 0 ] && [ "${c2:-0}" -gt 0 ]; then
    ok "Correctif rétroporté par la distribution (les deux CVE figurent dans le changelog)"
  elif [ "${c1:-0}" -gt 0 ] || [ "${c2:-0}" -gt 0 ]; then
    warn "Une seule des deux CVE figure dans le changelog — vérifier l'avis de sécurité de la distribution"
  elif [ -z "$fixed" ]; then
    ko "Branche $v sans correctif officiel : migrer vers 8.2+ ou retirer le service d'Internet"
  else
    ko "Version vulnérable : mettre à jour vers $fixed ou plus"
  fi

  # --- 2 & 3. SAPI : config effective + redémarrage ---------------------------
  for sapi in fpm apache2 cgi; do
    dir="/etc/php/$v/$sapi"
    [ -d "$dir" ] || continue

    used=""
    case $sapi in
      fpm)     systemctl is-active --quiet "php$v-fpm" 2>/dev/null && used=1 ;;
      apache2) [ -e "/etc/apache2/mods-enabled/php$v.load" ] \
                 && systemctl is-active --quiet apache2 2>/dev/null && used=1 ;;
      cgi)     [ -x "/usr/bin/php-cgi$v" ] && used=1 ;;
    esac
    st="inactif"; [ -n "$used" ] && st="actif"

    upe="?"; sp=""
    if [ -n "$bin" ]; then
      eff=$(PHP_INI_SCAN_DIR="$dir/conf.d" "$bin" -c "$dir" -r \
            'echo ini_get("session.upload_progress.enabled"), "|", ini_get("session.save_path");' 2>/dev/null)
      upe=${eff%%|*}; sp=${eff#*|}
    fi

    # Surcharges dans les pools FPM (php_value / php_admin_value / php_flag ...)
    if [ "$sapi" = fpm ] && [ -d "$dir/pool.d" ]; then
      over=$(grep -rhEi '^[[:space:]]*php_(admin_)?(value|flag)\[session\.upload_progress\.enabled\]' "$dir/pool.d" 2>/dev/null)
      if [ -n "$over" ]; then
        info "Surcharge pool.d : $over"
        if grep -qEi "$ENABLE_RE" <<<"$over"; then upe=1; else upe=0; fi
      fi
    fi

    case "${upe,,}" in
      "?")  warn "$sapi ($st) : impossible d'évaluer (binaire php$v absent)" ;;
      1|on) if [ -n "$used" ]; then ko "$sapi ($st) : session.upload_progress ACTIVÉ"
            else warn "$sapi ($st) : session.upload_progress activé (SAPI non utilisé)"; fi ;;
      *)    ok "$sapi ($st) : session.upload_progress désactivé" ;;
    esac

    [ -n "$used" ] || continue
    SAVE_PATHS["${sp##*;}"]=1

    # Processus : ancien binaire encore chargé ? redémarrés après la config ?
    [ "$sapi" = cgi ] && continue
    unit="php$v-fpm"; [ "$sapi" = apache2 ] && unit="apache2"
    main=$(systemctl show -p MainPID --value "$unit" 2>/dev/null)
    [ -n "$main" ] && [ "$main" != 0 ] || { warn "$unit : PID principal introuvable"; continue; }
    mapfile -t procs < <(pgrep -P "$main")
    [ ${#procs[@]} -gt 0 ] || procs=("$main")

    stale=""
    for p in "$main" "${procs[@]}"; do
      if [ "$sapi" = fpm ]; then
        readlink "/proc/$p/exe" 2>/dev/null | grep -q '(deleted)' && stale=1
      else
        grep -qs 'libphp.*(deleted)' "/proc/$p/maps" && stale=1
      fi
    done
    [ -n "$stale" ] && ko "$unit exécute encore l'ancien code PHP (fichier remplacé par la MAJ) : redémarrer"

    ref=$(newest_mtime "$dir/php.ini" "$dir"/conf.d/*.ini "$dir"/pool.d/*.conf)
    start=$(oldest_start "${procs[@]}")
    if [ "$start" -lt "$ref" ]; then
      ko "$unit : processus démarrés le $(fmt "$start"), avant la dernière modif de config ($(fmt "$ref")) : redémarrer"
    elif [ -z "$stale" ]; then
      ok "$unit : processus à jour (démarrés le $(fmt "$start"))"
    fi
  done
done

# -----------------------------------------------------------------------------
titre "Surcharges hors /etc/php (Apache, .htaccess, .user.ini)"
hits=$(grep -rnEi 'session\.upload_progress\.enabled' /etc/apache2 2>/dev/null)
for w in "${WEBROOTS[@]}"; do
  [ -d "$w" ] || continue
  h=$(grep -rnEi 'session\.upload_progress\.enabled' "$w" --include=.htaccess --include=.user.ini 2>/dev/null)
  [ -n "$h" ] && hits+=$'\n'"$h"
done
hits=$(sed '/^$/d' <<<"$hits")
if [ -z "$hits" ]; then
  ok "Aucune surcharge"
elif grep -qEi "$ENABLE_RE" <<<"$hits"; then
  ko "Surcharge qui RÉACTIVE upload_progress :"; info "$hits"
else
  ok "Surcharges présentes, toutes désactivantes :"; info "$hits"
fi

# -----------------------------------------------------------------------------
titre "Fichiers de session"
[ ${#SAVE_PATHS[@]} -eq 0 ] && SAVE_PATHS[/var/lib/php/sessions]=1
for sp in "${!SAVE_PATHS[@]}"; do
  [ -z "$sp" ] && sp=/var/lib/php/sessions
  if [ ! -d "$sp" ]; then info "$sp absent (sessions ailleurs : Redis, memcached… ?)"; continue; fi
  n=$(find "$sp" -maxdepth 1 -type f -name 'sess_*' 2>/dev/null | wc -l)
  bad=$(find "$sp" -maxdepth 1 -type f -name 'sess_*' -exec grep -lE '<\?(php|=)' {} + 2>/dev/null)
  upn=$(find "$sp" -maxdepth 1 -type f -name 'sess_*' -exec grep -l 'upload_progress_' {} + 2>/dev/null | wc -l)
  if [ -n "$bad" ]; then
    ko "$sp : session(s) contenant du code PHP — compromission probable. CONSERVER pour analyse avant purge :"
    info "$(head -20 <<<"$bad")"
  else
    ok "$sp : $n fichier(s) de session, aucun ne contient de code PHP"
  fi
  [ "$upn" -gt 0 ] && warn "$sp : $upn session(s) avec données upload_progress — purge conseillée"
done

# -----------------------------------------------------------------------------
titre "Signatures d'exploitation dans les logs"
mapfile -t LOGS < <(ls /var/log/apache2/error.log* /var/log/php*-fpm.log* /var/log/nginx/error.log* 2>/dev/null)
if [ ${#LOGS[@]} -eq 0 ]; then
  info "Aucun log Apache / nginx / FPM aux emplacements standard"
else
  u=$(zgrep -h "in Unknown on line 0" "${LOGS[@]}" 2>/dev/null | wc -l)
  a=$(zgrep -h "AH00052" "${LOGS[@]}" 2>/dev/null | wc -l)
  if [ "$u" -gt 0 ]; then
    warn "$u erreur(s) « in Unknown on line 0 » (signature de l'exploit) — à dater et corréler. Dernières :"
    info "$(zgrep -h "in Unknown on line 0" "${LOGS[@]}" 2>/dev/null | tail -3 | cut -c1-200)"
  else
    ok "Aucune erreur « in Unknown on line 0 »"
  fi
  if [ "$a" -gt 0 ]; then
    warn "$a entrée(s) AH00052 (worker Apache tué) — chercher une rafale de gros POST depuis une même IP"
  else
    ok "Aucune entrée AH00052"
  fi
fi

# -----------------------------------------------------------------------------
titre "Fichiers suspects depuis le $SINCE"
for w in "${WEBROOTS[@]}"; do
  [ -d "$w" ] || { info "$w absent"; continue; }
  up=$(find "$w" -path '*/uploads/*' -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.php[0-9]' \) 2>/dev/null)
  if [ -n "$up" ]; then
    warn "$w : fichier(s) PHP dans un dossier uploads :"; info "$(head -15 <<<"$up")"
  else
    ok "$w : aucun fichier PHP dans les dossiers uploads"
  fi
  rec=$(find "$w" -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' \) -newermt "$SINCE" 2>/dev/null)
  nrec=$(sed '/^$/d' <<<"$rec" | wc -l)
  if [ "$nrec" -gt 0 ]; then
    warn "$w : $nrec fichier(s) PHP modifié(s) depuis le $SINCE (MAJ légitimes possibles) — extrait :"
    info "$(head -15 <<<"$rec")"
  else
    ok "$w : aucun fichier PHP modifié depuis le $SINCE"
  fi
done

tmpf=$(find /tmp /var/tmp /dev/shm -user "$WEBUSER" -type f -newermt "$SINCE" 2>/dev/null)
if [ -n "$tmpf" ]; then
  warn "Fichiers créés par $WEBUSER dans /tmp, /var/tmp, /dev/shm :"; info "$(head -15 <<<"$tmpf")"
else
  ok "Aucun fichier récent de $WEBUSER dans /tmp, /var/tmp, /dev/shm"
fi

cron=$(crontab -l -u "$WEBUSER" 2>/dev/null | grep -vE '^[[:space:]]*(#|$)')
if [ -n "$cron" ]; then
  warn "Crontab de $WEBUSER non vide :"; info "$cron"
else
  ok "Crontab de $WEBUSER vide"
fi

# -----------------------------------------------------------------------------
titre "Bilan"
if [ "$NB_KO" -gt 0 ]; then
  echo "  ${R}CRITICAL${N} : $NB_KO point(s) bloquant(s), $NB_WARN avertissement(s)"; exit 2
elif [ "$NB_WARN" -gt 0 ]; then
  echo "  ${Y}WARNING${N} : $NB_WARN avertissement(s) à examiner"; exit 1
else
  echo "  ${G}OK${N} : rien de bloquant détecté"; exit 0
fi