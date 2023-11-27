#!/usr/bin/env bash
#
# install_server.sh - hysteria (SlowUDP) server install script
# Try `install_server.sh --help` for usage.
#
# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Aperture Internet Laboratory
# 
# Modify by Evozi - https://github.com/evozi/hysteria-install
#

set -e


###
# SCRIPT CONFIGURATION
###

# Basename of this script
SCRIPT_NAME="$(basename "$0")"

# Command line arguments of this script
SCRIPT_ARGS=("$@")

# Path for installing executable
EXECUTABLE_INSTALL_PATH="/usr/local/bin/slowudp"

# Paths to install systemd files
SYSTEMD_SERVICES_DIR="/etc/systemd/system"

# Directory to store slowudp config file
CONFIG_DIR="/etc/slowudp"

# URLs of GitHub
REPO_URL="https://github.com/evozi/hysteria-install"
API_BASE_URL="https://api.github.com/repos/evozi/hysteria-install"

# curl command line flags.
# To using a proxy, please specify ALL_PROXY in the environ variable, such like:
# export ALL_PROXY=socks5h://192.0.2.1:1080
CURL_FLAGS=(-L -f -q --retry 5 --retry-delay 10 --retry-max-time 60)

# Latest version of SlowUDP
# LATEST_VERSION_SLOWUDP="v1.0.0"


###
# AUTO DETECTED GLOBAL VARIABLE
###

# Package manager
PACKAGE_MANAGEMENT_INSTALL="${PACKAGE_MANAGEMENT_INSTALL:-}"

# Operating System of current machine, supported: linux
OPERATING_SYSTEM="${OPERATING_SYSTEM:-}"

# Architecture of current machine, supported: 386, amd64, arm, arm64, mipsle, s390x
ARCHITECTURE="${ARCHITECTURE:-}"

# User for running slowudp
SLOWUDP_USER="${SLOWUDP_USER:-}"

# Directory for ACME certificates storage
SLOWUDP_HOME_DIR="${SLOWUDP_HOME_DIR:-}"


###
# ARGUMENTS
###

# Supported operation: install, remove, check_update
OPERATION=

# User specified version to install
VERSION=

# Force install even if installed
FORCE=

# User specified binary to install
LOCAL_FILE=


###
# COMMAND REPLACEMENT & UTILITIES
###

has_command() {
  local _command=$1

  type -P "$_command" > /dev/null 2>&1
}

curl() {
  command curl "${CURL_FLAGS[@]}" "$@"
}

mktemp() {
  command mktemp "$@" "/tmp/slowudpservinst.XXXXXXXXXX"
}

tput() {
  if has_command tput; then
    command tput "$@"
  fi
}

tred() {
  tput setaf 1
}

tgreen() {
  tput setaf 2
}

tyellow() {
  tput setaf 3
}

tblue() {
  tput setaf 4
}

taoi() {
  tput setaf 6
}

tbold() {
  tput bold
}

treset() {
  tput sgr0
}

note() {
  local _msg="$1"

  echo -e "$SCRIPT_NAME: $(tbold)note: $_msg$(treset)"
}

warning() {
  local _msg="$1"

  echo -e "$SCRIPT_NAME: $(tyellow)warning: $_msg$(treset)"
}

error() {
  local _msg="$1"

  echo -e "$SCRIPT_NAME: $(tred)error: $_msg$(treset)"
}

has_prefix() {
    local _s="$1"
    local _prefix="$2"

    if [[ -z "$_prefix" ]]; then
        return 0
    fi

    if [[ -z "$_s" ]]; then
        return 1
    fi

    [[ "x$_s" != "x${_s#"$_prefix"}" ]]
}

systemctl() {
  if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]] || ! has_command systemctl; then
    warning "Ignored systemd command: systemctl $@"
    return
  fi

  command systemctl "$@"
}

show_argument_error_and_exit() {
  local _error_msg="$1"

  error "$_error_msg"
  echo "Try \"$0 --help\" for usage." >&2
  exit 22
}

install_content() {
  local _install_flags="$1"
  local _content="$2"
  local _destination="$3"
  local _overwrite="$4"

  local _tmpfile="$(mktemp)"

  echo -ne "Install $_destination ... "
  echo "$_content" > "$_tmpfile"
  if [[ -z "$_overwrite" && -e "$_destination" ]]; then
    echo -e "exists"
  elif install "$_install_flags" "$_tmpfile" "$_destination"; then
    echo -e "ok"
  fi

  rm -f "$_tmpfile"
}

remove_file() {
  local _target="$1"

  echo -ne "Remove $_target ... "
  if rm "$_target"; then
    echo -e "ok"
  fi
}

exec_sudo() {
  # exec sudo with configurable environ preserved.
  local _saved_ifs="$IFS"
  IFS=$'\n'
  local _preserved_env=(
    $(env | grep "^PACKAGE_MANAGEMENT_INSTALL=" || true)
    $(env | grep "^OPERATING_SYSTEM=" || true)
    $(env | grep "^ARCHITECTURE=" || true)
    $(env | grep "^SLOWUDP_\w*=" || true)
    $(env | grep "^FORCE_\w*=" || true)
  )
  IFS="$_saved_ifs"

  exec sudo env \
    "${_preserved_env[@]}" \
    "$@"
}

detect_package_manager() {
  if [[ -n "$PACKAGE_MANAGEMENT_INSTALL" ]]; then
    return 0
  fi

  if has_command apt; then
    PACKAGE_MANAGEMENT_INSTALL='apt -y --no-install-recommends install'
    return 0
  fi

  if has_command dnf; then
    PACKAGE_MANAGEMENT_INSTALL='dnf -y install'
    return 0
  fi

  if has_command yum; then
    PACKAGE_MANAGEMENT_INSTALL='yum -y install'
    return 0
  fi

  if has_command zypper; then
    PACKAGE_MANAGEMENT_INSTALL='zypper install -y --no-recommends'
    return 0
  fi

  if has_command pacman; then
    PACKAGE_MANAGEMENT_INSTALL='pacman -Syu --noconfirm'
    return 0
  fi

  return 1
}

install_software() {
  local _package_name="$1"

  if ! detect_package_manager; then
    error "Supported package manager is not detected, please install the following package manually:"
    echo
    echo -e "\t* $_package_name"
    echo
    exit 65
  fi

  echo "Installing missing dependence '$_package_name' with '$PACKAGE_MANAGEMENT_INSTALL' ... "
  if $PACKAGE_MANAGEMENT_INSTALL "$_package_name"; then
    echo "ok"
  else
    error "Cannot install '$_package_name' with detected package manager, please install it manually."
    exit 65
  fi
}

is_user_exists() {
  local _user="$1"

  id "$_user" > /dev/null 2>&1
}

rerun_with_sudo() {
  if ! has_command sudo; then
    return 13
  fi

  local _target_script

  if has_prefix "$0" "/dev/fd/"; then
    local _tmp_script="$(mktemp)"
    chmod +x "$_tmp_script"

    if has_command curl; then
      curl -o "$_tmp_script" 'https://raw.githubusercontent.com/evozi/hysteria-install/main/slowudp/install_server.sh'
    elif has_command wget; then
      wget -O "$_tmp_script" 'https://raw.githubusercontent.com/evozi/hysteria-install/main/slowudp/install_server.sh'
    else
      return 127
    fi

    _target_script="$_tmp_script"
  else
    _target_script="$0"
  fi

  note "Re-running this script with sudo. You can also specify FORCE_NO_ROOT=1 to force this script to run as the current user."
  exec_sudo "$_target_script" "${SCRIPT_ARGS[@]}"
}

check_permission() {
  if [[ "$UID" -eq '0' ]]; then
    return
  fi

  note "The user running this script is not root."

  case "$FORCE_NO_ROOT" in
    '1')
      warning "FORCE_NO_ROOT=1 detected, we will proceed without root, but you may get insufficient privileges errors."
      ;;
    *)
      if ! rerun_with_sudo; then
        error "Please run this script with root or specify FORCE_NO_ROOT=1 to force this script to run as the current user."
        exit 13
      fi
      ;;
  esac
}

check_environment_operating_system() {
  if [[ -n "$OPERATING_SYSTEM" ]]; then
    warning "OPERATING_SYSTEM=$OPERATING_SYSTEM detected, operating system detection will not be performed."
    return
  fi

  if [[ "x$(uname)" == "xLinux" ]]; then
    OPERATING_SYSTEM=linux
    return
  fi

  error "This script only supports Linux."
  note "Specify OPERATING_SYSTEM=[linux|darwin|freebsd|windows] to bypass this check and force this script to run on this $(uname)."
  exit 95
}

check_environment_architecture() {
  if [[ -n "$ARCHITECTURE" ]]; then
    warning "ARCHITECTURE=$ARCHITECTURE detected, architecture detection will not be performed."
    return
  fi

  case "$(uname -m)" in
    'i386' | 'i686')
      ARCHITECTURE='386'
      ;;
    'amd64' | 'x86_64')
      ARCHITECTURE='amd64'
      ;;
    #'armv5tel' | 'armv6l' | 'armv7' | 'armv7l')
    #  ARCHITECTURE='arm'
    #  ;;
    #'armv8' | 'aarch64')
    #  ARCHITECTURE='arm64'
    #  ;;
    #'mips' | 'mipsle' | 'mips64' | 'mips64le')
    #  ARCHITECTURE='mipsle'
    #  ;;
    #'s390x')
    #  ARCHITECTURE='s390x'
    #  ;;
    *)
      error "The architecture '$(uname -a)' is not supported."
      note "Specify ARCHITECTURE=<architecture> to bypass this check and force this script to run on this $(uname -m)."
      exit 8
      ;;
  esac
}

check_environment_systemd() {
  if [[ -d "/run/systemd/system" ]] || grep -q systemd <(ls -l /sbin/init); then
    return
  fi

  case "$FORCE_NO_SYSTEMD" in
    '1')
      warning "FORCE_NO_SYSTEMD=1, we will proceed as normal even if systemd is not detected."
      ;;
    '2')
      warning "FORCE_NO_SYSTEMD=2, we will proceed but skip all systemd related commands."
      ;;
    *)
      error "This script only supports Linux distributions with systemd."
      note "Specify FORCE_NO_SYSTEMD=1 to disable this check and force this script to run as if systemd exists."
      note "Specify FORCE_NO_SYSTEMD=2 to disable this check and skip all systemd related commands."
      ;;
  esac
}

check_environment_curl() {
  if has_command curl; then
    return
  fi

  install_software curl
}

check_environment_grep() {
  if has_command grep; then
    return
  fi

  install_software grep
}

check_environment() {
  check_environment_operating_system
  check_environment_architecture
  check_environment_systemd
  check_environment_curl
  check_environment_grep
}

vercmp_segment() {
  local _lhs="$1"
  local _rhs="$2"

  if [[ "x$_lhs" == "x$_rhs" ]]; then
    echo 0
    return
  fi
  if [[ -z "$_lhs" ]]; then
    echo -1
    return
  fi
  if [[ -z "$_rhs" ]]; then
    echo 1
    return
  fi

  local _lhs_num="${_lhs//[A-Za-z]*/}"
  local _rhs_num="${_rhs//[A-Za-z]*/}"

  if [[ "x$_lhs_num" == "x$_rhs_num" ]]; then
    echo 0
    return
  fi
  if [[ -z "$_lhs_num" ]]; then
    echo -1
    return
  fi
  if [[ -z "$_rhs_num" ]]; then
    echo 1
    return
  fi
  local _numcmp=$(($_lhs_num - $_rhs_num))
  if [[ "$_numcmp" -ne 0 ]]; then
    echo "$_numcmp"
    return
  fi

  local _lhs_suffix="${_lhs#"$_lhs_num"}"
  local _rhs_suffix="${_rhs#"$_rhs_num"}"

  if [[ "x$_lhs_suffix" == "x$_rhs_suffix" ]]; then
    echo 0
    return
  fi
  if [[ -z "$_lhs_suffix" ]]; then
    echo 1
    return
  fi
  if [[ -z "$_rhs_suffix" ]]; then
    echo -1
    return
  fi
  if [[ "$_lhs_suffix" < "$_rhs_suffix" ]]; then
    echo -1
    return
  fi
  echo 1
}

vercmp() {
  local _lhs=${1#v}
  local _rhs=${2#v}

  while [[ -n "$_lhs" && -n "$_rhs" ]]; do
    local _clhs="${_lhs/.*/}"
    local _crhs="${_rhs/.*/}"

    local _segcmp="$(vercmp_segment "$_clhs" "$_crhs")"
    if [[ "$_segcmp" -ne 0 ]]; then
      echo "$_segcmp"
      return
    fi

    _lhs="${_lhs#"$_clhs"}"
    _lhs="${_lhs#.}"
    _rhs="${_rhs#"$_crhs"}"
    _rhs="${_rhs#.}"
  done

  if [[ "x$_lhs" == "x$_rhs" ]]; then
    echo 0
    return
  fi

  if [[ -z "$_lhs" ]]; then
    echo -1
    return
  fi

  if [[ -z "$_rhs" ]]; then
    echo 1
    return
  fi

  return
}

check_slowudp_user() {
  local _default_slowudp_user="$1"

  if [[ -n "$SLOWUDP_USER" ]]; then
    return
  fi

  if [[ ! -e "$SYSTEMD_SERVICES_DIR/slowudp-server.service" ]]; then
    SLOWUDP_USER="$_default_slowudp_user"
    return
  fi

  SLOWUDP_USER="$(grep -o '^User=\w*' "$SYSTEMD_SERVICES_DIR/slowudp-server.service" | tail -1 | cut -d '=' -f 2 || true)"

  if [[ -z "$SLOWUDP_USER" ]]; then
    SLOWUDP_USER="$_default_slowudp_user"
  fi
}

check_slowudp_homedir() {
  local _default_slowudp_homedir="$1"

  if [[ -n "$SLOWUDP_HOME_DIR" ]]; then
    return
  fi

  if ! is_user_exists "$SLOWUDP_USER"; then
    SLOWUDP_HOME_DIR="$_default_slowudp_homedir"
    return
  fi

  SLOWUDP_HOME_DIR="$(eval echo ~"$SLOWUDP_USER")"
}


###
# ARGUMENTS PARSER
###

show_usage_and_exit() {
  echo
  echo -e "\t$(tbold)$SCRIPT_NAME$(treset) - slowudp server install script"
  echo
  echo -e "Usage:"
  echo
  echo -e "$(tbold)Install slowudp$(treset)"
  echo -e "\t$0 [ -f | -l <file> | --version <version> ]"
  echo -e "Flags:"
  echo -e "\t-f, --force\tForce re-install latest or specified version even if it has been installed."
  echo -e "\t-l, --local <file>\tInstall specified slowudp binary instead of download it."
  echo -e "\t--version <version>\tInstall specified version instead of the latest."
  echo
  echo -e "$(tbold)Remove slowudp$(treset)"
  echo -e "\t$0 --remove"
  echo
  echo -e "$(tbold)Check for the update$(treset)"
  echo -e "\t$0 -c"
  echo -e "\t$0 --check"
  echo
  echo -e "$(tbold)Show this help$(treset)"
  echo -e "\t$0 -h"
  echo -e "\t$0 --help"
  exit 0
}

parse_arguments() {
  while [[ "$#" -gt '0' ]]; do
    case "$1" in
      '--remove')
        if [[ -n "$OPERATION" && "$OPERATION" != 'remove' ]]; then
          show_argument_error_and_exit "Option '--remove' is in conflict with other options."
        fi
        OPERATION='remove'
        ;;
      '--version')
        VERSION="$2"
        if [[ -z "$VERSION" ]]; then
          show_argument_error_and_exit "Please specify the version for option '--version'."
        fi
        shift
        if ! has_prefix "$VERSION" 'v'; then
          show_argument_error_and_exit "Version numbers should begin with 'v' (such as 'v1.3.5'), got '$VERSION'"
        fi
        ;;
      '-c' | '--check')
        if [[ -n "$OPERATION" && "$OPERATION" != 'check' ]]; then
          show_argument_error_and_exit "Option '-c' or '--check' is in conflict with other options."
        fi
        OPERATION='check_update'
        ;;
      '-f' | '--force')
        FORCE='1'
        ;;
      '-h' | '--help')
        show_usage_and_exit
        ;;
      '-l' | '--local')
        LOCAL_FILE="$2"
        if [[ -z "$LOCAL_FILE" ]]; then
          show_argument_error_and_exit "Please specify the local binary to install for option '-l' or '--local'."
        fi
        break
        ;;
      *)
        show_argument_error_and_exit "Unknown option '$1'"
        ;;
    esac
    shift
  done
  
  if [[ -z "$OPERATION" ]]; then
    OPERATION='install'
  fi

  # validate arguments
  case "$OPERATION" in
    'install')
      if [[ -n "$VERSION" && -n "$LOCAL_FILE" ]]; then
        show_argument_error_and_exit '--version and --local cannot be used together.'
      fi
      ;;
    *)
      if [[ -n "$VERSION" ]]; then
        show_argument_error_and_exit "--version is only valid for install operation."
      fi
      if [[ -n "$LOCAL_FILE" ]]; then
        show_argument_error_and_exit "--local is only valid for install operation."
      fi
      ;;
  esac
}


###
# FILE TEMPLATES
###

# /etc/systemd/system/slowudp-server.service
tpl_slowudp_server_service_base() {
  local _config_name="$1"

  cat << EOF
[Unit]
Description=Hysteria (SlowUDP) Server Service (${_config_name}.json)
After=network.target

[Service]
Type=simple
ExecStart=$EXECUTABLE_INSTALL_PATH --config ${_config_name}.json server
WorkingDirectory=$CONFIG_DIR
User=$SLOWUDP_USER
Group=$SLOWUDP_USER
Environment=SLOWUDP_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
}

# /etc/systemd/system/slowudp-server.service
tpl_slowudp_server_service() {
  tpl_slowudp_server_service_base 'config'
}

# /etc/systemd/system/slowudp-server@.service
tpl_slowudp_server_x_service() {
  tpl_slowudp_server_service_base '%i'
}

# /etc/slowudp/config.json
tpl_etc_slowudp_config_json() {
  cat << EOF
{
  "listen": ":36712",
  "acme": {
    "domains": [
      "your.domain.com"
    ],
    "email": "your@email.com"
  },
  "obfs": "8ZuA2Zpqhuk8yakXvMjDqEXBwY"
}
EOF
}


###
# SYSTEMD
###

get_running_services() {
  if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
    return
  fi

  systemctl list-units --state=active --plain --no-legend \
    | grep -o "slowudp-server@*[^\s]*.service" || true
}

restart_running_services() {
  if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
    return
  fi

  echo "Restarting running service ... "

  for service in $(get_running_services); do
    echo -ne "Restarting $service ... "
    systemctl restart "$service"
    echo "done"
  done
}

stop_running_services() {
  if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
    return
  fi

  echo "Stopping running service ... "

  for service in $(get_running_services); do
    echo -ne "Stopping $service ... "
    systemctl stop "$service"
    echo "done"
  done
}


###
# SLOWUDP & GITHUB API
###

is_slowudp_installed() {
  # RETURN VALUE
  # 0: slowudp is installed
  # 1: slowudp is not installed

  if [[ -f "$EXECUTABLE_INSTALL_PATH" || -h "$EXECUTABLE_INSTALL_PATH" ]]; then
    return 0
  fi
  return 1
}

is_slowudp_version() {
  local _version="$1"

  has_prefix "$_version" "v1." || has_prefix "$_version" "v0."
}

get_installed_version() {
  if is_slowudp_installed; then
    "$EXECUTABLE_INSTALL_PATH" -v | cut -d ' ' -f 3
  fi
}

get_latest_version() {
  if [[ -n "$VERSION" ]]; then
    echo "$VERSION"
    return
  fi

  local _tmpfile=$(mktemp)
  if ! curl -sS -H 'Accept: application/vnd.github.v3+json' "$API_BASE_URL/releases/latest" -o "$_tmpfile"; then
    error "Failed to get latest release, please check your network."
    exit 11
  fi

  local _latest_version=$(grep 'tag_name' "$_tmpfile" | head -1 | grep -o '"v.*"')
  _latest_version=${_latest_version#'"'}
  _latest_version=${_latest_version%'"'}

  if [[ -n "$_latest_version" ]]; then
    echo "$_latest_version"
  fi

  rm -f "$_tmpfile"
}

download_slowudp() {
  local _version="$1"
  local _destination="$2"

  local _download_url="$REPO_URL/releases/download/$_version/slowudp-$OPERATING_SYSTEM-$ARCHITECTURE"
  echo "Downloading slowudp binary: $_download_url ..."
  if ! curl -R -H 'Cache-Control: no-cache' "$_download_url" -o "$_destination"; then
    error "Download failed, please check your network and try again."
    return 11
  fi
  return 0
}

check_update() {
  # RETURN VALUE
  # 0: update available
  # 1: installed version is latest

  echo -ne "Checking for installed version ... "
  local _installed_version="$(get_installed_version)"
  if [[ -n "$_installed_version" ]]; then
    echo "$_installed_version"
  else
    echo "not installed"
  fi

  echo -ne "Checking for latest version ... "
  local _latest_version="$(get_latest_version)"
  if [[ -n "$_latest_version" ]]; then
    echo "$_latest_version"
    VERSION="$_latest_version"
  else
    echo "failed"
    return 1
  fi

  local _vercmp="$(vercmp "$_installed_version" "$_latest_version")"
  if [[ "$_vercmp" -lt 0 ]]; then
    return 0
  fi

  return 1
}


###
# ENTRY
###

perform_install_slowudp_binary() {
  if [[ -n "$LOCAL_FILE" ]]; then
    note "Performing local install: $LOCAL_FILE"

    echo -ne "Installing slowudp executable ... "
    
    if install -Dm755 "$LOCAL_FILE" "$EXECUTABLE_INSTALL_PATH"; then
      echo "ok"
    else
      exit 2
    fi

    return
  fi

  local _tmpfile=$(mktemp)

  if ! download_slowudp "$VERSION" "$_tmpfile"; then
    rm -f "$_tmpfile"
    exit 11
  fi

  echo -ne "Installing slowudp executable ... "

  if install -Dm755 "$_tmpfile" "$EXECUTABLE_INSTALL_PATH"; then
    echo "ok"
  else
    exit 13
  fi

  rm -f "$_tmpfile"
}

perform_remove_slowudp_binary() {
  remove_file "$EXECUTABLE_INSTALL_PATH"
}

perform_install_slowudp_example_config() {
  install_content -Dm644 "$(tpl_etc_slowudp_config_json)" "$CONFIG_DIR/config.json" ""
}

perform_install_slowudp_systemd() {
  if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
    return
  fi

  install_content -Dm644 "$(tpl_slowudp_server_service)" "$SYSTEMD_SERVICES_DIR/slowudp-server.service" "1"
  install_content -Dm644 "$(tpl_slowudp_server_x_service)" "$SYSTEMD_SERVICES_DIR/slowudp-server@.service" "1"

  systemctl daemon-reload
}

perform_remove_slowudp_systemd() {
  remove_file "$SYSTEMD_SERVICES_DIR/slowudp-server.service"
  remove_file "$SYSTEMD_SERVICES_DIR/slowudp-server@.service"

  systemctl daemon-reload
}

perform_install_slowudp_home_legacy() {
  if ! is_user_exists "$SLOWUDP_USER"; then
    echo -ne "Creating user $SLOWUDP_USER ... "
    useradd -r -d "$SLOWUDP_HOME_DIR" -m "$SLOWUDP_USER"
    echo "ok"
  fi
}

perform_install() {
  local _is_frash_install
  if ! is_slowudp_installed; then
    _is_frash_install=1
  fi

  local _is_update_required

  if [[ -n "$LOCAL_FILE" ]] || [[ -n "$VERSION" ]] || check_update; then
    _is_update_required=1
  fi

  if [[ "x$FORCE" == "x1" ]]; then
    if [[ -z "$_is_update_required" ]]; then
      note "Option '--force' detected, re-install even if installed version is the latest."
    fi
    _is_update_required=1
  fi

  if [[ -z "$_is_update_required" ]]; then
    echo "$(tgreen)Installed version is up-to-date, there is nothing to do.$(treset)"
    return
  fi

  if ! is_slowudp_version "$VERSION"; then
    error "This script can only install SlowUDP."
    exit 95
  fi

  perform_install_slowudp_binary
  perform_install_slowudp_example_config
  perform_install_slowudp_home_legacy
  perform_install_slowudp_systemd

  if [[ -n "$_is_frash_install" ]]; then
    echo
    echo -e "$(tbold)Congratulation! SlowUDP has been successfully installed on your server.$(treset)"
    echo
    echo -e "What's next?"
    echo
    echo -e "\t+ Edit server config file at $(tred)$CONFIG_DIR/config.json$(treset)"
    echo -e "\t+ Start your slowudp server with $(tred)systemctl start slowudp-server.service$(treset)"
    echo -e "\t+ Configure slowudp start on system boot with $(tred)systemctl enable slowudp-server.service$(treset)"
    echo
  else
    restart_running_services

    echo
    echo -e "$(tbold)SlowUDP has been successfully update to $VERSION.$(treset)"
    echo
  fi
}

perform_remove() {
  perform_remove_slowudp_binary
  stop_running_services
  perform_remove_slowudp_systemd

  echo
  echo -e "$(tbold)Congratulation! SlowUDP has been successfully removed from your server.$(treset)"
  echo
  echo -e "You still need to remove configuration files and ACME certificates manually with the following commands:"
  echo
  echo -e "\t$(tred)rm -rf "$CONFIG_DIR"$(treset)"
  if [[ "x$SLOWUDP_USER" != "xroot" ]]; then
    echo -e "\t$(tred)userdel -r "$SLOWUDP_USER"$(treset)"
  fi
  if [[ "x$FORCE_NO_SYSTEMD" != "x2" ]]; then
    echo
    echo -e "You still might need to disable all related systemd services with the following commands:"
    echo
    echo -e "\t$(tred)rm -f /etc/systemd/system/multi-user.target.wants/slowudp-server.service$(treset)"
    echo -e "\t$(tred)rm -f /etc/systemd/system/multi-user.target.wants/slowudp-server@*.service$(treset)"
    echo -e "\t$(tred)systemctl daemon-reload$(treset)"
  fi
  echo
}

perform_check_update() {
  if check_update; then
    echo
    echo -e "$(tbold)Update available: $VERSION$(treset)"
    echo
    echo -e "$(tgreen)You can download and install the latest version by execute this script without any arguments.$(treset)"
    echo
  else
    echo
    echo "$(tgreen)Installed version is up-to-date.$(treset)"
    echo
  fi
}

main() {
  parse_arguments "$@"

  check_permission
  check_environment
  check_slowudp_user "slowudp"
  check_slowudp_homedir "/var/lib/$SLOWUDP_USER"

  case "$OPERATION" in
    "install")
      perform_install
      ;;
    "remove")
      perform_remove
      ;;
    "check_update")
      perform_check_update
      ;;
    *)
      error "Unknown operation '$OPERATION'."
      ;;
  esac
}

main "$@"

# vim:set ft=bash ts=2 sw=2 sts=2 et: