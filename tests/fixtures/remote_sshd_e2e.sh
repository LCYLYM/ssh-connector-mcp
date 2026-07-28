#!/usr/bin/env bash
set -euo pipefail

ACTION=${1:-}
PUBLIC_KEY_FILE=${2:-}
ROOT_DIR=/tmp/ssh-connector-e2e
TEST_USER=sshmcp-e2e
PRIMARY_PORT=${SSHMCP_E2E_PRIMARY_PORT:-22222}
ROTATE_PORT=${SSHMCP_E2E_ROTATE_PORT:-22223}

stop_instance() {
  local port=$1
  local pid_file="$ROOT_DIR/sshd-$port.pid"
  if [[ -s "$pid_file" ]]; then
    local pid
    pid=$(<"$pid_file")
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid"
      for _ in {1..50}; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
      done
    fi
  fi
}

write_config() {
  local port=$1
  local host_key=$2
  local config="$ROOT_DIR/sshd-$port.conf"
  {
    printf 'Port %s\n' "$port"
    printf 'ListenAddress 0.0.0.0\n'
    printf 'PidFile %s/sshd-%s.pid\n' "$ROOT_DIR" "$port"
    printf 'HostKey %s\n' "$host_key"
    printf 'UsePAM yes\n'
    printf 'PasswordAuthentication yes\n'
    printf 'KbdInteractiveAuthentication yes\n'
    printf 'ChallengeResponseAuthentication yes\n'
    printf 'PubkeyAuthentication yes\n'
    printf 'AuthenticationMethods any\n'
    printf 'PermitRootLogin no\n'
    printf 'PermitEmptyPasswords no\n'
    printf 'AllowTcpForwarding yes\n'
    printf 'AuthorizedKeysFile .ssh/authorized_keys\n'
    printf 'StrictModes yes\n'
    printf 'UseDNS no\n'
    printf 'PrintMotd no\n'
    printf 'LogLevel VERBOSE\n'
    printf 'AllowUsers %s\n' "$TEST_USER"
    printf 'Subsystem sftp internal-sftp\n'
  } >"$config"
}

start_instance() {
  local port=$1
  local host_key=$2
  write_config "$port" "$host_key"
  /usr/sbin/sshd -t -f "$ROOT_DIR/sshd-$port.conf"
  /usr/sbin/sshd -f "$ROOT_DIR/sshd-$port.conf" -E "$ROOT_DIR/sshd-$port.log"
}

case "$ACTION" in
  setup)
    if [[ ! -f "$PUBLIC_KEY_FILE" ]]; then
      printf 'public key file is required\n' >&2
      exit 2
    fi
    IFS= read -r test_password
    if [[ -z "$test_password" ]]; then
      printf 'test password must be supplied on stdin\n' >&2
      exit 2
    fi

    mkdir -p "$ROOT_DIR"
    chmod 700 "$ROOT_DIR"
    stop_instance "$PRIMARY_PORT"
    stop_instance "$ROTATE_PORT"
    find "$ROOT_DIR" -mindepth 1 -depth -delete
    if id "$TEST_USER" >/dev/null 2>&1; then
      userdel -r "$TEST_USER" 2>/dev/null || userdel "$TEST_USER"
    fi
    useradd -m -s /bin/bash "$TEST_USER"
    printf '%s:%s\n' "$TEST_USER" "$test_password" | chpasswd
    install -d -m 700 -o "$TEST_USER" -g "$TEST_USER" "/home/$TEST_USER/.ssh"
    install -m 600 -o "$TEST_USER" -g "$TEST_USER" \
      "$PUBLIC_KEY_FILE" "/home/$TEST_USER/.ssh/authorized_keys"

    ssh-keygen -q -t ed25519 -N '' -f "$ROOT_DIR/host-key-a"
    ssh-keygen -q -t ed25519 -N '' -f "$ROOT_DIR/host-key-b"
    start_instance "$PRIMARY_PORT" "$ROOT_DIR/host-key-a"
    start_instance "$ROTATE_PORT" "$ROOT_DIR/host-key-a"
    ;;
  rotate)
    stop_instance "$ROTATE_PORT"
    start_instance "$ROTATE_PORT" "$ROOT_DIR/host-key-b"
    ;;
  cleanup)
    stop_instance "$PRIMARY_PORT"
    stop_instance "$ROTATE_PORT"
    if id "$TEST_USER" >/dev/null 2>&1; then
      userdel -r "$TEST_USER" 2>/dev/null || userdel "$TEST_USER"
    fi
    if [[ -d "$ROOT_DIR" ]]; then
      find "$ROOT_DIR" -depth -delete
    fi
    ;;
  *)
    printf 'usage: %s setup PUBLIC_KEY_FILE | rotate | cleanup\n' "$0" >&2
    exit 2
    ;;
esac
