#!/bin/sh
set -eu

REPO="0xOpCode/sysbridge-mcp"
BINARY="sysbridge-mcp"
VERSION="${SYSBRIDGE_VERSION:-latest}"

log() {
  printf "[sysbridge-mcp] %s\n" "$1"
}

err() {
  printf "[sysbridge-mcp] ERROR: %s\n" "$1" >&2
  exit 1
}

detect_os() {
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$os" in
    linux*|android*)
      printf "linux"
      ;;
    darwin*)
      printf "darwin"
      ;;
    freebsd*)
      printf "freebsd"
      ;;
    *)
      err "unsupported operating system: $os"
      ;;
  esac
}

detect_arch() {
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64)
      printf "amd64"
      ;;
    aarch64|arm64)
      printf "arm64"
      ;;
    armv7l|armv8l|arm)
      printf "armv7"
      ;;
    i386|i686)
      printf "386"
      ;;
    *)
      err "unsupported CPU architecture: $arch"
      ;;
  esac
}

resolve_bindir() {
  if [ -n "${BINDIR:-}" ]; then
    printf "%s" "$BINDIR"
    return
  fi

  # Termux sets PREFIX to /data/data/com.termux/files/usr and forbids root chown
  if [ -n "${TERMUX_VERSION:-}" ] || { [ -n "${PREFIX:-}" ] && [ -d "${PREFIX}/bin" ] && case "${PREFIX}" in *com.termux*) true ;; *) false ;; esac; }; then
    printf "%s/bin" "$PREFIX"
    return
  fi

  if [ -w "/usr/local/bin" ]; then
    printf "/usr/local/bin"
    return
  fi

  printf "%s/.local/bin" "${HOME:-/tmp}"
}

fetch() {
  url="$1"
  out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$out"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
  else
    err "curl or wget is required to download release archives"
  fi
}

fetch_stdout() {
  url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- "$url"
  else
    err "curl or wget is required"
  fi
}

main() {
  os="$(detect_os)"
  arch="$(detect_arch)"
  target_dir="$(resolve_bindir)"
  mkdir -p "$target_dir"

  if [ -f "./cmd/sysbridge-mcp/main.go" ] && command -v go >/dev/null 2>&1 && [ "${SYSBRIDGE_FORCE_DOWNLOAD:-0}" != "1" ]; then
    log "building ${BINARY} from local source for ${os}/${arch}"
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "${target_dir}/${BINARY}" ./cmd/sysbridge-mcp
    chmod 0755 "${target_dir}/${BINARY}"
    log "installed ${BINARY} to ${target_dir}/${BINARY}"
    return 0
  fi

  if [ "$VERSION" = "latest" ]; then
    tag="$(fetch_stdout "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
    if [ -z "$tag" ]; then
      err "unable to resolve latest release tag from GitHub API"
    fi
  else
    tag="$VERSION"
  fi

  ver_num="${tag#v}"
  archive="${BINARY}_${ver_num}_${os}_${arch}.tar.gz"
  base_url="https://github.com/${REPO}/releases/download/${tag}"

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT INT TERM

  log "downloading ${base_url}/${archive}"
  fetch "${base_url}/${archive}" "${tmpdir}/${archive}"
  fetch "${base_url}/checksums.txt" "${tmpdir}/checksums.txt"

  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$tmpdir" && grep " ${archive}\$" checksums.txt | sha256sum -c - >/dev/null)
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$tmpdir" && grep " ${archive}\$" checksums.txt | shasum -a 256 -c - >/dev/null)
  fi

  tar -xzf "${tmpdir}/${archive}" -C "$tmpdir"
  install -m 0755 "${tmpdir}/${BINARY}" "${target_dir}/${BINARY}"
  log "installed ${BINARY} ${tag} to ${target_dir}/${BINARY}"

  case ":${PATH:-}:" in
    *":${target_dir}:"*) ;;
    *)
      log "add ${target_dir} to your PATH: export PATH=\"${target_dir}:\$PATH\""
      ;;
  esac
}

main "$@"
