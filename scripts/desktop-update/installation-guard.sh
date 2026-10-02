# Native directory observation; no interpreter or sentinel contents are needed.
self_update_installation_guard() {
  local physical_root observed marker
  physical_root="$(cd -- "$INSTALL_ROOT" 2>/dev/null && pwd -P)" || {
    echo "Self-update protection could not be checked for this installation. Use operator-managed maintenance." >&2
    return 2
  }
  observed="$(find -H "$physical_root" -mindepth 1 -maxdepth 1 -name '.hermes-self-update-disabled' -print 2>/dev/null)" || {
    echo "Self-update protection could not be checked for this installation. Use operator-managed maintenance." >&2
    return 2
  }
  # Native lookup also sees case aliases on case-insensitive filesystems.
  # Enumeration still must complete, and -L includes dangling marker links.
  marker="$physical_root/.hermes-self-update-disabled"
  if [ -n "$observed" ] || [ -e "$marker" ] || [ -L "$marker" ]; then
    echo "Self-update is disabled for this installation. Use operator-managed maintenance." >&2
    return 2
  fi
  INSTALL_ROOT="$physical_root"
}
