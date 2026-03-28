#!/usr/bin/env bash
# =============================================================================
# AEGIS-FLOW :: Git Initialise Script
# =============================================================================
# Initialises a local git repository, makes an initial commit,
# and prints instructions for pushing to GitHub.
#
# Usage:
#   chmod +x scripts/git_init.sh
#   ./scripts/git_init.sh
# =============================================================================

set -euo pipefail

CYAN="\033[0;36m"
GREEN="\033[0;32m"
BOLD="\033[1m"
RESET="\033[0m"

info()    { echo -e "${CYAN}[aegis]${RESET} $*"; }
success() { echo -e "${GREEN}[aegis] ✅ $*${RESET}"; }

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║       AEGIS-FLOW :: Git Repository Init            ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# Initialise repo if not already one
if [ ! -d ".git" ]; then
  info "Initialising git repository..."
  git init
  git branch -M main
  success "Git repo initialised on branch 'main'"
else
  info "Git repository already exists"
fi

# Stage all files
info "Staging all files..."
git add .

# Initial commit
info "Creating initial commit..."
git commit -m "feat: AEGIS-FLOW v1.0.0 — initial release

- Core runtime fingerprinting engine (SHA-256 state hashing)
- Continuous monitoring loop with configurable interval
- Enclave simulator (TEE interface, nonce validation, HMAC signing)
- Alert manager with severity levels and pluggable hooks
- AegisRegistry Solidity smart contract (EVM-compatible)
- Python blockchain client (web3.py)
- Hardhat deployment + test suite
- GitHub Actions CI/CD (Python lint/test + Solidity compile)
- Full setup script and documentation"

success "Initial commit created"

echo ""
echo -e "${BOLD}Next steps — push to GitHub:${RESET}"
echo ""
echo "  1. Create a new repository on GitHub:"
echo "     https://github.com/new"
echo "     Name it: aegis-flow"
echo "     Leave it EMPTY (no README, no .gitignore)"
echo ""
echo "  2. Add the remote and push:"
echo "     git remote add origin https://github.com/YOUR_USERNAME/aegis-flow.git"
echo "     git push -u origin main"
echo ""
echo "  3. After pushing, enable GitHub Actions in the repo Settings → Actions"
echo ""
echo -e "${GREEN}Done! Your AEGIS-FLOW repository is ready to push.${RESET}"
