#!/usr/bin/env bash
# =============================================================================
# AEGIS-FLOW :: Local Setup Script
# =============================================================================
# Run this once to bootstrap your local development environment.
#
# Usage:
#   chmod +x scripts/setup.sh
#   ./scripts/setup.sh
#
# What it does:
#   1. Checks system prerequisites (Python, Node, Git)
#   2. Creates Python virtual environment
#   3. Installs Python dependencies
#   4. Installs Node/Hardhat dependencies
#   5. Copies .env.example → .env
#   6. Creates logs/ directory
#   7. Runs Python tests to verify setup
# =============================================================================

set -euo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
CYAN="\033[0;36m"
RESET="\033[0m"

info()    { echo -e "${CYAN}[aegis]${RESET} $*"; }
success() { echo -e "${GREEN}[aegis] ✅ $*${RESET}"; }
warn()    { echo -e "${YELLOW}[aegis] ⚠️  $*${RESET}"; }
error()   { echo -e "${RED}[aegis] ❌ $*${RESET}"; exit 1; }

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║          AEGIS-FLOW  v1.0.0 :: Setup               ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ── 1. Prerequisites ───────────────────────────────────────────────────
info "Checking prerequisites..."

command -v python3 >/dev/null 2>&1 || error "Python 3 is required. Install from https://python.org"
command -v node    >/dev/null 2>&1 || error "Node.js is required. Install from https://nodejs.org"
command -v npm     >/dev/null 2>&1 || error "npm is required (comes with Node.js)"
command -v git     >/dev/null 2>&1 || error "Git is required. Install from https://git-scm.com"

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
NODE_VERSION=$(node --version)
info "Python: $PYTHON_VERSION  |  Node: $NODE_VERSION"

# ── 2. Python virtual environment ─────────────────────────────────────
if [ ! -d "venv" ]; then
  info "Creating Python virtual environment..."
  python3 -m venv venv
  success "Virtual environment created at ./venv"
else
  warn "Virtual environment already exists — skipping creation"
fi

info "Activating virtual environment..."
# shellcheck disable=SC1091
source venv/bin/activate

# ── 3. Python dependencies ─────────────────────────────────────────────
info "Installing Python dependencies..."
pip install --upgrade pip -q
pip install -r requirements.txt -q
success "Python dependencies installed"

# ── 4. Node / Hardhat dependencies ────────────────────────────────────
info "Installing Node.js / Hardhat dependencies..."
npm install --silent
success "Node.js dependencies installed"

# ── 5. Environment file ───────────────────────────────────────────────
if [ ! -f ".env" ]; then
  info "Copying .env.example → .env"
  cp .env.example .env
  success ".env created — edit it to configure blockchain settings"
else
  warn ".env already exists — skipping"
fi

# ── 6. Create logs directory ──────────────────────────────────────────
mkdir -p logs
success "logs/ directory ready"

# ── 7. Compile Solidity contracts ─────────────────────────────────────
info "Compiling Solidity contracts..."
npx hardhat compile --quiet
success "Contracts compiled"

# ── 8. Run Python tests ───────────────────────────────────────────────
info "Running Python test suite..."
pytest tests/ -v --tb=short
success "All tests passed"

# ── Done ──────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}Setup complete! 🚀${RESET}"
echo ""
echo -e "  ${BOLD}Run the monitor:${RESET}"
echo "    source venv/bin/activate"
echo "    python main.py"
echo ""
echo -e "  ${BOLD}Run a single integrity check:${RESET}"
echo "    python main.py --once"
echo ""
echo -e "  ${BOLD}Start a local Ethereum node:${RESET}"
echo "    npm run node"
echo ""
echo -e "  ${BOLD}Deploy contract locally:${RESET}"
echo "    npm run deploy:local"
echo ""
echo -e "  ${BOLD}Enable blockchain anchoring:${RESET}"
echo "    Edit .env → set AEGIS_BLOCKCHAIN_ENABLED=true"
echo "    python main.py --blockchain --rpc-url http://127.0.0.1:8545 \\"
echo "                   --contract <ADDR> --private-key <KEY>"
echo ""
