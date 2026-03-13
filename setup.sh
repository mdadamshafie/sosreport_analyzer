#!/usr/bin/env bash
# ============================================================
#  SOSreport Analyzer V7 – WSL2 / Linux Bootstrap
#
#  What it does:
#    1. Installs Docker Engine + Docker Compose plugin (if missing)
#    2. Starts the Docker daemon (if not already running)
#    3. Builds & launches all four services
#
#  Run from the repo root:
#    chmod +x setup.sh && ./setup.sh
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Helper: ensure Docker apt repo is configured ─────────────
ensure_docker_repo() {
    if [ -f /etc/apt/sources.list.d/docker.list ]; then
        return 0   # already set up
    fi
    info "Adding Docker apt repository …"
    sudo apt-get update -qq
    sudo apt-get install -y -qq \
        ca-certificates curl gnupg lsb-release >/dev/null

    sudo install -m 0755 -d /etc/apt/keyrings
    if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
            | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        sudo chmod a+r /etc/apt/keyrings/docker.gpg
    fi

    DISTRO=$(. /etc/os-release && echo "$ID")
    CODENAME=$(. /etc/os-release && echo "$VERSION_CODENAME")
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
      https://download.docker.com/linux/${DISTRO} ${CODENAME} stable" \
      | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null

    sudo apt-get update -qq
}

# ── 1. Docker Engine ─────────────────────────────────────────
install_docker() {
    info "Installing Docker Engine …"
    ensure_docker_repo

    sudo apt-get install -y -qq \
        docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin >/dev/null

    # Let current user run Docker without sudo
    sudo usermod -aG docker "$USER" 2>/dev/null || true
    info "Docker Engine installed."
}

if ! command -v docker &>/dev/null; then
    install_docker
else
    info "Docker Engine already installed ($(docker --version))"
fi

# ── 2. Docker Compose plugin ────────────────────────────────
if ! docker compose version &>/dev/null; then
    warn "docker compose plugin not found – installing …"
    ensure_docker_repo
    sudo apt-get install -y -qq docker-compose-plugin >/dev/null
fi
info "Docker Compose $(docker compose version --short)"

# ── 2b. Docker Buildx plugin (required for 'docker compose --build') ─
if ! docker buildx version &>/dev/null 2>&1; then
    warn "docker buildx plugin not found – installing …"
    ensure_docker_repo
    sudo apt-get install -y -qq docker-buildx-plugin 2>/dev/null || true
    # Verify it installed correctly; if not, download binary directly
    if ! docker buildx version &>/dev/null 2>&1; then
        warn "apt package unavailable – installing buildx from GitHub release …"
        BUILDX_VERSION=$(curl -s https://api.github.com/repos/docker/buildx/releases/latest \
            | grep -oP '"tag_name": "\K[^"]+' || echo "v0.32.1")
        BUILDX_URL="https://github.com/docker/buildx/releases/download/${BUILDX_VERSION}/buildx-${BUILDX_VERSION}.linux-$(dpkg --print-architecture)"
        sudo mkdir -p /usr/local/lib/docker/cli-plugins
        sudo curl -fsSL "$BUILDX_URL" -o /usr/local/lib/docker/cli-plugins/docker-buildx
        sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-buildx
    fi
    docker buildx version &>/dev/null 2>&1 || error "Failed to install docker buildx. Please install manually."
fi
info "Docker Buildx $(docker buildx version 2>/dev/null | head -1)"

# ── 3. Ensure Docker daemon is running ──────────────────────
if ! docker info &>/dev/null 2>&1; then
    info "Starting Docker daemon …"
    sudo service docker start || sudo dockerd &>/dev/null &
    # Wait up to 30 s for the daemon
    for i in $(seq 1 30); do
        docker info &>/dev/null 2>&1 && break
        sleep 1
    done
    docker info &>/dev/null 2>&1 || error "Docker daemon failed to start."
fi
info "Docker daemon is running."

# ── 4. Build & launch ───────────────────────────────────────
info "Building & starting all services (InfluxDB, Loki, Grafana, Streamlit) …"
CACHEBUST=$(date +%s) docker compose -f docker-compose.all.yml up --build -d

echo ""
info "──────────────────────────────────────────────"
info " All services are up!"
info ""
info "  Streamlit App : http://localhost:8501"
info "  InfluxDB      : http://localhost:8086"
info "  Loki          : http://localhost:3100"
info "  Grafana       : http://localhost:3000"
info "                  user: admin  pass: sosreport2026"
info "──────────────────────────────────────────────"
info ""
info "Useful commands:"
info "  docker compose -f docker-compose.all.yml logs -f app   # app logs"
info "  docker compose -f docker-compose.all.yml down           # stop"
info "  docker compose -f docker-compose.all.yml down -v        # stop + wipe data"
