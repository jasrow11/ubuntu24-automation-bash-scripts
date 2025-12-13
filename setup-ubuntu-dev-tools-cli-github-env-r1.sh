#!/usr/bin/env bash
# =============================================================================
# SCRIPT NAME: setup-ubuntu-dev-tools-cli-github-env-r1.sh
# AUTHOR: Jason Rowsell (jason@jasonrowsell.net)
# CREATED: 12-12-2025
# Tested on Ubuntu 24.04.3 LTS (Noble/Desktop & Server)
# License: MIT License
# =============================================================================
#
# DESCRIPTION:
#   CLI-based developer environment bootstrap script for Ubuntu 24.04.3.
#   Installs a full toolchain for system programming, scripting, and DevOps,
#   including compilers, debuggers, linters, Docker, Terraform, version managers,
#   and Git configuration.
#
# FEATURES:
#   - Installs latest stable versions of core dev tools using upstream sources
#   - Rust via rustup, Docker via Docker CE repo, Terraform via HashiCorp repo
#   - Version managers: pyenv, nvm, asdf
#   - Interactive Git setup (username and email)
#   - Detects user shell and modifies the correct shell RC file
#   - Verifies tool versions post-install
#
# REQUIREMENTS:
#
# Important - This script must be run with sudo because it installs packages, modifies /etc/apt, and adds system-level users to groups (e.g., Docker).
#
#   - Must be run with root privileges (use sudo)
#   - Interactive terminal session
#
#
# Example:
#
# Make script executable:
# chmod +x setup-ubuntu-dev-tools-cli-github-env-r1.sh
#
# Run script (it will prompt you for github account information).
# sudo ./setup-ubuntu-dev-tools-cli-github-env-r1.sh
#
# =============================================================================
# REVISION HISTORY
# -----------------------------------------------------------------------------
# DATE         | VERSION | AUTHOR       | CHANGE
# -------------|---------|--------------|--------------------------------------
# 12-13-2025   | 1.0.1   |Jason Rowsell | Initial release with all features.
# =============================================================================
#
#
# License:        MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
# ---------------------------------------------------------------------------
#
# Begin script

set -euo pipefail

UBUNTU_CODENAME="noble"

main() {
    check_root
    update_system
    install_dev_packages
    install_rust
    install_pyenv
    install_nvm
    install_asdf
    install_terraform
    install_docker
    configure_git
    update_shell_profile
    verify_versions
    printf "Development environment setup complete.\n"
}

check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        printf "This script must be run as root.\n" >&2
        return 1
    fi
}

update_system() {
    # Refresh APT sources and upgrade base system packages
    apt-get update -y && apt-get upgrade -y
    apt-get install -y software-properties-common curl gnupg2 lsb-release ca-certificates apt-transport-https
}

install_dev_packages() {
    # === Install core development tools from APT ===
    apt-get install -y \
        build-essential \
        cmake \
        gdb \
        lldb \
        valgrind \
        python3 \
        python3-pip \
        python3-venv \
        pipx \
        git \
        jq \
        unzip \
        shellcheck \
        tree \
        wget \
        neovim
    pipx ensurepath
}

install_rust() {
    # Install Rust via official rustup script
    if ! command -v rustup > /dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi
}

install_pyenv() {
    local pyenv_root="$HOME/.pyenv"

    if [[ ! -d "$pyenv_root" ]]; then
        # Install pyenv from GitHub (latest stable)
        git clone https://github.com/pyenv/pyenv.git "$pyenv_root"
    fi
}

install_nvm() {
    if [[ ! -d "$HOME/.nvm" ]]; then
        # Install NVM using official install script
        curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
    fi
}

install_asdf() {
    local asdf_dir="$HOME/.asdf"

    if [[ ! -d "$asdf_dir" ]]; then
        # Install ASDF from GitHub (multi-runtime version manager)
        git clone https://github.com/asdf-vm/asdf.git "$asdf_dir" --branch v0.14.0
    fi
}

install_terraform() {
    local key_url="https://apt.releases.hashicorp.com/gpg"
    local repo_entry="deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com ${UBUNTU_CODENAME} main"

    if [[ ! -f /usr/share/keyrings/hashicorp-archive-keyring.gpg ]]; then
        curl -fsSL "${key_url}" | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
    fi

    if ! grep -q "^${repo_entry}" /etc/apt/sources.list.d/hashicorp.list 2>/dev/null; then
        printf "%s\n" "${repo_entry}" > /etc/apt/sources.list.d/hashicorp.list
        apt-get update -y
    fi

    apt-get install -y terraform
}

install_docker() {
    if ! command -v docker > /dev/null 2>&1; then
        apt-get remove -y docker docker-engine docker.io containerd runc || true

        # === Install Docker CE using official Docker APT repo ===
        install_docker_dependencies
        setup_docker_repo
        apt-get update -y
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

        # NOTE: Docker group membership will take effect after re-login
        usermod -aG docker "${SUDO_USER:-$USER}"
    fi
}

install_docker_dependencies() {
    apt-get install -y ca-certificates curl gnupg
    mkdir -p /etc/apt/keyrings
}

setup_docker_repo() {
    local keyring="/etc/apt/keyrings/docker.gpg"
    local arch; arch=$(dpkg --print-architecture)
    local repo="deb [arch=${arch} signed-by=${keyring}] https://download.docker.com/linux/ubuntu ${UBUNTU_CODENAME} stable"

    if [[ ! -f "$keyring" ]]; then
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o "$keyring"
    fi

    printf "%s\n" "${repo}" > /etc/apt/sources.list.d/docker.list
}

configure_git() {
    # === Prompt user for Git identity ===
    local git_user git_email

    printf "\n🔧 Git Configuration:\n"
    read -rp "Enter your Git user.name: " git_user
    read -rp "Enter your Git user.email: " git_email

    if [[ -z "${git_user// }" ]] || [[ -z "${git_email// }" ]]; then
        printf "Git name and email cannot be empty.\n" >&2
        return 1
    fi

    # Set global Git config
    git config --global user.name "$git_user"
    git config --global user.email "$git_email"
    git config --global init.defaultBranch main
    git config --global pull.rebase false
    git config --global core.editor nvim

    printf "Git configured.\n"
}

update_shell_profile() {
    # === Inject version manager initialization into shell config ===
    local shell_rc
    shell_rc=$(detect_shell_rc)

    if [[ -z "$shell_rc" ]]; then
        printf "Unable to detect a writable shell profile.\n" >&2
        return 1
    fi

    # NOTE: Avoid duplicate entries
    append_if_missing "$shell_rc" 'export PYENV_ROOT="$HOME/.pyenv"'
    append_if_missing "$shell_rc" '[[ -d "$PYENV_ROOT/bin" ]] && export PATH="$PYENV_ROOT/bin:$PATH"'
    append_if_missing "$shell_rc" 'eval "$(pyenv init --path)"'

    append_if_missing "$shell_rc" 'export NVM_DIR="$HOME/.nvm"'
    append_if_missing "$shell_rc" '[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"'

    append_if_missing "$shell_rc" '. "$HOME/.asdf/asdf.sh"'
    append_if_missing "$shell_rc" '. "$HOME/.asdf/completions/asdf.bash"'
}

detect_shell_rc() {
    local shell rc

    shell=$(getent passwd "$SUDO_USER" | cut -d: -f7)

    case "$shell" in
        */bash) rc="$HOME/.bashrc" ;;
        */zsh)  rc="$HOME/.zshrc"  ;;
        *)      rc="" ;;
    esac

    [[ -w "$rc" ]] && printf "%s\n" "$rc" || printf ""
}

append_if_missing() {
    local file="$1"
    local line="$2"

    grep -qxF "$line" "$file" 2>/dev/null || printf "\n%s\n" "$line" >> "$file"
}

verify_versions() {
    printf "\n Verifying Installed Versions:\n"

    # NOTE: We skip error trapping here to show all available versions
    set +e
    command -v gcc        && gcc --version | head -n1
    command -v rustc      && rustc --version
    command -v python3    && python3 --version
    command -v docker     && docker --version
    command -v terraform  && terraform -version | head -n1
    command -v git        && git --version
    command -v nvim       && nvim --version | head -n1
    set -e
}

main "$@"

#END Script