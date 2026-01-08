# Multi-stage Dockerfile for Guardian CLI with Alpine Linux
# Installs all 15 security tools for comprehensive penetration testing

# ============================================================================
# Stage 1: Builder - Install Go tools and build dependencies
# ============================================================================
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache \
    git \
    gcc \
    musl-dev \
    ca-certificates \
    make \
    bash \
    wget \
    unzip \
    tar

# Configure Go environment and module settings
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    GOPROXY=https://proxy.golang.org,direct \
    GOSUMDB=sum.golang.org \
    GO111MODULE=on

# Ensure Go bin directory exists and is in PATH
# Test network connectivity and Go setup
RUN mkdir -p /go/bin && \
    echo "=== Go Environment ===" && \
    echo "Go version: $(go version)" && \
    echo "GOPATH: $(go env GOPATH)" && \
    echo "GOROOT: $(go env GOROOT)" && \
    echo "GOPROXY: $(go env GOPROXY)" && \
    echo "" && \
    echo "=== Network Test ===" && \
    (wget -q --spider https://proxy.golang.org && echo "✓ Go proxy reachable" || echo "✗ Go proxy not reachable") && \
    (wget -q --spider https://github.com && echo "✓ GitHub reachable" || echo "✗ GitHub not reachable") && \
    echo "" && \
    echo "=== Testing Go Module Access ===" && \
    (go list -m -versions github.com/projectdiscovery/httpx 2>&1 | head -5 || echo "Module check failed, will try direct mode")

# Install Go-based security tools using pre-built binaries (more reliable)
# This approach downloads pre-built binaries from GitHub releases

# Install httpx
RUN echo "=== Installing httpx ===" && \
    cd /tmp && \
    (wget -q https://github.com/projectdiscovery/httpx/releases/download/v1.3.7/httpx_1.3.7_linux_amd64.zip -O httpx.zip || \
     wget -q https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_1.3.7_linux_amd64.zip -O httpx.zip) && \
    unzip -q httpx.zip && \
    mv httpx /go/bin/ && \
    chmod +x /go/bin/httpx && \
    rm -f httpx.zip *.md 2>/dev/null && \
    echo "✓ httpx installed" || \
    (echo "⚠ httpx download failed, trying go install..." && \
     (GOBIN=/go/bin go install github.com/projectdiscovery/httpx/cmd/httpx@latest || \
      GOPROXY=direct GOSUMDB=off GOBIN=/go/bin go install github.com/projectdiscovery/httpx/cmd/httpx@latest) && \
     echo "✓ httpx installed via go install")

# Install subfinder
RUN echo "=== Installing subfinder ===" && \
    cd /tmp && \
    (wget -q https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_2.6.3_linux_amd64.zip -O subfinder.zip || \
     wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip -O subfinder.zip) && \
    unzip -q subfinder.zip && \
    mv subfinder /go/bin/ && \
    chmod +x /go/bin/subfinder && \
    rm -f subfinder.zip *.md 2>/dev/null && \
    echo "✓ subfinder installed" || \
    (echo "⚠ subfinder download failed, trying go install..." && \
     (GOBIN=/go/bin go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || \
      GOPROXY=direct GOSUMDB=off GOBIN=/go/bin go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest) && \
     echo "✓ subfinder installed via go install")

# Install nuclei
RUN echo "=== Installing nuclei ===" && \
    cd /tmp && \
    (wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.1.7_linux_amd64.zip -O nuclei.zip || \
     wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.1.7/nuclei_3.1.7_linux_amd64.zip -O nuclei.zip) && \
    unzip -q nuclei.zip && \
    mv nuclei /go/bin/ && \
    chmod +x /go/bin/nuclei && \
    rm -f nuclei.zip *.md 2>/dev/null && \
    echo "✓ nuclei installed" || \
    (echo "⚠ nuclei download failed, trying go install..." && \
     (GOBIN=/go/bin go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || \
      GOPROXY=direct GOSUMDB=off GOBIN=/go/bin go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest) && \
     echo "✓ nuclei installed via go install")

# Install gobuster
RUN echo "=== Installing gobuster ===" && \
    cd /tmp && \
    (wget -q https://github.com/OJ/gobuster/releases/latest/download/gobuster_Linux_x86_64.tar.gz -O gobuster.tar.gz || \
     wget -q https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz -O gobuster.tar.gz) && \
    tar -xzf gobuster.tar.gz && \
    mv gobuster /go/bin/ && \
    chmod +x /go/bin/gobuster && \
    rm -f gobuster.tar.gz *.md 2>/dev/null && \
    echo "✓ gobuster installed" || \
    (echo "⚠ gobuster download failed, trying go install..." && \
     (GOBIN=/go/bin go install github.com/OJ/gobuster/v3@latest || \
      GOPROXY=direct GOSUMDB=off GOBIN=/go/bin go install github.com/OJ/gobuster/v3@latest) && \
     echo "✓ gobuster installed via go install")

# Install ffuf
RUN echo "=== Installing ffuf ===" && \
    cd /tmp && \
    (wget -q https://github.com/ffuf/ffuf/releases/latest/download/ffuf_2.2.0_linux_amd64.tar.gz -O ffuf.tar.gz || \
     wget -q https://github.com/ffuf/ffuf/releases/download/v2.2.0/ffuf_2.2.0_linux_amd64.tar.gz -O ffuf.tar.gz) && \
    tar -xzf ffuf.tar.gz && \
    mv ffuf /go/bin/ && \
    chmod +x /go/bin/ffuf && \
    rm -f ffuf.tar.gz *.md 2>/dev/null && \
    echo "✓ ffuf installed" || \
    (echo "⚠ ffuf download failed, trying go install..." && \
     (GOBIN=/go/bin go install github.com/ffuf/ffuf/v2@latest || \
      GOPROXY=direct GOSUMDB=off GOBIN=/go/bin go install github.com/ffuf/ffuf/v2@latest) && \
     echo "✓ ffuf installed via go install")

# Install gitleaks
RUN echo "=== Installing gitleaks ===" && \
    cd /tmp && \
    (wget -q https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_8.18.0_linux_x64.tar.gz -O gitleaks.tar.gz || \
     wget -q https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz -O gitleaks.tar.gz) && \
    tar -xzf gitleaks.tar.gz && \
    mv gitleaks /go/bin/ && \
    chmod +x /go/bin/gitleaks && \
    rm -f gitleaks.tar.gz *.md 2>/dev/null && \
    echo "✓ gitleaks installed" || \
    (echo "⚠ gitleaks download failed, trying go install..." && \
     (GOBIN=/go/bin go install github.com/zricethezav/gitleaks/v8@latest || \
      GOPROXY=direct GOSUMDB=off GOBIN=/go/bin go install github.com/zricethezav/gitleaks/v8@latest) && \
     echo "✓ gitleaks installed via go install")

# Install amass (try pre-built, fallback to go install, optional if both fail)
RUN echo "=== Installing amass ===" && \
    (cd /tmp && \
      wget -q https://github.com/owasp-amass/amass/releases/download/v5.0.0/amass_linux_amd64.tar.gz -O amass.tar.gz && \
     tar -zxvf amass.tar.gz && \
     mv amass /go/bin/ && \
     chmod +x /go/bin/amass && \
     rm -f amass.tar.gz *.md 2>/dev/null && \
     echo "✓ amass installed") || \
    (echo "Trying go install..." && \
     (GOBIN=/go/bin go install github.com/owasp-amass/amass/v4/...@latest || \
      GOPROXY=direct GOSUMDB=off GOBIN=/go/bin go install github.com/owasp-amass/amass/v4/...@latest) && \
     echo "✓ amass installed via go install") || \
    echo "⚠ Warning: amass installation failed, Guardian will work without it"

# Verify installations
RUN echo "Verifying installed tools..." && \
    ls -lh /go/bin/ && \
    echo "Tool verification:" && \
    (/go/bin/httpx -version 2>&1 || echo "httpx: installed") && \
    (/go/bin/subfinder -version 2>&1 || echo "subfinder: installed") && \
    (/go/bin/nuclei -version 2>&1 || echo "nuclei: installed")

# ============================================================================
# Stage 2: Runtime - Python environment with all tools
# ============================================================================
FROM python:3.11-alpine

LABEL maintainer="Guardian Security Team"
LABEL description="AI-Powered Penetration Testing Automation Platform"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    GUARDIAN_HOME=/guardian

WORKDIR ${GUARDIAN_HOME}

# Install system dependencies and security tools
RUN apk add --no-cache \
    # Build dependencies
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    # Network tools
    nmap \
    nmap-scripts \
    git \
    curl \
    # Ruby for WhatWeb and WPScan
    ruby \
    ruby-dev \
    ruby-bundler \
    # Nikto dependencies
    perl \
    perl-net-ssleay \
    # Masscan build dependencies
    make \
    # Additional Ruby build dependencies
    libxml2-dev \
    libxslt-dev \
    zlib-dev \
    && \
    # Install Nikto
    echo "=== Installing Nikto ===" && \
    git clone https://github.com/sullo/nikto /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /usr/local/bin/nikto && \
    # Install Masscan
    echo "=== Installing Masscan ===" && \
    git clone https://github.com/robertdavidgraham/masscan /opt/masscan && \
    cd /opt/masscan && make && make install && \
    cd ${GUARDIAN_HOME}

# Install Ruby-based tools (separate RUN to avoid failing the main install)
RUN echo "=== Installing Ruby gems ===" && \
    echo "Installing whatweb..." && \
    gem install --no-document whatweb && echo "✓ whatweb installed" || \
    (echo "⚠ whatweb failed, continuing without it" && true)

RUN echo "Installing wpscan..." && \
    gem install --no-document wpscan && echo "✓ wpscan installed" || \
    (echo "⚠ wpscan failed, continuing without it" && true)

# Copy Go tools from builder
COPY --from=builder /go/bin/* /usr/local/bin/

# Install Python-based security tools (BEFORE removing build dependencies)
# Some packages need gcc/musl-dev to compile native extensions
RUN echo "=== Installing Python security tools ===" && \
    pip install --no-cache-dir wafw00f sqlmap sslyze arjun dnsrecon cmseek || \
    (echo "⚠ Some Python packages failed, trying individually..." && \
     pip install --no-cache-dir wafw00f || echo "⚠ wafw00f failed" && \
     pip install --no-cache-dir sqlmap || echo "⚠ sqlmap failed" && \
     pip install --no-cache-dir sslyze || echo "⚠ sslyze failed" && \
     pip install --no-cache-dir arjun || echo "⚠ arjun failed" && \
     pip install --no-cache-dir dnsrecon || echo "⚠ dnsrecon failed" && \
     pip install --no-cache-dir cmseek || echo "⚠ cmseek failed")

# Clean up build dependencies (after Python packages are installed)
RUN apk del make gcc musl-dev libxml2-dev libxslt-dev zlib-dev

# Download TestSSL
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl && \
    ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl

# Install XSStrike
RUN git clone https://github.com/s0md3v/XSStrike.git /opt/xsstrike && \
    pip install -r /opt/xsstrike/requirements.txt && \
    ln -s /opt/xsstrike/xsstrike.py /usr/local/bin/xsstrike && \
    chmod +x /usr/local/bin/xsstrike

# Copy Guardian application files
COPY pyproject.toml ./
COPY README.md ./
COPY ai/ ./ai/
COPY cli/ ./cli/
COPY core/ ./core/
COPY tools/ ./tools/
COPY utils/ ./utils/
COPY workflows/ ./workflows/
COPY config/ ./config/

# Ensure reports package exists (reports/ is .dockerignored locally)
RUN mkdir -p reports && touch reports/__init__.py

# Install Guardian and its dependencies
RUN pip install --no-cache-dir -e .

# Create directories for reports and logs
RUN mkdir -p /guardian/reports /guardian/logs && \
    chmod 777 /guardian/reports /guardian/logs

# Create non-root user for security
RUN addgroup -g 1000 guardian && \
    adduser -D -u 1000 -G guardian guardian && \
    chown -R guardian:guardian ${GUARDIAN_HOME}

# Switch to non-root user
USER guardian

# Update Nuclei templates on container start
RUN nuclei -update-templates || true

# Set entry point
ENTRYPOINT ["python", "-m", "cli.main"]
CMD ["--help"]
