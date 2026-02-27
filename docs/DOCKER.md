# Docker Deployment Guide for Guardian CLI

Guardian CLI can be deployed using Docker for easy setup and consistent environments across different systems. The Docker image includes **all 15 security tools** pre-installed.

## Quick Start

### 1. Build the Docker Image

```bash
docker compose build
```

This will create a Docker image with all security tools installed (~1.5GB).

### 2. Set Up Environment

Create a `.env` file in the project root:

```bash
GOOGLE_API_KEY=your_gemini_api_key_here
```

### 3. Run Guardian

```bash
# List available workflows
docker compose run --rm guardian workflow list

# Run reconnaissance
docker compose run --rm guardian recon --domain example.com

# Run web application scan  
docker compose run --rm guardian workflow run --name web --target https://example.com

# Get help
docker compose run --rm guardian --help
```

---

## Installation Methods

### Method 1: Docker Compose (Recommended)

```bash
# Build and run
docker compose build
docker compose run --rm guardian recon --domain example.com
```

### Method 2: Docker CLI

```bash
# Build image
docker build -t guardian-cli:latest .

# Run with volume mounts
docker run --rm \
  -v $(pwd)/reports:/guardian/reports \
  -v $(pwd)/logs:/guardian/logs \
  -e GOOGLE_API_KEY=your_key_here \
  guardian-cli:latest recon --domain example.com
```

---

## Pre-installed Tools

The Docker image includes all 15 security tools:

| Category | Tools |
|----------|-------|
| **Network Scanning** | Nmap, Masscan |
| **Web Reconnaissance** | httpx, WhatWeb, Wafw00f |
| **Subdomain Discovery** | Subfinder, Amass |
| **Vulnerability Scanning** | Nuclei, Nikto, SQLMap, WPScan |
| **SSL/TLS Testing** | TestSSL, SSLyze |
| **Content Discovery** | Gobuster, FFuf |

All tools are ready to use without additional installation!

---

## Volume Mounts

Guardian uses volume mounts to persist data:

```yaml
volumes:
  - ./reports:/guardian/reports    # Scan reports
  - ./logs:/guardian/logs          # Application logs
  - ./config:/guardian/config      # Custom configuration
  - ./workflows:/guardian/workflows # Custom workflows
```

### Accessing Reports

Reports generated inside the container are automatically saved to your local `./reports/` directory:

```bash
# Run a scan
docker compose run --rm guardian recon --domain example.com

# Reports are saved locally
ls -la ./reports/
```

---

## Configuration

### Environment Variables

Set via `.env` file or command line:

```bash
# Required
GOOGLE_API_KEY=your_api_key

# Optional
GUARDIAN_LOG_LEVEL=INFO
GUARDIAN_SAFE_MODE=true
```

### Custom Configuration

Mount custom `guardian.yaml`:

```bash
docker run --rm \
  -v $(pwd)/my-config.yaml:/guardian/config/guardian.yaml \
  -e GOOGLE_API_KEY=key \
  guardian-cli:latest recon --domain example.com
```

---

## Common Use Cases

### 1. Quick Reconnaissance

```bash
docker compose run --rm guardian recon --domain example.com
```

### 2. Web Application Scan

```bash
docker compose run --rm guardian workflow run --name web --target https://example.com
```

### 3. Network Assessment

```bash
docker compose run --rm guardian workflow run --name network --target 192.168.1.0/24
```

### 4. Generate Report

```bash
docker compose run --rm guardian report --session 20251222_120000 --format html
```

### 5. Interactive Shell

```bash
docker compose run --rm guardian bash
```

---

## Advanced Usage

### Custom Docker Compose

Create `docker compose.override.yml` for custom settings:

```yaml
version: '3.8'

services:
  guardian:
    environment:
      - GUARDIAN_LOG_LEVEL=DEBUG
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G
```

### Building for Production

```bash
# Build optimized image
docker build --no-cache -t guardian-cli:production .

# Tag for registry
docker tag guardian-cli:production registry.example.com/guardian-cli:latest

# Push to registry
docker push registry.example.com/guardian-cli:latest
```

### CI/CD Integration

```yaml
# Example GitLab CI
docker-scan:
  image: guardian-cli:latest
  script:
    - python -m cli.main recon --domain $TARGET_DOMAIN
  artifacts:
    paths:
      - reports/
```

---

## Troubleshooting

### Issue: Build fails with "out of memory"

**Solution**: Increase Docker memory limit:
```bash
# Docker Desktop: Settings → Resources → Memory (4GB+)
```

### Issue: Permission denied on reports directory

**Solution**: Fix permissions:
```bash
chmod 777 -R ./reports ./logs
```

### Issue: Tool not found

**Solution**: Verify tool installation in container:
```bash
docker compose run --rm guardian bash
which nmap httpx nuclei
```

### Issue: API rate limit errors

**Solution**: Check API key and rate limits:
```bash
# Verify API key is set
docker compose run --rm guardian bash -c 'echo $GOOGLE_API_KEY'
```

---

## Performance Optimization

### Reduce Image Size

The multi-stage build already optimizes size. Current image size: ~1.5GB

### Speed Up Builds

Use BuildKit for faster builds:
```bash
DOCKER_BUILDKIT=1 docker compose build
```

### Cache Dependencies

Docker layers cache dependencies automatically. Only rebuild when needed:
```bash
# Rebuild only if Dockerfile changed
docker compose build --no-cache
```

---

## Security Considerations

### Non-Root User

Guardian runs as non-root user `guardian` (UID 1000) for security.

### Network Isolation

Use custom Docker networks for isolation:
```yaml
networks:
  guardian-net:
    driver: bridge
```

### Secrets Management

Never commit `.env` file. Use Docker secrets:
```bash
echo "your_api_key" | docker secret create gemini_key -
```

---

## Cleanup

### Remove Containers

```bash
docker compose down
```

### Remove Images

```bash
docker rmi guardian-cli:latest
```

### Clean Build Cache

```bash
docker builder prune -a
```

---

## Comparison: Docker vs Local

| Feature | Docker | Local Install |
|---------|--------|---------------|
| **Setup Time** | 5 minutes | 30+ minutes |
| **Tool Installation** | All included | Manual per tool |
| **Portability** | ✅ High | ❌ Low |
| **Isolation** | ✅ Sandboxed | ❌ System-wide |
| **Updates** | Rebuild image | Update each tool |
| **Disk Space** | ~1.5GB | ~500MB |

**Recommendation**: Use Docker for quick deployment and consistency. Use local install for development or custom tool versions.

---

## Support

For Docker-specific issues:
- Check logs: `docker compose logs`
- Verify build: `docker compose config`
- Test tools: `docker compose run --rm guardian bash`

For Guardian issues, see main [README.md](../README.md).
