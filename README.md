# OPNsense API

![CI Build](https://github.com/USERNAME/REPOSITORY/actions/workflows/ci.yml/badge.svg)
[![SBOM Dependency Graph](https://img.shields.io/badge/SBOM-Dependency%20Graph-blue)](https://github.com/USERNAME/REPOSITORY/network/dependencies)
[![Vulnerability Scanning](https://img.shields.io/badge/Security-Grype%20Scanned-green)](https://github.com/USERNAME/REPOSITORY/security/code-scanning)

An abstract, highly lightweight microservice interface designed to communicate with OPNsense firewall and network appliances. Built with C for maximum performance and efficiency, packaged using containerization best practices, and backed by automated Software Supply Chain Security pipelines.

> 🤖 **AI Collaboration Disclosure**  
> This project's container architecture, multi-stage build optimization, static/dynamic linkage strategies, and automated CI/CD pipeline (incorporating Syft SBOM generation and Grype vulnerability scanning) were designed and refined with the assistance of **AI**.

---

## 📐 Project Abstract

The **OPNsense API** service acts as a lightweight bridge for programmatic interactions with OPNsense network management features. The project prioritizes:

1. **Minimal Attack Surface:** Built on Alpine Linux multi-stage builds to produce a clean runtime (~10 MB) stripped of non-essential shell utilities and OS bloat.
2. **Software Supply Chain Integrity:** Automated generation of machine-readable Software Bill of Materials (SBOM) compliant with the CycloneDX specification.
3. **Continuous Security Verification:** Shift-left security model featuring automated vulnerability scanning (CVE checks) on every push and pull request.

---

## 🏗️ Container Architecture

The container workflow uses a multi-stage approach to separate compilation dependencies from runtime execution:

* **Builder Stage (`alpine:3.24`):** Compiles the C binary against headers (`curl-dev`, `cjson-dev`, `libmicrohttpd-dev`) and links required system shared objects.
* **Runtime Stage (`alpine:3.24`):** Installs only essential dynamic runtime libraries (`libcurl`, `cjson`, `libmicrohttpd`, `ca-certificates`) and executes the application binary directly.

---

## 🛡️ CI/CD & Supply Chain Security

The continuous integration pipeline is driven by GitHub Actions and Podman:

1. **Container Build & Test:** Builds the container image via Podman and executes health check verification.
2. **SBOM Generation:** Syft (`anchore/sbom-action`) scans the container image archive and produces a `cyclonedx-json` formatted `sbom.json`.
3. **Vulnerability Scanning:** Grype (`anchore/scan-action`) analyzes the SBOM against up-to-date CVE databases.
4. **Security Reporting:** Results are converted into SARIF format and uploaded directly to GitHub Code Scanning.

---

## 🔍 Verifying SBOM & Security Reports

### 1. Repository Main Page & Native Views
* **Dependency Graph:** View detected components directly under the repository's [Insights → Dependency graph](https://github.com/USERNAME/REPOSITORY/network/dependencies) tab.
* **Security Findings:** Review identified CVEs and remediation status under the repository's [Security → Code scanning](https://github.com/USERNAME/REPOSITORY/security/code-scanning) tab.

### 2. Inspecting the SBOM Artifact Locally
Download the `opnsense-api-sbom` artifact from any completed workflow run or release tag:

```bash
# Count total components in the SBOM
jq '.components | length' sbom.json

# List component names and versions
jq '.components[] | {name: .name, version: .version, type: .type}' sbom.json

# Validate standard compliance
cyclonedx validate --input-file sbom.json
```

### 3. Local Vulnerability Scanning
To run an offline CVE audit against the generated SBOM using Grype or Trivy:

```bash
# Scan using Grype
grype sbom:sbom.json

# Scan using Trivy
trivy sbom sbom.json
```

---

## 🚀 Getting Started

### Local Build with Podman
```bash
# Build the container image
podman build -t opnsense-api:latest .

# Run the application
podman run --rm opnsense-api:latest --help
```

