<p align="center">
  <a href="https://fleetfolio.dev/">
    <img src="https://fleetfolio.dev/assets/fleetfolio-logo-rev-Ct20ggww.png" alt="Fleetfolio" width="250">
  </a>
</p>

<p align="center">
  <a href="https://docs.opsfolio.com/fleetfolio/eaa/introduction"><img src="https://img.shields.io/badge/Docs-4285F4?style=for-the-badge&logo=googledocs&logoColor=white" alt="Docs"></a>
  <a href="https://fleetfolio.dev/"><img src="https://img.shields.io/badge/Website-06B6D4?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Website"></a>
</p>

# Fleetfolio: Next-Generation Infrastructure Assurance

[Fleetfolio](https://fleetfolio.dev/) is a powerful infrastructure assurance platform built on surveilr that helps organizations achieve continuous compliance, security, and operational reliability. Unlike traditional asset management tools that simply list discovered assets, Fleetfolio takes a proactive approach by defining expected infrastructure assets and verifying them against actual assets found using osQuery Management Server (MS).

Fleetfolio consists of two core components:

- **EAA (Enterprise Asset Assurance)**
- **TEM (Threat Exposure Management)**

Together, EAA and TEM provide a complete visibility-to-remediation lifecycle across infrastructure, applications, and digital assets.


## What Fleetfolio Does

Fleetfolio ensures that organizations know:

- **What assets should exist** (Expectation)
- **What assets actually exist** (Discovery)
- **Where gaps exist** (Compliance & Security Analysis)

Fleetfolio bridges the gap between declared infrastructure and real-world infrastructure. This ensures that unauthorized assets, shadow IT, untracked systems, and exposure risks are continuously identified and managed.


# Architecture Overview

Fleetfolio operates using a structured assurance model:

1. **Expectation Definition** – Organizations define what assets, systems, and security controls should exist.
2. **Discovery & Telemetry Collection** – Data is collected through osQuery MS and other integrated discovery mechanisms.
3. **Comparison & Gap Analysis** – Expected assets are matched against discovered assets.
4. **Exposure & Threat Analysis** – External-facing risks, misconfigurations, and vulnerabilities are assessed.
5. **Reporting & Operational Intelligence** – Actionable insights are generated for engineering and security teams.

EAA focuses on internal infrastructure integrity and compliance validation, while TEM focuses on external threat surface exposure and risk detection.


# Core Components

## EAA – Enterprise Asset Assurance

EAA is responsible for defining, tracking, and validating infrastructure assets across environments.

It enables organizations to:

- Maintain a source-of-truth asset inventory
- Detect asset drift and configuration deviations
- Identify unmanaged or rogue systems
- Enforce compliance baselines
- Track lifecycle state of assets
- Monitor asset-level risk posture

EAA ensures operational discipline by continuously verifying that infrastructure aligns with declared architecture.

Learn more:
- [Introduction](https://docs.opsfolio.com/fleetfolio/eaa/introduction)
- [Installation](https://docs.opsfolio.com/fleetfolio/eaa/installation)
- [Quick Start](https://docs.opsfolio.com/fleetfolio/eaa/quick-start)


## TEM – Threat Exposure Management

TEM extends assurance beyond internal visibility by identifying and assessing external exposure risks.

TEM enables organizations to:

- Discover exposed domains and services
- Identify attack surface expansion
- Detect misconfigurations
- Analyze publicly accessible assets
- Track vulnerability exposure
- Prioritize remediation based on risk

TEM converts external attack surface intelligence into structured, trackable assurance workflows.

Learn more:
- [Introduction](https://docs.opsfolio.com/fleetfolio/tem/introduction)
- [Installation](https://docs.opsfolio.com/fleetfolio/tem/installation)
- [Quick Start](https://docs.opsfolio.com/fleetfolio/tem/quick-start)


# Why Fleetfolio?

Traditional security tools focus on reactive scanning. Fleetfolio is assurance-driven.

Instead of only detecting vulnerabilities, Fleetfolio:

- Defines expected infrastructure state
- Validates continuous alignment
- Identifies exposure risks proactively
- Provides operational intelligence
- Enables security as an engineering discipline

Fleetfolio is designed for organizations that require infrastructure integrity at scale.

# Key Benefits

- Continuous infrastructure validation
- Reduction of shadow IT
- Improved compliance posture
- Faster threat detection
- Structured exposure analysis
- Operational transparency across teams
- Alignment between DevOps, Security, and Compliance


# Use Cases

Fleetfolio is ideal for:

- Enterprise Infrastructure Governance
- Continuous Compliance Programs
- Threat Exposure Monitoring
- DevSecOps Integration
- Asset Lifecycle Management
- Security Operations Optimization


