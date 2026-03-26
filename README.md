# Cloud Compliance Dashboard

[![Security Pipeline](https://github.com/Fmbravoglobal/cloud-compliance-dashboard/actions/workflows/security-pipeline.yml/badge.svg)](https://github.com/Fmbravoglobal/cloud-compliance-dashboard/actions)

## Overview

A real-time multi-cloud compliance scoring dashboard that evaluates cloud resources against four major security frameworks simultaneously: CIS Benchmarks, NIST 800-53, PCI-DSS, and SOC 2 Type II.

The platform provides per-framework compliance scores, identifies control gaps, and generates prioritized remediation guidance across AWS, GCP, and Azure resources.

## Architecture Components

- FastAPI compliance evaluation engine
- AWS DynamoDB (findings storage)
- AWS S3 (compliance reports archive, KMS-encrypted)
- AWS KMS (customer-managed encryption)
- Terraform Infrastructure as Code
- GitHub Actions CI/CD pipeline

## Compliance Frameworks

| Framework | Controls Evaluated |
|---|---|
| CIS AWS Benchmark | Encryption, access control, logging, MFA |
| NIST 800-53 Rev5 | SC-28, AC-3, AU-2, IA-5, SI-4 |
| PCI-DSS v3.2 | Req 3, 7, 8, 10 |
| SOC 2 Type II | CC6.1, CC6.6, CC6.7, A1.2 |

## Author

**Oluwafemi Alabi Okunlola** | Cloud Security Engineer
[oluwafemiokunlola308@gmail.com](mailto:oluwafemiokunlola308@gmail.com)
