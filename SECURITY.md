# Security Policy

## Supported versions

This project is under active development. Only the latest version on the `main` branch receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report vulnerabilities privately through GitHub: go to the **Security** tab of this repository and click **Report a vulnerability**. Include a description of the issue, steps to reproduce it and its potential impact.

You can expect an initial response within 7 days. Once the issue is confirmed and fixed, you will be credited in the release notes unless you prefer to remain anonymous.

## Scope

In scope:

- Vulnerabilities in the ingestion, enrichment, classification or reporting code.
- Weaknesses in the deployment configuration that could expose the homelab or allow the sensor to be used against third parties.
- Prompt injection issues that could make the LLM pipeline produce misleading results or leak data.

Out of scope:

- The honeypot being reachable and appearing vulnerable: this is intentional.
- Vulnerabilities in third-party projects such as Cowrie; please report those to their maintainers.

## Responsible use

This project is intended for defensive security research and education. Captured data may contain personal data (such as IP addresses) and malicious files; it must be handled responsibly and never used to attack others.
