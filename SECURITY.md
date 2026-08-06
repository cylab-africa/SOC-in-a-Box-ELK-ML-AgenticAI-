# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly:

1. **Do NOT** open a public GitHub issue for security vulnerabilities
2. Email the maintainers with details of the vulnerability
3. Include steps to reproduce the issue
4. Allow reasonable time for a fix before public disclosure

## Scope

This project is a security detection tool. Vulnerabilities in the detection pipeline, credential handling, or backend communication are in scope.

## Security Best Practices for Users

- Never commit `.env` files or credentials to version control
- Use API keys instead of username/password for Elasticsearch where possible
- Run the detection service with least-privilege OS accounts
- Enable TLS (`verify_certs: true`) for production Elasticsearch connections
- Regularly update dependencies: `pip install --upgrade -e ".[dev]"`
- Review `config/` files to ensure FP lists match your environment
