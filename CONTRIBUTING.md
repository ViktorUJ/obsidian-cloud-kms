# Contributing

Thank you for your interest in contributing to Obsidian Cloud KMS Encryption!

## Development Setup

```bash
git clone https://github.com/ViktorUJ/obsidian-cloud-kms.git
cd obsidian-cloud-kms
npm install
npm test
npm run build
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run tests: `npm test`
5. Run linter: `npx eslint src/ tests/`
6. Run typecheck: `npx tsc --noEmit`
7. Commit with a descriptive message
8. Push and create a Pull Request

## Code Style

- TypeScript strict mode
- ESLint with no warnings
- No `console.log` in production code (use structured logger)
- No sensitive data in error messages or logs

## Security

- Never store credentials in code or settings
- Always zero DEK buffers after use
- Never write plaintext to disk
- Report vulnerabilities privately (see [SECURITY.md](SECURITY.md))

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
