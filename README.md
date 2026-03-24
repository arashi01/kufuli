# kufuli

Cross-platform Scala 3 cryptographic library.

## Modules

| Module | Platforms | Description |
|--------|-----------|-------------|
| `kufuli-core` | JVM, JS, Native | Pure ADTs, algorithm models, security primitives |
| `kufuli-js-shared` | JS | Shared JS utilities for Node.js and browser backends |
| `kufuli-zio` | JVM, JS, Native | ZIO typeclass traits and platform-specific backends |
| `kufuli-zio-browser` | JS | Web Crypto (SubtleCrypto) backend |
| `kufuli-testkit` | JVM, JS, Native | RFC test vectors and abstract test suites |

## License

MIT
