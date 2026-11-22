# Static Audit Test Fixtures (DO NOT DEPLOY)

These minimal, non-executable snippets are excluded from the container image (`.dockerignore`) and exist solely to validate that the AIOps Security Auditor detects multi-ecosystem open-source vulnerability classes:

- **PHP (`php2shell` class)**: Untrusted `unserialize()`, dynamic `include()`, OS command sink, outdated Composer dependencies.
- **Node.js (`node2shell` / React2Shell / RSC class)**: Untrusted `child_process.exec()`, `vm.runInNewContext()`, unsafe prototype merge, vulnerable `package.json` (Next.js / React / Lodash / suspicious `postinstall`).
- **Java (`java4shell` / Log4Shell / Spring4Shell class)**: JNDI `InitialContext.lookup()`, `ObjectInputStream.readObject()`, SpEL `parseExpression()`, vulnerable `pom.xml`.
- **Python**: `yaml.load()` without SafeLoader, `pickle.loads()`, `subprocess.run(..., shell=True)`.
- **IaC**: Open `0.0.0.0/0` SSH security group and unencrypted EBS volume.

