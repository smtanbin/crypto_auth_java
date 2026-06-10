# Publish to Maven Central

## 1) Update project coordinates
Edit `pom.xml` and verify:
- `groupId` matches your verified namespace in Sonatype Central.
- `artifactId` is final.
- `version` is a release version (for example `1.0.0`, not `-SNAPSHOT`).
- `url`, `scm`, `developers`, and license metadata are correct.

## 2) Configure Central credentials
Use `%USERPROFILE%\\.m2\\settings.xml` with server id `central`:

```xml
<settings>
  <servers>
    <server>
      <id>central</id>
      <username>${env.CENTRAL_USERNAME}</username>
      <password>${env.CENTRAL_TOKEN}</password>
    </server>
  </servers>
</settings>
```

In PowerShell:

```powershell
$env:CENTRAL_USERNAME = "<your-central-username>"
$env:CENTRAL_TOKEN = "<your-central-token>"
```

## 3) Configure GPG signing
Generate a key (once):

```powershell
gpg --full-generate-key
gpg --list-secret-keys --keyid-format LONG
```

Use one of these approaches:
- GPG agent prompt during `mvn -P release ...`
- Or configure Maven GPG passphrase securely via environment variable.

## 4) Build and publish

```powershell
mvn -P release clean verify central:publish
```

The `release` profile in `pom.xml` already attaches:
- sources jar
- javadoc jar
- GPG signatures
- Sonatype Central publisher plugin

## 5) Verify release
- Check your publication in Sonatype Central UI.
- Confirm artifact appears in Maven Central search/index.

## Notes
If you have not installed Maven yet on Windows, install Apache Maven and ensure `mvn -v` works in a new terminal.
