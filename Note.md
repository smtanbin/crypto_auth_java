# Maven Central Publish Notes

## What to store securely

For future publishes, keep these values safe and do not commit them into git:

- `CENTRAL_USERNAME`
- `CENTRAL_TOKEN`
- `GPG_PRIVATE_KEY`
- `GPG_KEY_ID`
- `GPG_PASSPHRASE` (only if your GPG key has a passphrase)

## Local files and ignored items

These files should remain local and should not be committed:

- `.mvn/settings.xml`
- `gpg-private-key.asc`
- any local GPG keyring files created for publish testing

The repository already ignores `.mvn/settings.xml` and `gpg-private-key.asc`.

## GitHub Actions publish

The workflow file is:

- `.github/workflows/publish-maven-central.yml`

It publishes automatically when you push a version tag matching `v*.*.*`.

### Required GitHub secrets

- `CENTRAL_USERNAME`
- `CENTRAL_TOKEN`
- `GPG_PRIVATE_KEY`
- `GPG_KEY_ID`

## Local CLI publish

If you publish locally, use:

```powershell
cd E:\Codes\crypto_auth
$env:GNUPGHOME = '/E/Codes/crypto_auth/gpg-temp'
$env:PATH = 'C:\Program Files\Git\usr\bin;' + $env:PATH
.\apache-maven-3.9.9\bin\mvn.cmd -s .mvn\settings.xml -B -ntp -Prelease clean verify org.sonatype.central:central-publishing-maven-plugin:0.6.0:publish
```

If you do not use the temporary `gpg-temp` home, ensure your normal GPG key is available and the public key has been published to a supported keyserver (for example `hkps://keys.openpgp.org`).

## Important notes

- `CENTRAL_TOKEN` is generated from Sonatype Central user tokens.
- `GPG_PRIVATE_KEY` must be the ASCII-armored private key block.
- `GPG_KEY_ID` is the long key ID of the signing key.
- Public key must be published to an active keyserver before Sonatype accepts signatures.
- Use `Note.md` to record any new token/secret values locally, not in git.
