# rustacme

`rustacme` is a small Docker-friendly ACME DNS-01 renewer for domains managed by the West.cn DNS API.

It stores certificates under `/certs/<first-domain>/`:

- `fullchain.pem`
- `privkey.pem`
- `account.json`

Issued certificate private keys are always generated as RSA 4096-bit PKCS#8 keys. CSRs are signed with RSA PKCS#1 v1.5 + SHA-512, the strongest RSA/SHA mode supported by the current `rcgen` version used by this project. The final certificate chain signature algorithm is selected by the ACME CA.

## Usage

```bash
cp .env.example .env
chmod 600 .env
mkdir -p certs
chmod 700 certs
docker compose up -d
```

The bundled Compose file uses Docker host networking.

Set `RUSTACME_IMAGE` when using a published image:

```bash
RUSTACME_IMAGE=ghcr.io/ethandetigris/rustacme:latest docker compose up -d
```

GitHub Actions and the default Docker build use the official crates.io sparse index. On mainland China hosts you can opt into the China Cargo mirror profile:

```bash
RUSTACME_CARGO_CONFIG=.cargo/config.china.toml ./build.sh
```

or:

```bash
docker build --build-arg CARGO_CONFIG=.cargo/config.china.toml -t rustacme:local .
```

## Configuration

```env
ACME_EMAIL=admin@example.com
CERT_1_DOMAINS=example.com,*.example.com
CERT_1_KEY=west-domain-api-key
```

Additional certificate groups can be added with `CERT_2_DOMAINS`, `CERT_2_KEY`, and so on.

Optional settings:

```env
RENEW_BEFORE_DAYS=30
CHECK_INTERVAL_SECS=43200
DNS_WAIT_SECS=90
ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory
```

Use Let's Encrypt staging while testing:

```env
ACME_DIRECTORY_URL=https://acme-staging-v02.api.letsencrypt.org/directory
```

## Security Notes

- Keep `.env` at mode `600`.
- Keep `certs/` private. The private keys and ACME account are stored there.
- DNS TXT cleanup only removes records that match the exact challenge value created by this process.

## License

Apache-2.0
