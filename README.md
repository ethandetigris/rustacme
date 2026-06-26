# rustacme

`rustacme` is a small Docker-friendly ACME DNS-01 renewer for domains managed by the West.cn DNS API.

It stores certificates under `/certs/<first-domain>/`:

- `fullchain.pem`
- `privkey.pem`
- `account.json`

## Usage

```bash
cp .env.example .env
chmod 600 .env
mkdir -p certs
chmod 700 certs
docker compose up -d
```

Set `RUSTACME_IMAGE` when using a published image:

```bash
RUSTACME_IMAGE=ghcr.io/ethandetigris/rustacme:latest docker compose up -d
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
