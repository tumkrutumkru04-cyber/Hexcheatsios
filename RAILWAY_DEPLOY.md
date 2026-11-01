# Deploy CUBAN PROXY API on Railway

## Files to upload to GitHub

Upload:

```text
app.py
requirements.txt
Procfile
```

Do **not** upload the private key or `licenses.db`.

## Railway steps

1. Create a new Railway project.
2. Choose **Deploy from GitHub repo**.
3. Select the repository containing these files.
4. Open the service's **Variables** tab.
5. Add this variable:

```text
LICENSE_PRIVATE_KEY_PEM
```

Paste the complete contents of `cuban-new-license-private-key.pem` as the value, including:

```text
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
```

6. Deploy/redeploy the service.
7. Generate a Railway public domain in **Settings → Networking → Generate Domain**.
8. Test:

```text
https://YOUR-RAILWAY-DOMAIN/api/health
```

It should return `ok: true`.

## Important APK URL step

The current working APK points to the temporary `trycloudflare.com` URL. After Railway gives you a permanent domain, the APK must be rebuilt again with:

```text
https://YOUR-RAILWAY-DOMAIN/api/lic/activate
```

Do not put the private key in GitHub, screenshots, or public messages. If it is exposed, generate a new keypair and rebuild the APK.
