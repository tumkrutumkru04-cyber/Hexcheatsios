# Standalone Railway deployment

This `app.py` contains the signing key internally, so no `LICENSE_PRIVATE_KEY_PEM` Railway variable is required.

## Important security warning

Do not upload this version of `app.py` to a public GitHub repository. Anyone who gets it can create valid license tokens. Use a private repository or deploy the file directly.

## Deploy

1. Replace the old `app.py` in your Railway GitHub repository with this one.
2. Commit and push.
3. Railway will redeploy automatically.
4. Test:

```text
https://hexchaets.up.railway.app/api/health
```

Then install `CUBAN-PROXY-v3-railway.apk`.

## Android crash fix

Uninstall every older CUBAN PROXY APK first, restart the phone, then install the new Railway APK. The rebuilt APK is signed with a new certificate, so it cannot update the old APK directly.

If it still crashes, capture the exact screen/time and Android version. A crash before the login screen and a crash after successful login have different causes.
