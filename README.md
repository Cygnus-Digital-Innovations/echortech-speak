# EchorTech Speak

Anonymous, end-to-end encrypted messaging between EchorTech employees. Messages are encrypted in the sender's browser, so the server only ever stores scrambled data.

## Develop

```bash
npm install
npm test
npm run build
npm start   # http://127.0.0.1:3000
```

Requires Node 24 or newer.

## Add a person

1. They open `/setup`, create their keys and save their key file.
2. They send an admin their listing line.
3. Add it to `config/directory.json` with the next unused `keyId`:

   ```json
   [{ "keyId": 1, "name": "Their name", "publicKey": "...", "status": "active" }]
   ```

4. Redeploy. Public keys are built into the send page so a database compromise can't swap them.

To remove someone, set their `status` to `retired` and redeploy. Never delete a listed key, because their existing threads depend on it.

## Deploy

```bash
./deploy/deploy.sh
```

The app runs as a Docker container on the shared server, bound to `127.0.0.1:3200`, behind `deploy/nginx-speak.conf`. Keep nginx access logging off for this site, because it would record the IP addresses of anonymous senders.

The database is in the `echortech-speak-data` Docker volume.
