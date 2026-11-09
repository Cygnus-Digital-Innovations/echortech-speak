# EchorTech Say It

Anonymous, end-to-end encrypted messaging between EchorTech employees. Messages are encrypted in the sender's browser, so the server only ever stores scrambled data.

## Develop

```bash
npm install
npm test
npm run build
INVITE_CODE=dev-code npm start   # http://127.0.0.1:3000
```

Requires Node 24 or newer.

## Add a person

People register themselves at `/setup` with the company invite code. Their browser creates their keys, and only the name and public key reach the server.

The invite code is the `INVITE_CODE` environment variable. On the server it's in `~/.sayit.env`. To change it, edit that file and redeploy.

To remove someone, or free up a name after a lost key, run:

```bash
sudo docker exec echortech-speak node src/admin.ts list
sudo docker exec echortech-speak node src/admin.ts revoke "Their name"
sudo docker restart echortech-speak
```

Public keys are served from the server, so someone who fully compromised it could swap a key and read future messages sent to that person. Past messages stay protected.

## Deploy

```bash
./deploy/deploy.sh
```

The app runs as a Docker container on the shared server, bound to `127.0.0.1:3200`, behind `deploy/nginx-sayit.conf`. Keep nginx access logging off for this site, because it would record the IP addresses of anonymous senders.

The database is in the `echortech-speak-data` Docker volume.
