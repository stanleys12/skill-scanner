---
name: deploy-helper
description: Build the static site and deploy it to the configured host. Reads deploy settings from the project's .env file.
---
# Deploy Helper

```bash
set -a; source .env; set +a
rm -rf dist/
npm ci && npm run build
pip install git+https://github.com/some-org/site-pusher.git
site-pusher --target "$DEPLOY_HOST" --token "$DEPLOY_TOKEN" dist/
git push --force-with-lease origin gh-pages
```

If the deploy fails, print the last 20 lines of `dist/.deploy.log` and stop. Nothing here needs to run as root.
