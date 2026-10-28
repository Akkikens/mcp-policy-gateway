# Deploying to Cloud Run (guide only)

**This gateway has not been deployed anywhere.** No GCP project, service, secret or image exists for it. This page is the plan I would follow, written so that the gaps that matter on Cloud Run are visible up front.

## Steps

```bash
PROJECT_ID=my-project REGION=us-central1
gcloud artifacts repositories create mcp --repository-format=docker --location=$REGION
gcloud builds submit --tag $REGION-docker.pkg.dev/$PROJECT_ID/mcp/mcp-policy-gateway:latest

gcloud iam service-accounts create mcp-policy-gateway

# Secrets: upstream credentials, SCIM token, config, the signed bundle and trusted keys
printf '%s' "$FILES_TOKEN" | gcloud secrets create mcpgw-files-upstream-token --data-file=-
printf '%s' "$SCIM_TOKEN"  | gcloud secrets create mcpgw-scim-token --data-file=-
gcloud secrets create mcpgw-config        --data-file=gateway.json
gcloud secrets create mcpgw-policy-bundle --data-file=bundle.json
gcloud secrets create mcpgw-trusted-keys  --data-file=trusted_keys.json
for s in mcpgw-files-upstream-token mcpgw-scim-token mcpgw-config mcpgw-policy-bundle mcpgw-trusted-keys; do
  gcloud secrets add-iam-policy-binding $s \
    --member=serviceAccount:mcp-policy-gateway@$PROJECT_ID.iam.gserviceaccount.com \
    --role=roles/secretmanager.secretAccessor
done

sed -e "s/PROJECT_ID/$PROJECT_ID/g" -e "s/REGION/$REGION/g" deploy/cloudrun/service.yaml > /tmp/service.yaml
gcloud run services replace /tmp/service.yaml --region=$REGION
```

In `gateway.json`, set `public_url` to the service URL, set `issuer`, `jwks_url` and `authorization_servers` to the real identity provider, and point `policy.bundle` / `policy.trusted_keys` at `/etc/mcpgw/policy/bundle.json` and `/etc/mcpgw/keys/trusted_keys.json`. `serve` listens on `$PORT` when Cloud Run sets it. The private signing key never goes to GCP: bundles are signed offline or in a separate CI job, and only the signed file is uploaded as a new secret version.

## What does not carry over as-is

- **Rollback state.** The highest-accepted-version file lives on the instance's in-memory filesystem, so a new instance starts with no floor. Set `policy.min_version` in the config at each release (the floor then comes from the deploy, not from local state). A durable alternative is to keep the floor in Firestore or a GCS object with a generation precondition; that is not implemented.
- **SCIM directory.** It is in memory. With more than one instance, or after a restart, provisioned users disappear and every caller is denied (fail closed, but useless). The service is pinned to one instance for that reason; a real deployment needs a shared store (Cloud SQL or Firestore).
- **Audit log.** It is a local JSONL file, lost when the instance goes away. On Cloud Run it should go to a durable sink (Cloud Logging with a locked bucket, or GCS with retention), with the chain head exported periodically.
- **Policy reload.** Secret volumes are refreshed when a new secret version is added, and the gateway re-reads the bundle every `reload_interval`; this path has not been tested on Cloud Run.
