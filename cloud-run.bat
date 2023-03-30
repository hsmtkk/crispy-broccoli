call gcloud builds submit
call gcloud run deploy app ^
--allow-unauthenticated ^
--execution-environment=gen2 ^
--image=us-central1-docker.pkg.dev/crispy-broccoli-382122/registry/app:latest ^
--min-instances=0 ^
--max-instances=1 ^
--region=us-central1 ^
--service-account=cloud-runner@crispy-broccoli-382122.iam.gserviceaccount.com ^
--set-secrets=LWA_CLIENT_ID=lwa-client-id:1 ^
--set-secrets=LWA_CLIENT_SECRET=lwa-client-secret:1 ^
