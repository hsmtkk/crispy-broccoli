REM gcloud iam service-accounts create cloud-runner
gcloud projects add-iam-policy-binding crispy-broccoli-382122 --member=serviceAccount:cloud-runner@crispy-broccoli-382122.iam.gserviceaccount.com --role=roles/secretmanager.secretAccessor
