resource "google_service_account" "app" {
  account_id   = "ss-app"
  display_name = "secrets-sprawl runtime"
}
resource "google_project_iam_member" "app_vertex" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.app.email}"
}
resource "google_project_iam_member" "app_logs_write" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.app.email}"
}
# Read-only sources the scanner needs. These are broad reads by nature (that is what a secrets scan is),
# so the service is private and each source is limited by an allow-list in the app.
resource "google_project_iam_member" "app_run_viewer" {
  project = var.project_id
  role    = "roles/run.viewer"
  member  = "serviceAccount:${google_service_account.app.email}"
}
resource "google_project_iam_member" "app_log_viewer" {
  project = var.project_id
  role    = "roles/logging.viewer"
  member  = "serviceAccount:${google_service_account.app.email}"
}
resource "google_project_iam_member" "app_compute_viewer" {
  project = var.project_id
  role    = "roles/compute.viewer"
  member  = "serviceAccount:${google_service_account.app.email}"
}
# Needed to read IAM policies (who can read a source, what a leaked key's account can do) and to ask whether a leaked key is still active.
resource "google_project_iam_member" "app_security_reviewer" {
  project = var.project_id
  role    = "roles/iam.securityReviewer"
  member  = "serviceAccount:${google_service_account.app.email}"
}

# --- canary: FAKE credentials planted in real places so the scanner can be checked against ground truth ---
resource "google_storage_bucket" "canary" {
  name                        = "${var.project_id}-ss-canary"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true
  labels                      = { env = "demo", owner = "platform" }
}
# Only this bucket is readable by the scanner: bucket-level, not project-wide.
resource "google_storage_bucket_iam_member" "app_reads_canary" {
  bucket = google_storage_bucket.canary.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.app.email}"
}
resource "google_storage_bucket_object" "canary_env" {
  name         = "config/app.env"
  bucket       = google_storage_bucket.canary.name
  content_type = "text/plain"
  content      = <<-EOT
    # FAKE credentials for scanner validation. None of these is live.
    APP_NAME=orders
    DATABASE_URL=postgres://orders_app:Zq8!vT3mK9xLw2Rp@10.20.0.5:5432/orders
    STRIPE_SECRET=sk_live_${""}4eC39HqLyjWDarjtT1zdp7dc
    AWS_ACCESS_KEY_ID=AKIAQWERTYUIOPASDFGH
    DEBUG=false
  EOT
}
resource "google_storage_bucket_object" "canary_notes" {
  name         = "docs/README.md"
  bucket       = google_storage_bucket.canary.name
  content_type = "text/markdown"
  content      = <<-EOT
    # Setup notes (benign: placeholders and documentation only)
    Set `API_KEY=$${API_KEY}` before starting. Example AWS key from the docs: AKIAIOSFODNN7EXAMPLE
    password: <your-password-here>
    The checksum is 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
  EOT
}

resource "google_cloud_run_v2_service" "canary" {
  count               = var.image != "" ? 1 : 0
  name                = "ss-canary"
  location            = var.region
  deletion_protection = false
  labels              = { env = "demo", owner = "platform" }
  template {
    service_account = google_service_account.app.email
    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }
    containers {
      image = var.image
      resources {
        limits = { cpu = "1", memory = "512Mi" }
      }
      # FAKE values, planted for validation
      env {
        name  = "GITHUB_TOKEN"
        value = "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
      }
      env {
        name  = "REDIS_URL"
        value = "redis://default:Hq7!pX2vN8cMz4Ld@10.20.0.9:6379"
      }
      env {
        name  = "LOG_LEVEL"
        value = "debug"
      }
      env {
        name  = "REGION"
        value = "us-central1"
      }
    }
  }
}

resource "google_cloud_run_v2_service" "app" {
  count               = var.image != "" ? 1 : 0
  name                = "secrets-sprawl"
  location            = var.region
  deletion_protection = false
  labels              = { env = "demo", owner = "platform" }
  template {
    service_account                  = google_service_account.app.email
    timeout                          = "120s"
    max_instance_request_concurrency = 10
    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }
    containers {
      image = var.image
      resources {
        limits = { cpu = "1", memory = "512Mi" }
      }
      startup_probe {
        http_get { path = "/healthz" }
      }
      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      env {
        name  = "SPRAWL_LLM"
        value = "vertex"
      }
      env {
        name  = "SPRAWL_ALLOWED_PROVIDERS"
        value = "vertex,none"
      }
      env {
        name  = "SPRAWL_PROJECTS"
        value = var.project_id
      }
      env {
        name  = "SPRAWL_BUCKETS"
        value = google_storage_bucket.canary.name
      }
    }
  }
  depends_on = [
    google_project_iam_member.app_vertex,
    google_project_iam_member.app_run_viewer,
    google_project_iam_member.app_log_viewer,
    google_project_iam_member.app_security_reviewer,
  ]
}

# Private: only the admin may invoke. No allUsers binding.
resource "google_cloud_run_v2_service_iam_member" "admin_invoker" {
  count    = var.image != "" ? 1 : 0
  name     = google_cloud_run_v2_service.app[0].name
  location = var.region
  role     = "roles/run.invoker"
  member   = "user:${var.admin_email}"
}
