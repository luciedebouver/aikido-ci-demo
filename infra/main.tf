# IaC scanning: publicly readable S3 bucket
resource "aws_s3_bucket" "uploads" {
  bucket = "aikido-ci-demo-uploads"
  acl    = "public-read"
}
