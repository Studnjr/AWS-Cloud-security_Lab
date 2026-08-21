terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "aws" {
  region = var.aws_region

  # Every resource gets tagged. This is not security theatre: it is how you
  # find and destroy orphaned lab resources six weeks from now when you have
  # forgotten what you created.
  default_tags {
    tags = {
      Project     = var.project_name
      Environment = "lab"
      Owner       = var.lab_owner
      Warning     = "INTENTIONALLY-INSECURE-DO-NOT-USE"
      ManagedBy   = "terraform"
    }
  }
}

# S3 bucket names are globally unique across all AWS customers, so a fixed
# name will collide. Suffix with randomness.
resource "random_id" "suffix" {
  byte_length = 4
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

output "lab_summary" {
  value = {
    account_id        = data.aws_caller_identity.current.account_id
    region            = data.aws_region.current.name
    billable_enabled  = var.enable_billable_resources
    public_bucket     = aws_s3_bucket.customer_data.bucket
    public_bucket_url = "https://${aws_s3_bucket.customer_data.bucket}.s3.amazonaws.com/"
    reminder          = "Run 'terraform destroy' when finished."
  }
}
