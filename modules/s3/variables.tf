variable "project_name" {
  description = "Name of the project (used for resource naming)"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

# Single bucket configuration (legacy support)
variable "bucket_name" {
  description = "Name of the S3 bucket (will be prefixed with project and environment)"
  type        = string
  default     = "assets"
}

# Multiple buckets configuration
variable "buckets" {
  description = "List of S3 bucket configurations"
  type = list(object({
    name                 = string
    enable_versioning    = optional(bool, true)
    block_public_access  = optional(bool, true)
    enable_cloudfront   = optional(bool, true)
    default_root_object = optional(string, "index.html")
    price_class         = optional(string, "PriceClass_100")
  }))
  default = []
}

variable "bucket_names" {
  description = "Simple list of S3 bucket names"
  type        = list(string)
  default     = []
}

variable "environment_buckets" {
  description = "Environment-specific bucket configurations"
  type = map(object({
    bucket_names = list(string)
    enable_cloudfront = optional(bool, true)
    enable_versioning = optional(bool, true)
    block_public_access = optional(bool, true)
  }))
  default = {}
}

# Global settings for all buckets
variable "enable_versioning" {
  description = "Enable S3 bucket versioning (for single bucket)"
  type        = bool
  default     = true
}

variable "block_public_access" {
  description = "Block public access to S3 bucket (for single bucket)"
  type        = bool
  default     = true
}

variable "default_root_object" {
  description = "Default root object for CloudFront distribution (for single bucket)"
  type        = string
  default     = "index.html"
}

variable "price_class" {
  description = "CloudFront price class (for single bucket)"
  type        = string
  default     = "PriceClass_100"
  validation {
    condition = contains([
      "PriceClass_All",
      "PriceClass_200", 
      "PriceClass_100"
    ], var.price_class)
    error_message = "Price class must be one of: PriceClass_All, PriceClass_200, PriceClass_100."
  }
}
