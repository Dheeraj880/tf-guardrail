variable "vpc_id" {
  type        = string
  description = "VPC the app runs in"
}

variable "app_subnet_ids" {
  type = list(string)
}
