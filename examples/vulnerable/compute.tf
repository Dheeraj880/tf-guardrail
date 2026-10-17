resource "aws_instance" "bastion" {
  ami                    = "ami-0abcdef1234567890"
  instance_type          = "t3.micro"
  subnet_id              = var.app_subnet_ids[0]
  vpc_security_group_ids = [aws_security_group.bastion.id]

  tags = {
    Name = "bastion"
  }
}

resource "aws_cloudtrail" "main" {
  name                       = "org-trail"
  s3_bucket_name             = aws_s3_bucket.logs.id
  is_multi_region_trail      = true
  enable_log_file_validation = false
}
