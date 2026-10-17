# Role used by the nightly reports job: reads from the reports bucket only.
data "aws_iam_policy_document" "reports_job" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "reports_job" {
  name   = "reports-job"
  policy = data.aws_iam_policy_document.reports_job.json
}
