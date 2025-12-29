# AWS deployment for fund-private mpcd

This directory holds Terraform that provisions the AWS infrastructure a
fund needs to run a private mpcd cluster.

The contract is documented in
`papers/lux-private-mpc-deployment/lux-private-mpc-deployment.tex`.

## Layout

- `main.tf` — VPC + S3 audit bucket with Object Lock. Plan-pass.
- `eks.tf` — EKS cluster (TODO: not yet plan-tested).
- `cloudhsm.tf` — CloudHSM cluster (TODO: not yet plan-tested).
- `secrets.tf` — Secrets Manager entries (TODO: not yet plan-tested).

## Plan status

`terraform plan` succeeds for `main.tf` against AWS provider 5.x with a
local backend. EKS and CloudHSM modules are stubbed with the intended
contract but not yet deployed in any region — the runbook walks through
applying them by hand for the first deployment.

## What this module does NOT do

- Provision the kustomize overlay at `deployments/k8s-private/`. That
  is a separate `kubectl apply -k` step driven by the fund's CD
  pipeline.
- Generate or rotate secrets. The fund's KMS pipeline owns that.
- Bootstrap the cluster's first key ceremony. That is a manual
  multi-party operation; see the runbook section "Key ceremony".
