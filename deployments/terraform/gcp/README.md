# GCP deployment for fund-private mpcd

Counterpart to `../aws/`. Same contract, different cloud.

## Plan status

`terraform plan` succeeds for `main.tf` against google provider 5.x
with a local backend. GKE Autopilot + Cloud HSM modules are stubbed
in `gke.tf` and `cloudhsm.tf` (TODO) and not yet plan-tested.

## Notable differences from AWS

- GKE Autopilot is the recommended starting point — it lets the fund
  defer node management. Standard GKE is supported via a flag in
  `gke.tf` once that file lands.
- GCS retention policies are immutable once locked; pick the duration
  carefully. Default in `main.tf` is 7 years.
- Cloud HSM is region-bound; the fund's region selection determines
  HSM availability.
