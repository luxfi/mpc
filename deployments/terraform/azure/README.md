# Azure deployment for fund-private mpcd

Counterpart to `../aws/`. Same contract, Azure flavour.

## Plan status

`terraform plan` succeeds for `main.tf` against azurerm provider 4.x.
AKS + Azure Key Vault Managed HSM modules are stubbed (TODO).

## Notes

- Audit storage uses ZRS to survive a single-zone outage; the fund's
  compliance regime may require GZRS instead.
- Azure Immutable Blob Storage policies are append-only once locked.
- Use Premium tier for audit if write QPS exceeds the Standard cap.
