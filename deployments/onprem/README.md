# On-prem deployment for fund-private mpcd

For funds that cannot use a public cloud. The deployment shape is the
same as the cloud variants: a 3- or 5-replica StatefulSet, a hardware
WORM volume for the audit log, an HSM provider for ZapDB password
unwrap.

## Required components

1. **Kubernetes cluster** — any conformant distribution. Tested with
   k3s 1.30+, vanilla 1.30+, OpenShift 4.16+. The cluster must support
   PersistentVolumes, NetworkPolicies, and Pod Security Admission at
   `restricted` level.
2. **WORM storage class** — the StatefulSet's `volumeClaimTemplates`
   request a storage class named `worm-block-storage`. Operators map
   this to NetApp SnapLock, Dell ECS retention, or a tape-backed CIFS
   mount. The mpcd daemon does not enforce immutability — the storage
   layer must.
3. **HSM** — PKCS#11-accessible. YubiHSM, SafeNet Luna, Thales Crypto
   Command Center, or a software HSM (SoftHSM2) for non-prod. Set
   `MPC_HSM_PROVIDER=pkcs11` in the StatefulSet and mount the PKCS#11
   bridge as a sidecar at `app=fund-hsm-bridge`.
4. **Identity provider** — for the dashboard's JWT issuer. Hanzo IAM
   if the fund is a Lux customer; the fund's existing OIDC IdP if not.
5. **Time source** — operators must point all nodes at chrony or PTP.
   The audit log timestamps drive compliance attestations; clock skew
   between nodes corrupts the chain order across replicas.

## Deployment steps

```bash
# 1. Apply the Kustomize overlay against the cluster
kubectl apply -k ../k8s-private/

# 2. Populate mpc-secrets via the fund's KMS pipeline
kubectl create secret generic mpc-secrets -n fund-mpc \
  --from-literal=hsm-provider=pkcs11 \
  --from-literal=hsm-key-id=path-to-key \
  --from-literal=hsm-signer=local \
  --from-literal=jwt-secret=$(openssl rand -hex 32) \
  --from-literal=internal-api-key=$(openssl rand -hex 32) \
  --dry-run=client -o yaml | kubectl apply -f -

# 3. Wait for all 3 nodes to become Ready
kubectl rollout status -n fund-mpc statefulset/mpc-node

# 4. Run the key ceremony (see runbook §5)
mpc-key-ceremony --threshold 2 --participants node-0,node-1,node-2

# 5. Sign your first transaction (see runbook §6)
```

See the LaTeX runbook in `papers/lux-private-mpc-deployment/` for the
full operational procedures.
