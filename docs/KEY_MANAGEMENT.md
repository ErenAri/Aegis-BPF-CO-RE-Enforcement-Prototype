# Key Management Runbook

This runbook defines how to rotate and revoke policy-signing keys used by
AegisBPF signed policy bundles.

## Model

- Trusted public keys are loaded from `/etc/aegisbpf/keys` (or
  `AEGIS_KEYS_DIR` in tests/dev).
- Policy bundles include a monotonic `policy_version`.
- Anti-rollback enforcement uses `/var/lib/aegisbpf/version_counter` (or
  `AEGIS_VERSION_COUNTER_PATH` in tests/dev).

## Rotate signing keys

1. Generate a new Ed25519 keypair **offline** and store the private key in a
   secure signer/HSM.
2. Distribute the new public key to each host:
   ```bash
   sudo aegisbpf keys add /path/to/new-key.pub
   ```
3. Sign the next policy with the new private key.
4. Apply with signature enforcement:
   ```bash
   sudo aegisbpf policy apply /path/to/policy.signed --require-signature
   ```
5. Verify the fleet accepts signed bundles with the new key.
6. Remove the old public key from `/etc/aegisbpf/keys/` after cutover.

## Revoke a compromised key

1. Remove compromised key files from `/etc/aegisbpf/keys/` on all hosts.
2. Apply an emergency policy bundle signed by a non-compromised key.
3. Verify anti-rollback remains monotonic:
   - New bundle version must be greater than the current version counter.
4. Audit recent policy apply events and key changes in SIEM.

## External signer (KMS/HSM) workflow

For environments where private keys must stay inside KMS/HSM:

1. Implement a signer command that reads a payload from stdin and outputs a
   128-char Ed25519 signature hex string.
2. Generate signed bundles via:
   ```bash
   scripts/sign_policy_external.sh \
     --policy /etc/aegisbpf/policy.conf \
     --public-key /etc/aegisbpf/keys/signer.pub \
     --output /tmp/policy.signed \
     --sign-command 'your-kms-sign-wrapper'
   ```
3. Deploy with signature enforcement:
   ```bash
   sudo aegisbpf policy apply /tmp/policy.signed --require-signature
   ```

## Backup and restore

Back up and protect:

- `/etc/aegisbpf/keys/`
- `/var/lib/aegisbpf/version_counter`
- `/var/lib/aegisbpf/policy.applied*`

After restore, run:

```bash
sudo aegisbpf health --json
```

and verify signed policy apply succeeds.

## Operational cadence

- Rotate signing keys at least every 90 days.
- Run a revocation drill at least once per quarter.
- Require two-person review for key rollout/revocation changes.
