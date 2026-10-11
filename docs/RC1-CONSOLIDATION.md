# RC1 consolidation status (2026-10-08)

## Verified by user on Rocky Linux 10

- TCP/UDP local forwarding, existing parser tests, 20 and 100 repeated SIGHUP cycles
- Select wakeup fix using the diagnostic 100 ms timeout

## Added in this bundle

- Stronger test requiring UDP destination to **change** after SIGHUP
- Unified acceptance runner; errors if compiled executable is missing
- Retained original compiler overlay as the working baseline

## Blocking the 1.0 release

- Transactional configuration parsing/commit/rollback is **not yet implemented**.
- Safe preservation of established TCP connections during configuration changes is not yet demonstrated.
- self-pipe/eventfd wakeup is not yet implemented; 100ms workaround remains.
- Real builds of RPMs and verification on Rocky 8 and 9 are outstanding.
- ASan/UBSan and systematic memory safety review are outstanding.

Do not describe this as release candidate approved for production. Run acceptance
on Rocky 10, then repeat on Rocky 8 and 9 with binaries compiled on each OS.

Never copy the generated binary over an existing production install without
an explicit deployment decision and a backup of the existing executable.
