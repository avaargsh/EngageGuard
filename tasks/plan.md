# EngageGuard Implementation Plan

1. Freeze ActionEnvelope, CanonicalAction, ActionHash, Permit, Receipt and Operation state machine.
2. Implement Go API and PostgreSQL transaction schema.
3. Implement auth context verification and deterministic deny-by-default policy.
4. Implement approval bound to ActionHash.
5. Implement one-time Permit claim under concurrency.
6. Implement isolated Workspace Executor with root confinement and symlink-race tests.
7. Implement Operation Journal and UNKNOWN reconciliation.
8. Add adversarial and crash-window integration tests.

Exit gate: no authorization/no execution; one Permit cannot be consumed twice; modified approved action is denied; ambiguous side effects never blindly replay.
