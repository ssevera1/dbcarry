# Autopilot playbook

Runs remaining phases back to back, stopping only at gates and
failures. Autopilot is the same pipeline, not a different one: each
phase executes ITS OWN playbook file, unmodified, including its
verification steps. Gates are presented exactly as the phase playbook
specifies; autonomy never skips or pre-answers a gate.

1. `state verify`; on failure report and stop.
2. Loop:
   a. `state show`; find the first phase not complete.
   b. No such phase -> report the migration complete and stop.
   c. If the phase is blocked by an unapproved gate, the owning
      playbook (plan or cutover) presents it as part of its normal
      flow; a decline stops the loop with a summary of what was
      declined and why.
   d. Read references/phase-<name>.md (map: migrate_schema ->
      phase-schema.md, migrate_data -> phase-data.md, others ->
      phase-<name>.md) and execute it fully.
   e. Phase failed -> stop. Report: the phase, the reason recorded in
      the decision log, the artifact to inspect, and the exact command
      to resume after fixing (the phase's own command; autopilot may
      also be re-run and will pick up from the same spot).
3. Long-running steps (data moves, wait-synced) run with background
   execution and polling rather than blocking timeouts.
4. After each completed phase, print a one-line progress summary so
   the transcript reads as a pipeline log.
