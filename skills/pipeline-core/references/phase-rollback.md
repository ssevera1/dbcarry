# Rollback playbook

Available from provision onward. Destroys the TARGET only; the source
is never touched except to revert pipeline-made changes (read-only
quiesce, publication, replication slot).

1. `state verify`; read state, migration.yaml, target.json.
2. Confirm with the user: list exactly what will be destroyed (target
   instance/resource from target.json) and what will be reverted on
   the source (only items the pipeline created: publication
   dbdrift_pub, its slot, the read-only setting if cutover set it).
   Require the user to TYPE the migration name (AskUserQuestion free
   text via Other, or ask in chat). A click is not enough. Abort on
   any other input.
3. Revert source-side pipeline artifacts, in this order:
   a. If a subscription exists on the target:
      `python "$SCRIPTS" replicate drop-subscription <target flags>
      --name dbdrift_sub`
   b. If publication exists on the source:
      `python "$SCRIPTS" replicate drop-publication <source flags>
      --name dbdrift_pub`
   c. If cutover had quiesced: SQL on source
      `ALTER DATABASE "<db>" RESET default_transaction_read_only`.
4. Tear down the target per the provider skill's Teardown section.
5. `state mark-rollback --reason <user's reason>`; append a summary of
   everything destroyed/reverted to the decision log via the command's
   own logging (mark-rollback already logs; add detail with a second
   decline-style note if needed by editing nothing: put the detail in
   the --reason string).
6. Report what was destroyed, what was reverted, and that the source
   is exactly as it was before the pipeline ran.
