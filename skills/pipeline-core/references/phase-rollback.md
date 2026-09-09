# Rollback playbook

Available from provision onward. Destroys the TARGET only; the source
is never touched except to revert pipeline-made changes (read-only
quiesce, publication, replication slot).

1. `state verify`; read state, migration.yaml, target.json.
2. Confirm with the user: list exactly what will be destroyed (target
   instance/resource from target.json; bigquery: the datasets and the
   taxonomy named there) and what will be reverted on the source (only
   items the pipeline created: publication dbdrift_pub, its slot, the
   read-only setting if cutover set it). Require the user to TYPE the
   migration name (AskUserQuestion free text via Other, or ask in
   chat). A click is not enough. Abort on any other input.

## Providers: local, gcp, aws, azure

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

## Provider: bigquery

3. Revert source-side pipeline artifacts: only the read-only quiesce,
   if cutover set it: SQL on source
   `ALTER DATABASE "<db>" RESET default_transaction_read_only`.
   bulk_load creates no publication and no slot.
4. Destroy exactly these resources and nothing else, per the Teardown
   section of ${CLAUDE_PLUGIN_ROOT}/skills/provider-bigquery/SKILL.md:
   - every dataset named under datasets in target.json (tables, views,
     row access policies, and the tag attachments go with them);
   - the taxonomy dbdrift_<migration>, by the full resource name
     recorded under taxonomy in artifacts/security-applied.json (when
     that file is missing, migrate_security never ran and there is no
     taxonomy), after the datasets: a tag still attached to a column
     blocks the delete.
   Emulated: `python "$SCRIPTS" bq-backend reset --migration <name>
   --yes` removes ~/.db-drift/bq-emulated/<name>/ (datasets, taxonomy,
   loaded rows) in one step; without --yes it prints the path and exits
   2, and it refuses any path that is not a direct child of
   bq-emulated.
   Live (NOT LIVE-TESTED): the skill's commands in its order:
   `bq --project_id=<project> rm -r -f -d <project>:<dataset>` per
   dataset, then the Data Catalog DELETE of the taxonomy resource name
   with a token the shell expands inside the Authorization header
   (never echoed, never written). The project-level
   roles/bigquery.jobUser bindings the plan added are left in place and
   listed; remove them only when the operator asks. Record each
   command's output.
   Staging copies hold every row in plain text: delete
   <workspace>/artifacts/export/ and, in live mode with gcs_bucket set,
   gs://<bucket>/db-drift/<name>/ (`gcloud storage rm -r`; NOT
   LIVE-TESTED).

## All providers

5. `state mark-rollback --reason <user's reason>`; append a summary of
   everything destroyed/reverted to the decision log via the command's
   own logging (mark-rollback already logs; add detail with a second
   decline-style note if needed by editing nothing: put the detail in
   the --reason string).
6. Report what was destroyed (bigquery: datasets, taxonomy, emulator
   directory or the live command outputs, staging copies), what was
   reverted, and that the source is exactly as it was before the
   pipeline ran.
