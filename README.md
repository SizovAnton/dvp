# DVP

Detection Validation Platform for testing Sigma rules using Atomic Red Team and collected Windows events.

## Automated Testing

On Windows, run the following command in PowerShell as Administrator:

```powershell
.\dvp.exe `
    --rule .\test_rule.yaml `
    --auto `
    --atomic-test T1087.001 8
```

- `--rule` specifies the Sigma rule to evaluate.
- `--auto` starts an automated test and event collection.
- `--atomic-test` specifies the Atomic Red Team technique and test number.
- `--show-correlation` displays detailed correlation information in the console.

Running an automated test requires configured installations of Atomic Red Team and Invoke-AtomicRedTeam, along with the event source specified in the configuration.

The current version collects events only from the first channel in `events.channels`.

The `sources` profiles define the channel, provider, product, service, and Event ID-to-category mappings in `event_categories`.

The report evaluates all collected events. A rule match among candidate events does not prove that the Atomic test caused those events.

## Saved Session Analysis

```bash
.venv/bin/python -B main.py \
    --rule test_rule.yaml \
    --session runs/SESSION_ID \
    --execution-log runs/SESSION_ID/execution.csv
```

Replace `SESSION_ID` with the saved session directory name.

This mode generates a report without running the Atomic test again.
