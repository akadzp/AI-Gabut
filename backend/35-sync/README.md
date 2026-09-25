# Sync Engine

Synchronization is separate from connectors because local files can be edited by a human without the AI. The sync layer reconciles local state, remote state, snapshots, conflicts and change history.

Future flow:

`Connector -> Sync Adapter -> Sync Engine -> Local Workspace`
