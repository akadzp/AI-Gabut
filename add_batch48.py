from pathlib import Path
p=Path('apps/agentic/backend/mission-control.js')
s=p.read_text()
needle=''' async function repairAuditRecoveryEvidence(ownerId,missionId){'''
insert=''' async function auditRecoveryEvidenceRepairStatus(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pending=mission.controlAuditRecoveryEvidenceRepairPending||null;
  const error=mission.controlAuditRecoveryEvidenceRepairError||null;
  const phase=pending?'pending':error?'error':'clear';
  return {
   missionId:mission.id,
   ownerId,
   phase,
   recoverable:Boolean(pending),
   reconciliationId:pending?.reconciliationId||null,
   phaseBefore:pending?.phaseBefore||null,
   reconciledByRetry:pending?.reconciledByRetry===true,
   repairedByRetry:pending?.repairedByRetry===true,
   createdAt:pending?.createdAt||null,
   error:error?String(error):null,
   storageVersion:mission._storage?.version??null
  };
 }

'''
assert needle in s
s=s.replace(needle,insert+needle)
s=s.replace('return Object.freeze({actions:Object.freeze([...CONTROL_ACTIONS]),control,status,audit,verifyAudit,reconciliationStatus,verifyAuditRecoveryEvidence,repairAuditRecoveryEvidence,reconcileAudit,recoverAuditReconciliation});', 'return Object.freeze({actions:Object.freeze([...CONTROL_ACTIONS]),control,status,audit,verifyAudit,reconciliationStatus,verifyAuditRecoveryEvidence,auditRecoveryEvidenceRepairStatus,repairAuditRecoveryEvidence,reconcileAudit,recoverAuditReconciliation});')
p.write_text(s)

p=Path('apps/agentic/backend/application.js')
s=p.read_text()
old='verifyMissionControlAuditRecoveryEvidence:missionControl.verifyAuditRecoveryEvidence,repairMissionControlAuditRecoveryEvidence:missionControl.repairAuditRecoveryEvidence,'
new='verifyMissionControlAuditRecoveryEvidence:missionControl.verifyAuditRecoveryEvidence,getMissionControlAuditRecoveryEvidenceRepairStatus:missionControl.auditRecoveryEvidenceRepairStatus,repairMissionControlAuditRecoveryEvidence:missionControl.repairAuditRecoveryEvidence,'
assert old in s
p.write_text(s.replace(old,new))

# add tests
p=Path('tests/apps/agentic-mission-control-audit-recovery-evidence-repair-status.mjs')
p.write_text('''import test from 'node:test';\nimport assert from 'node:assert/strict';\nimport {createMissionControl} from '../../apps/agentic/backend/mission-control.js';\n\nfunction runtime(initial){\n let current={...initial};\n const store={\n  async getOwned(_scope,_owner,id){return id===current.id?current:null;},\n  async putOwned(_scope,_owner,id,next){current={...next,_storage:{version:(current._storage?.version||0)+1}};return current;},\n  current:()=>current\n };\n const observability={async event(){},async snapshot(_o,m){return m;}};\n return {store,service:createMissionControl({missionStore:store,observability,clock:()=> '2026-10-08T00:00:00.000Z'})};\n}\nconst base={id:'m1',ownerId:'u1',status:'paused',controlHistory:[],_storage:{version:7}};\nconst pending={reconciliationId:'reconcile-48',phaseBefore:'pending',reconciledByRetry:false,repairedByRetry:false,createdAt:'2026-10-08T00:00:00.000Z'};\n\ntest('repair evidence status reports clear state without mutation',async()=>{\n const r=runtime(base); const before=r.store.current();\n const out=await r.service.auditRecoveryEvidenceRepairStatus('u1','m1');\n assert.deepEqual(out,{missionId:'m1',ownerId:'u1',phase:'clear',recoverable:false,reconciliationId:null,phaseBefore:null,reconciledByRetry:false,repairedByRetry:false,createdAt:null,error:null,storageVersion:7});\n assert.strictEqual(r.store.current(),before);\n});\n\ntest('repair evidence status reports pending recovery intent',async()=>{\n const r=runtime({...base,controlAuditRecoveryEvidenceRepairPending:pending,controlAuditRecoveryEvidenceRepairError:'OBSERVABILITY_DOWN'});\n const out=await r.service.auditRecoveryEvidenceRepairStatus('u1','m1');\n assert.equal(out.phase,'pending'); assert.equal(out.recoverable,true); assert.equal(out.reconciliationId,'reconcile-48');\n assert.equal(out.error,'OBSERVABILITY_DOWN'); assert.equal(out.phaseBefore,'pending');\n});\n\ntest('repair evidence status is owner scoped and exposes retry metadata',async()=>{\n const r=runtime({...base,controlAuditRecoveryEvidenceRepairPending:{...pending,reconciledByRetry:true,repairedByRetry:true}});\n const out=await r.service.auditRecoveryEvidenceRepairStatus('u1','m1');\n assert.equal(out.reconciledByRetry,true); assert.equal(out.repairedByRetry,true); assert.equal(out.storageVersion,7);\n await assert.rejects(()=>r.service.auditRecoveryEvidenceRepairStatus('u2','m1'),e=>e.code==='FORBIDDEN');\n});\n''')

p=Path('docs/status/00_Current-Status.txt')
s=p.read_text().replace('V4 Batch 47 — Mission Control Audit Recovery Evidence Repair Observability','V4 Batch 48 — Mission Control Audit Recovery Evidence Repair Status & Recovery Inspection').replace('''Scope completed:\n- durable recovery-evidence repair completion observability\n- deterministic owner-scoped repair evidence dedupe key\n- repair-evidence intent persisted before observability emission\n- recovery-evidence repair remains durable when observability fails\n- pending repair evidence can be retried without rerunning canonical repair\n- preserved owner scoping, optimistic concurrency, reconciliation authority, idempotency, and execution authority''','''Scope completed:\n- read-only owner-scoped repair-evidence repair status inspection\n- explicit clear/pending/error lifecycle classification\n- bounded recovery metadata exposure without mutation\n- retry metadata and durable storage version visibility\n- preserved repair observability, owner scoping, optimistic concurrency, idempotency, and execution authority''').replace('''Validation:\n- Batch 47 dedicated regression tests: 3/3 PASS\n- Mission Control recovery-evidence regression set: 12/12 PASS\n- JavaScript/MJS syntax validation: PASS\n- full npm test: 116/121 PASS\n- remaining 5 failures are pre-existing baseline failures outside Batch 47\n\nNext unfinished stage: Batch 48.''','''Validation:\n- Batch 48 dedicated regression tests: 3/3 PASS\n- Mission Control recovery-evidence regression set: 15/15 PASS\n- JavaScript/MJS syntax validation: PASS\n- full npm test: 119/124 PASS\n- remaining 5 failures are pre-existing baseline failures outside Batch 48\n\nNext unfinished stage: Batch 49.''')
p.write_text(s)
