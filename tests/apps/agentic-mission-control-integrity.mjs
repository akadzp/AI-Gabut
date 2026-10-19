import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionControlIntegrity} from '../../apps/agentic/backend/mission-control-integrity.js';
const integrity=createMissionControlIntegrity({clock:()=>Date.parse('2026-10-08T00:00:00.000Z')});
const base={id:'m1',ownerId:'u1',status:'paused',controlId:'c1',controlReason:'hold',controlRequestId:'r1',controlHistory:[{controlId:'c1',action:'pause',reason:'hold',requestId:'r1',createdAt:'2026-10-08T00:00:00.000Z'}]};
test('valid pause control state passes integrity',()=>assert.equal(integrity.inspect('u1',base).valid,true));
test('duplicate control ids and request ids are detected',()=>{const r=integrity.inspect('u1',{...base,controlHistory:[...base.controlHistory,{...base.controlHistory[0]}]});assert.equal(r.valid,false);assert.ok(r.issues.some(x=>x.code==='CONTROL_ID_DUPLICATE'));assert.ok(r.issues.some(x=>x.code==='CONTROL_REQUEST_DUPLICATE'));});
test('pending evidence must match durable control state',()=>{const r=integrity.inspect('u1',{...base,controlEvidencePending:{controlId:'other',action:'pause',requestId:'r1'}});assert.equal(r.valid,false);assert.ok(r.issues.some(x=>x.code==='CONTROL_PENDING_MISMATCH'));});
test('bounded repair removes malformed duplicate control history and orphan markers',()=>{const broken={...base,controlHistory:[...base.controlHistory,{...base.controlHistory[0]},null,{controlId:'bad',action:'pause',createdAt:'bad'}],controlEvidencePending:{controlId:'missing',action:'pause'},controlEvidenceError:'evidence unavailable'};const r=integrity.repair('u1',broken);assert.equal(r.remainingIssues.length,0);assert.equal(r.mission.controlHistory.length,1);assert.equal(r.mission.controlEvidencePending,undefined);assert.equal(r.mission.controlEvidenceError,undefined);});


test('transition audit metadata is validated when present',()=>{
 const valid={...base,controlHistory:[{...base.controlHistory[0],fromStatus:'running',toStatus:'paused',baseVersion:3}]};
 assert.equal(integrity.inspect('u1',valid).valid,true);
 const broken={...valid,controlHistory:[{...valid.controlHistory[0],toStatus:'cancelled'}]};
 const r=integrity.inspect('u1',broken);
 assert.ok(r.issues.some(x=>x.code==='CONTROL_TRANSITION_TARGET_MISMATCH'));
});
