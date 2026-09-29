import assert from "node:assert/strict";
import test from "node:test";
import { loadAgenticDeployment, assertAllowedOrigin, getSecurityHeaders } from "../../apps/agentic/backend/deployment.js";
import { createApprovalContract } from "../../core/security/governance/approval-contract.js";

test("split deployment requires explicit allowed origins",()=>{
  assert.throws(()=>loadAgenticDeployment({AGENTIC_TOPOLOGY:"split"}),/ALLOWED_ORIGINS/);
  const cfg=loadAgenticDeployment({AGENTIC_TOPOLOGY:"split",AGENTIC_ALLOWED_ORIGINS:"https://app.example.com"});
  assert.equal(assertAllowedOrigin("https://app.example.com",cfg),true);
  assert.equal(assertAllowedOrigin("https://evil.example",cfg),false);
  assert.equal(getSecurityHeaders({split:true})["X-Frame-Options"],"DENY");
});

test("approval contract binds token to principal, session, execution and exact input",()=>{
  let clock=1000;
  const c=createApprovalContract({ttlMs:100,now:()=>clock});
  const a=c.issue({tool:"git_push",input:{branch:"main"},principalId:"u1",sessionId:"s1",executionId:"e1"});
  assert.equal(c.consume({token:a.token,tool:"git_push",input:{branch:"main"},principalId:"u2",sessionId:"s1",executionId:"e1"}).ok,false);
  assert.equal(c.consume({token:a.token,tool:"git_push",input:{branch:"dev"},principalId:"u1",sessionId:"s1",executionId:"e1"}).ok,false);
  assert.equal(c.consume({token:a.token,tool:"git_push",input:{branch:"main"},principalId:"u1",sessionId:"s1",executionId:"e1"}).ok,true);
  assert.equal(c.consume({token:a.token,tool:"git_push",input:{branch:"main"},principalId:"u1",sessionId:"s1",executionId:"e1"}).ok,false);
  const b=c.issue({tool:"git_push",input:{branch:"main"},principalId:"u1",sessionId:"s1",executionId:"e2"});
  clock=1101;
  assert.equal(c.consume({token:b.token,tool:"git_push",input:{branch:"main"},principalId:"u1",sessionId:"s1",executionId:"e2"}).ok,false);
});
