import assert from "node:assert/strict";
import test from "node:test";
import { loadAgenticDeployment, assertAllowedOrigin, getSecurityHeaders } from "../../apps/agentic/backend/deployment.js";
import { createApprovalContract } from "../../core/security/governance/approval-contract.js";
import { createAgenticServer } from "../../apps/agentic/backend/server.js";
import http from "node:http";
import { authorizeTool } from "../../core/security/index.js";

test("split deployment requires explicit allowed origins",()=>{
  assert.throws(()=>loadAgenticDeployment({AGENTIC_TOPOLOGY:"split"}),/ALLOWED_ORIGINS/);
  const cfg=loadAgenticDeployment({AGENTIC_TOPOLOGY:"split",AGENTIC_ALLOWED_ORIGINS:"https://app.example.com"});
  assert.equal(assertAllowedOrigin("https://app.example.com",cfg),true);
  assert.equal(assertAllowedOrigin("https://evil.example",cfg),false);
  assert.equal(getSecurityHeaders({split:true})["X-Frame-Options"],"DENY");
});

test("approval contract is a facade over canonical security authority",()=>{
  const c=createApprovalContract();
  const a=c.issue({tool:"git_push",input:{branch:"main"},principalId:"u1",sessionId:"s1",executionId:"e1"});
  assert.equal(c.consume({token:a.token,tool:"git_push",input:{branch:"main"},principalId:"u2",sessionId:"s1",executionId:"e1"}).ok,false);
  assert.equal(c.consume({token:a.token,tool:"git_push",input:{branch:"dev"},principalId:"u1",sessionId:"s1",executionId:"e1"}).ok,false);
  assert.equal(c.consume({token:a.token,tool:"git_push",input:{branch:"main"},principalId:"u1",sessionId:"s1",executionId:"e1"}).ok,true);
  assert.equal(c.consume({token:a.token,tool:"git_push",input:{branch:"main"},principalId:"u1",sessionId:"s1",executionId:"e1"}).ok,false);
  const b=c.issue({tool:"git_push",input:{branch:"main"},principalId:"u1",sessionId:"s1",executionId:"e2"});
  assert.equal(c.revoke(b.token),true);
  assert.equal(c.consume({token:b.token,tool:"git_push",input:{branch:"main"},principalId:"u1",sessionId:"s1",executionId:"e2"}).ok,false);
});


test("canonical tool authorization binds approval to principal and execution",()=>{
  const c=createApprovalContract();
  const a=c.issue({tool:"git_push",input:{branch:"main"},principalId:"u1",sessionId:"s1",executionId:"e1"});
  const deniedPrincipal=authorizeTool({tool:"git_push",input:{branch:"main"},principalId:"u2",sessionId:"s1",executionId:"e1",approvalToken:a.token});
  assert.equal(deniedPrincipal.ok,false);
  const deniedExecution=authorizeTool({tool:"git_push",input:{branch:"main"},principalId:"u1",sessionId:"s1",executionId:"e2",approvalToken:a.token});
  assert.equal(deniedExecution.ok,false);
  const allowed=authorizeTool({tool:"git_push",input:{branch:"main"},principalId:"u1",sessionId:"s1",executionId:"e1",approvalToken:a.token});
  assert.equal(allowed.ok,true);
});


test("split deployment policy is enforced by the Agentic HTTP server", async()=>{
  const previous=process.env.AGENTIC_TOPOLOGY;
  const previousOrigins=process.env.AGENTIC_ALLOWED_ORIGINS;
  process.env.AGENTIC_TOPOLOGY="split";
  process.env.AGENTIC_ALLOWED_ORIGINS="https://app.example.com";
  const server=createAgenticServer({configuration:{port:0,host:"127.0.0.1"}});
  await new Promise(resolve=>server.server.once("listening",resolve));
  const port=server.server.address().port;
  const request=(origin)=>new Promise((resolve,reject)=>{const req=http.request({host:"127.0.0.1",port,path:"/api/agentic/health",headers:{Origin:origin}},res=>{let body="";res.on("data",c=>body+=c);res.on("end",()=>resolve({status:res.statusCode,headers:res.headers,body}));});req.on("error",reject);req.end();});
  try{
    const allowed=await request("https://app.example.com");
    assert.equal(allowed.status,200);
    assert.equal(allowed.headers["access-control-allow-origin"],"https://app.example.com");
    assert.equal(allowed.headers["x-content-type-options"],"nosniff");
    const denied=await request("https://evil.example");
    assert.equal(denied.status,403);
  }finally{
    await new Promise(resolve=>server.server.close(resolve));
    if(previous===undefined)delete process.env.AGENTIC_TOPOLOGY;else process.env.AGENTIC_TOPOLOGY=previous;
    if(previousOrigins===undefined)delete process.env.AGENTIC_ALLOWED_ORIGINS;else process.env.AGENTIC_ALLOWED_ORIGINS=previousOrigins;
  }
});
