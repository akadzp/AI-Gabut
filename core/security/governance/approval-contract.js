import crypto from "node:crypto";
import { redactSecrets } from "../secrets/manager.js";

const pending=new Map();
const DEFAULT_TTL_MS=5*60*1000;

export function createApprovalContract({ttlMs=DEFAULT_TTL_MS,now=()=>Date.now()}={}) {
  function fingerprint(tool,input={}) {
    const value={...input};
    delete value.approved;
    delete value.approvalToken;
    return crypto.createHash("sha256").update(`${tool}:${JSON.stringify(redactSecrets(value))}`).digest("hex");
  }
  function issue({tool,input={},principalId=null,sessionId=null,executionId=null,reason=""}={}) {
    if(!tool) throw new Error("Tool approval wajib diisi");
    const token=crypto.randomUUID(),createdAt=now(),expiresAt=createdAt+ttlMs;
    pending.set(token,{tool,sessionId,executionId,principalId,fingerprint:fingerprint(tool,input),reason:String(reason).slice(0,500),createdAt,expiresAt,used:false});
    return Object.freeze({token,tool,sessionId,executionId,expiresAt:new Date(expiresAt).toISOString()});
  }
  function consume({token,tool,input={},principalId=null,sessionId=null,executionId=null}={}) {
    const record=pending.get(token);
    if(!record) return{ok:false,error:"Approval token tidak valid"};
    if(record.used) return{ok:false,error:"Approval token sudah digunakan"};
    if(now()>record.expiresAt) return{ok:false,error:"Approval token sudah kedaluwarsa"};
    if(record.tool!==tool||record.sessionId!==sessionId||record.executionId!==executionId||record.principalId!==principalId) return{ok:false,error:"Approval token tidak cocok dengan authority context"};
    if(record.fingerprint!==fingerprint(tool,input)) return{ok:false,error:"Approval token tidak cocok dengan parameter tool"};
    record.used=true;
    return{ok:true};
  }
  function revoke(token){return pending.delete(token)}
  return Object.freeze({issue,consume,revoke});
}
