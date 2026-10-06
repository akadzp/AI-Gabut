import { createStateService } from "../../../core/storage/state/index.js";
import { createStorage } from "../../../core/storage/index.js";
import { createId } from "./ids.js";

const SCOPES=["users","auth-sessions","chat-sessions","chat-messages","connections","connection-credentials","workspaces","tasks","executions","activities","memories","works","changes","verifications","repair-checkpoints"];

export function createAgenticStore({storage=createStorage()}={}) {
  const state=createStateService({storage,namespace:"agentic",scopes:SCOPES});
  const ownerKey=(u,r)=>`${u}--${r}`;

  async function putOwned(scope,u,id,value,options={}) {
    return state.put(scope,ownerKey(u,id),{...value,id,ownerId:u},{overwrite:options.overwrite !== false,...options});
  }
  async function getOwned(scope,u,id) {
    const r=await state.get(scope,ownerKey(u,id));
    return r?.ownerId===u?r:null;
  }
  async function listOwned(scope,u) {
    const p=`${u}--`,out=[];
    for(const k of (await state.list(scope)).filter(x=>x.startsWith(p))) {
      const r=await state.get(scope,k);
      if(r?.ownerId===u) out.push(r);
    }
    return out;
  }
  async function removeOwned(scope,u,id) {
    const r=await getOwned(scope,u,id);
    if(!r) return false;
    return state.delete(scope,ownerKey(u,id),{expectedVersion:r._storage?.version});
  }

  return Object.freeze({
    state, createId, putOwned, getOwned, listOwned, removeOwned,
    createUser:u=>state.put("users",u.id,u,{overwrite:false}),
    getUser:id=>state.get("users",id),
    listUsers:async()=>Promise.all((await state.list("users")).map(id=>state.get("users",id))),
    putAuthSession:s=>state.put("auth-sessions",s.id,s,{overwrite:false}),
    getAuthSession:id=>state.get("auth-sessions",id),
    putChatSession:(u,s,o={})=>putOwned("chat-sessions",u,s.id,s,{overwrite:o.expectedVersion!=null,...o}),
    getChatSession:(u,id)=>getOwned("chat-sessions",u,id),
    listChatSessions:u=>listOwned("chat-sessions",u),
    putChatMessage:(u,m,o={})=>putOwned("chat-messages",u,m.id,m,o),
    getChatMessage:(u,id)=>getOwned("chat-messages",u,id),
    listChatMessages:u=>listOwned("chat-messages",u),
    removeConnection:(u,id)=>removeOwned("connections",u,id),
    putConnection:(u,c,o={})=>putOwned("connections",u,c.id,c,o),
    getConnection:(u,id)=>getOwned("connections",u,id),
    listConnections:u=>listOwned("connections",u),
    putConnectionCredential:(u,c,o={})=>putOwned("connection-credentials",u,c.id,c,o),
    getConnectionCredential:(u,id)=>getOwned("connection-credentials",u,id),
    listConnectionCredentials:u=>listOwned("connection-credentials",u),
    removeConnectionCredential:(u,id)=>removeOwned("connection-credentials",u,id),
    putWorkspace:(u,w,o={})=>putOwned("workspaces",u,w.id,w,o),
    getWorkspace:(u,id)=>getOwned("workspaces",u,id),
    listWorkspaces:u=>listOwned("workspaces",u),
    putTask:(u,t,o={})=>putOwned("tasks",u,t.id,t,o),
    getTask:(u,id)=>getOwned("tasks",u,id),
    listTasks:u=>listOwned("tasks",u),
    putExecution:(u,e,o={})=>putOwned("executions",u,e.id,e,o),
    getExecution:(u,id)=>getOwned("executions",u,id),
    listExecutions:u=>listOwned("executions",u),
    putActivity:(u,a,o={})=>putOwned("activities",u,a.id,a,o),
    listActivities:u=>listOwned("activities",u),
    putMemory:(u,m,o={})=>putOwned("memories",u,m.id,m,o),
    getMemory:(u,id)=>getOwned("memories",u,id),
    listMemories:u=>listOwned("memories",u),
    removeMemory:(u,id)=>removeOwned("memories",u,id),
    putWork:(u,w,o={})=>putOwned("works",u,w.id,w,o),
    getWork:(u,id)=>getOwned("works",u,id),
    listWorks:u=>listOwned("works",u),
    putChange:(u,c,o={})=>putOwned("changes",u,c.id,c,o),
    getChange:(u,id)=>getOwned("changes",u,id),
    listChanges:u=>listOwned("changes",u),
    putVerification:(u,v,o={})=>putOwned("verifications",u,v.id,v,o),
    getVerification:(u,id)=>getOwned("verifications",u,id),
    listVerifications:u=>listOwned("verifications",u),
    putRepairCheckpoint:(u,v,o={})=>putOwned("repair-checkpoints",u,v.id,v,o),
    getRepairCheckpoint:(u,id)=>getOwned("repair-checkpoints",u,id),
    listRepairCheckpoints:u=>listOwned("repair-checkpoints",u)
  });
}
