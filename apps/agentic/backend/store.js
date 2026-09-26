import { createStateService } from "../../../core/storage/state/index.js";
import { createStorage } from "../../../core/storage/index.js";
import { createId } from "./ids.js";
const SCOPES = ["users","auth-sessions","chat-sessions","connections","workspaces","tasks","activities"];
export function createAgenticStore({storage=createStorage()}={}) { const state=createStateService({storage,namespace:"agentic",scopes:SCOPES});
 const ownerKey=(u,r)=>`${u}--${r}`;
 async function putOwned(scope,u,id,value,options={}) { return state.put(scope,ownerKey(u,id),{...value,id,ownerId:u},options); }
 async function getOwned(scope,u,id) { const r=await state.get(scope,ownerKey(u,id)); return r?.ownerId===u?r:null; }
 async function listOwned(scope,u) { const prefix=`${u}--`; const ids=await state.list(scope); const out=[]; for(const key of ids.filter(k=>k.startsWith(prefix))){const r=await state.get(scope,key);if(r?.ownerId===u)out.push(r);} return out; }
 async function removeOwned(scope,u,id){const r=await getOwned(scope,u,id);if(!r)return false;return state.delete(scope,ownerKey(u,id),{expectedVersion:r._storage?.version});}
 return Object.freeze({state,createId,putOwned,getOwned,listOwned,removeOwned,
  createUser:u=>state.put("users",u.id,u,{overwrite:false}), getUser:id=>state.get("users",id), listUsers:async()=>Promise.all((await state.list("users")).map(id=>state.get("users",id))),
  putAuthSession:s=>state.put("auth-sessions",s.id,s,{overwrite:false}), getAuthSession:id=>state.get("auth-sessions",id),
  putChatSession:(u,s)=>putOwned("chat-sessions",u,s.id,s),getChatSession:(u,id)=>getOwned("chat-sessions",u,id),listChatSessions:u=>listOwned("chat-sessions",u),
  putConnection:(u,c)=>putOwned("connections",u,c.id,c),getConnection:(u,id)=>getOwned("connections",u,id),listConnections:u=>listOwned("connections",u),removeConnection:(u,id)=>removeOwned("connections",u,id),
  putWorkspace:(u,w)=>putOwned("workspaces",u,w.id,w),getWorkspace:(u,id)=>getOwned("workspaces",u,id),listWorkspaces:u=>listOwned("workspaces",u),
  putTask:(u,t)=>putOwned("tasks",u,t.id,t),listTasks:u=>listOwned("tasks",u),putActivity:(u,a)=>putOwned("activities",u,a.id,a),listActivities:u=>listOwned("activities",u)
 }); }
