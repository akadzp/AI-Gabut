import { createStateService } from "../../../core/storage/state/index.js";
import { createStorage } from "../../../core/storage/index.js";
import { createId } from "./ids.js";

const SCOPES=["users","auth-sessions","chat-sessions","chat-messages","connections","workspaces","tasks","executions","activities","memories"];

export function createAgenticStore({storage=createStorage()}={}) {
  const state=createStateService({storage,namespace:"agentic",scopes:SCOPES});
  const ownerKey=(u,r)=>`${u}--${r}`;

  async function putOwned(scope,u,id,value,options={overwrite:true}) {
    return state.put(
      scope,
      ownerKey(u,id),
      {...value,id,ownerId:u},
      options
    );
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
    state,
    createId,
    putOwned,
    getOwned,
    listOwned,
    removeOwned,

    createUser:u=>state.put("users",u.id,u,{overwrite:false}),
    getUser:id=>state.get("users",id),
    listUsers:async()=>Promise.all((await state.list("users")).map(id=>state.get("users",id))),

    putAuthSession:s=>state.put("auth-sessions",s.id,s,{overwrite:false}),
    getAuthSession:id=>state.get("auth-sessions",id),

    // New session: overwrite=false.
    // Existing session update: expectedVersion implies overwrite=true unless
    // the caller explicitly supplies another overwrite value.
    putChatSession:(u,s,o={})=>putOwned(
      "chat-sessions",
      u,
      s.id,
      s,
      {overwrite:o.expectedVersion!=null,...o}
    ),
    getChatSession:(u,id)=>getOwned("chat-sessions",u,id),
    listChatSessions:u=>listOwned("chat-sessions",u),

    putChatMessage:(u,m,o)=>putOwned("chat-messages",u,m.id,m,o),
    getChatMessage:(u,id)=>getOwned("chat-messages",u,id),
    listChatMessages:u=>listOwned("chat-messages",u),

    removeConnection:(u,id)=>removeOwned("connections",u,id),
    putConnection:(u,c)=>putOwned("connections",u,c.id,c),
    getConnection:(u,id)=>getOwned("connections",u,id),
    listConnections:u=>listOwned("connections",u),

    putWorkspace:(u,w)=>putOwned("workspaces",u,w.id,w),
    getWorkspace:(u,id)=>getOwned("workspaces",u,id),
    listWorkspaces:u=>listOwned("workspaces",u),

    putTask:(u,t)=>putOwned("tasks",u,t.id,t),
    getTask:(u,id)=>getOwned("tasks",u,id),
    listTasks:u=>listOwned("tasks",u),

    putExecution:(u,e)=>putOwned("executions",u,e.id,e),
    getExecution:(u,id)=>getOwned("executions",u,id),
    listExecutions:u=>listOwned("executions",u),

    putActivity:(u,a)=>putOwned("activities",u,a.id,a),
    listActivities:u=>listOwned("activities",u),

    putMemory:(u,m,o)=>putOwned("memories",u,m.id,m,o),
    getMemory:(u,id)=>getOwned("memories",u,id),
    listMemories:u=>listOwned("memories",u),
    removeMemory:(u,id)=>removeOwned("memories",u,id)
  });
}
