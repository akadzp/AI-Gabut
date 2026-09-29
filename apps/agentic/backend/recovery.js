import { AgenticError } from "./errors.js";

const RECOVERABLE=new Set(["running","waiting_approval"]);

export function createRecoveryService({store}={}) {
  async function scan(ownerId=null) {
    const owners=ownerId?[ownerId]:await store.listUsers().then(xs=>xs.map(x=>x.id));
    const found=[];
    for(const owner of owners){
      for(const execution of await store.listExecutions(owner)){
        if(!RECOVERABLE.has(execution.status)) continue;
        const interrupted={
          ...execution,
          status:"interrupted",
          recoverable:true,
          recoveryReason:"runtime-restart",
          updatedAt:new Date().toISOString()
        };
        await store.putExecution(owner,interrupted,{expectedVersion:execution._storage?.version});
        found.push({ownerId:owner,execution:interrupted});
      }
    }
    return found;
  }

  async function get(ownerId,id){
    const execution=await store.getExecution(ownerId,id);
    if(!execution) throw new AgenticError("EXECUTION_NOT_FOUND","Execution tidak ditemukan",404);
    if(execution.status!=="interrupted"||!execution.recoverable) {
      throw new AgenticError("EXECUTION_NOT_RECOVERABLE","Execution tidak berada pada recovery state",409);
    }
    return execution;
  }

  async function markResuming(ownerId,id){
    const execution=await get(ownerId,id);
    const next={...execution,status:"running",recoverable:false,recoveryReason:null,updatedAt:new Date().toISOString()};
    return store.putExecution(ownerId,next,{expectedVersion:execution._storage?.version});
  }

  return Object.freeze({scan,get,markResuming,recoverableStatuses:[...RECOVERABLE]});
}
