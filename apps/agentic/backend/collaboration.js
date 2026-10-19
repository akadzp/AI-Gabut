const createId=prefix=>`${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2,10)}`;
class AgenticError extends Error { constructor(code,message,status=400){super(message);this.code=code;this.status=status;} }

const TYPES = new Set(['instruction_refinement','intervention','feedback','approval','correction']);
const ACTIONS = new Set(['refine','feedback','correct','pause','resume']);

function clean(v,n=12000){return String(v??'').trim().slice(0,n)}
function provenance(ownerId,actor,source){return {ownerId,actor:actor||'user',source:source||'agentic',at:new Date().toISOString()}}

export function createCollaborationService({store,work,workExecution,realtime=null}={}){
  if(!store||!work||!workExecution) throw new Error('Collaboration service membutuhkan store, work, dan workExecution');
  async function record(ownerId,workId,type,payload={}){
    if(!TYPES.has(type)) throw new AgenticError('INVALID_COLLABORATION_TYPE','Jenis collaboration tidak valid');
    await work.raw(ownerId,workId);
    const now=new Date().toISOString();
    const item={id:createId('collab'),workId,ownerId,type,payload:{...payload},provenance:provenance(ownerId,payload.actor,payload.source),createdAt:now,updatedAt:now};
    await store.putOwned('collaboration',ownerId,item.id,item,{overwrite:false});
    if(realtime) await realtime.publish(ownerId,{id:createId('activity'),workId,type:'collaboration',action:`collaboration_${type}`,status:'completed',label:`Collaboration · ${type}`,meta:{collaborationId:item.id},createdAt:now});
    return item;
  }
  async function list(ownerId,workId){return (await store.listOwned('collaboration',ownerId)).filter(x=>!workId||x.workId===workId).sort((a,b)=>String(a.createdAt).localeCompare(String(b.createdAt)))}
  async function refine(ownerId,workId,instruction,actor='user'){const message=clean(instruction);if(!message)throw new AgenticError('INVALID_INTERVENTION','Instruksi refinement wajib diisi');const result=await workExecution.revise(ownerId,workId,message);await record(ownerId,workId,'instruction_refinement',{instruction:message,actor,source:'human'});return result}
  async function feedback(ownerId,workId,message,actor='user'){const text=clean(message,4000);if(!text)throw new AgenticError('INVALID_FEEDBACK','Feedback wajib diisi');return record(ownerId,workId,'feedback',{message:text,actor,source:'human'})}
  async function correct(ownerId,workId,instruction,actor='user'){const message=clean(instruction);if(!message)throw new AgenticError('INVALID_CORRECTION','Correction wajib diisi');const result=await workExecution.revise(ownerId,workId,message);await record(ownerId,workId,'correction',{instruction:message,actor,source:'human'});return result}
  async function pause(ownerId,workId,reason){const result=await workExecution.pause(ownerId,workId,reason);await record(ownerId,workId,'intervention',{action:'pause',reason:clean(reason,2000),actor:'user',source:'human'});return result}
  async function resume(ownerId,workId,options={}){const result=await workExecution.resume(ownerId,workId,options);await record(ownerId,workId,'intervention',{action:'resume',actor:'user',source:'human'});return result}
  return Object.freeze({types:Object.freeze([...TYPES]),actions:Object.freeze([...ACTIONS]),record,list,refine,feedback,correct,pause,resume});
}
