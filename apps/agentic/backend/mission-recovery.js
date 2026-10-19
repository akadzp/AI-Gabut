import { createId } from "./ids.js";

const DEFAULT_STALE_AFTER_MS=20*60*1000;
const ACTIVE_STAGE_STATES=new Set(["running","waiting_approval"]);

function nowIso(clock){return new Date(clock()).toISOString();}

export function createMissionRecovery({store,leaseService=null,observability=null,clock=()=>Date.now(),staleAfterMs=DEFAULT_STALE_AFTER_MS}={}){
  if(!store?.listMissions||!store?.putMission) throw new TypeError("Mission recovery membutuhkan mission store");
  const threshold=Math.max(60*1000,Number(staleAfterMs)||DEFAULT_STALE_AFTER_MS);

  async function scan(ownerId=null){
    const owners=ownerId?[ownerId]:await store.listUsers().then(xs=>xs.map(x=>x.id));
    const recovered=[];
    const at=clock();
    for(const owner of owners){
      for(const mission of await store.listMissions(owner)){
        if(mission.status!=="running") continue;
        const updated=Date.parse(mission.updatedAt||mission.createdAt||"");
        if(Number.isFinite(updated)&&at-updated<threshold) continue;
        const index=Number(mission.currentStageIndex)||0;
        const stage=mission.stages?.[index];
        if(!stage||!ACTIVE_STAGE_STATES.has(stage.state)) continue;

        if(leaseService){
          const lease=await store.getOwned?.("mission-leases",owner,`mission-lease:${owner}:${mission.id}`);
          if(lease?.expiresAtMs>at) continue;
        }

        const detectedAt=nowIso(clock);
        const recovery={
          id:createId("mission-recovery"),
          status:"interrupted",
          recoverable:true,
          reason:"runtime-restart-or-stale",
          detectedAt,
          previousState:mission.status,
          stageId:stage.id,
          stageIndex:index
        };
        const next={
          ...mission,
          status:"scheduled",
          nextRunAt:detectedAt,
          stages:mission.stages.map((s,i)=>i===index?{...s,state:"pending",recovery}:s),
          recovery:[...(mission.recovery||[]),recovery],
          updatedAt:detectedAt
        };
        const saved=await store.putMission(owner,next,{expectedVersion:mission._storage?.version});
        let evidenceError=null;
        if(observability?.event){
          try {
            await observability.event(owner,mission.id,"mission_recovered",{
              stageId:stage.id,
              stageIndex:index,
              recoveryId:recovery.id,
              reason:recovery.reason,
              previousState:recovery.previousState,
              dedupeKey:`mission-recovered:${recovery.id}`
            });
          } catch(error) {
            evidenceError={code:error.code||"MISSION_RECOVERY_EVIDENCE_FAILED",message:error.message||String(error)};
          }
        }
        recovered.push(evidenceError?{...saved,recoveryEvidenceError:evidenceError}:saved);
      }
    }
    return recovered;
  }

  return Object.freeze({scan,staleAfterMs:threshold});
}
