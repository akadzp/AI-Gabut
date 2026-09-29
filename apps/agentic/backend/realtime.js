function cursorOf(event) {
  return `${event.createdAt}|${event.id}`;
}
function compare(a,b) {
  const time=String(a.createdAt).localeCompare(String(b.createdAt));
  return time || String(a.id).localeCompare(String(b.id));
}
function publicEvent(event) {
  return {
    id:event.id,
    cursor:cursorOf(event),
    type:event.type||"activity",
    executionId:event.executionId||null,
    sessionId:event.sessionId||null,
    action:event.action||"unknown",
    status:event.status||"running",
    label:event.label||event.action||"Activity",
    meta:event.meta||{},
    error:event.error||null,
    createdAt:event.createdAt
  };
}
function afterCursor(events,cursor) {
  if(!cursor) return events;
  const [createdAt,...idParts]=String(cursor).split("|");
  const id=idParts.join("|");
  return events.filter(x=>compare(x,{createdAt,id})>0);
}
export function createRealtimeService({store}={}) {
  const subscribers=new Map();
  function subscribe(ownerId,handler,{executionId=null,sessionId=null}={}) {
    const set=subscribers.get(ownerId)||new Set();
    const sub={handler,executionId,sessionId};
    set.add(sub);subscribers.set(ownerId,set);
    return ()=>{set.delete(sub);if(!set.size)subscribers.delete(ownerId)};
  }
  async function replay(ownerId,{after=null,executionId=null,sessionId=null,limit=500}={}) {
    let events=(await store.listActivities(ownerId)).filter(x=>!executionId||x.executionId===executionId).filter(x=>!sessionId||x.sessionId===sessionId).sort(compare);
    events=afterCursor(events,after);
    return events.slice(0,Math.max(1,Math.min(Number(limit)||500,500))).map(publicEvent);
  }
  async function publish(ownerId,event) {
    const value=publicEvent(event);
    for(const sub of [...(subscribers.get(ownerId)||[])]) {
      if(sub.executionId&&sub.executionId!==value.executionId)continue;
      if(sub.sessionId&&sub.sessionId!==value.sessionId)continue;
      try{await sub.handler(value)}catch{}
    }
    return value;
  }
  return Object.freeze({subscribe,replay,publish,publicEvent,cursorOf});
}
