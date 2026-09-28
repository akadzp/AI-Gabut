import { createId } from "./ids.js";

const FORBIDDEN_TYPES=new Set(["credential","secret","password","token","api_key","apikey"]);
const SENSITIVE_KEYS=new Set(["password","token","accessToken","refreshToken","apiKey","api_key","secret","credential","authorization"]);

function now(){return new Date().toISOString();}
function normalizeText(v){return String(v??"").trim();}
function tokens(v){return normalizeText(v).toLowerCase().split(/[^a-z0-9_]+/).filter(Boolean);}

function assertSafeMemory(memory){
  const type=normalizeText(memory.type).toLowerCase();
  if(FORBIDDEN_TYPES.has(type)) throw new Error("Credential material cannot be stored as memory");
  for(const key of Object.keys(memory.metadata??{})) if(SENSITIVE_KEYS.has(key)) throw new Error("Sensitive credential field cannot be stored as memory");
  const content=normalizeText(memory.content);
  if(/(?:bearer\s+|sk-[a-z0-9_-]{12,}|gh[pousr]_[a-z0-9_]{12,}|AIza[a-z0-9_-]{20,})/i.test(content)) {
    throw new Error("Credential-like material cannot be stored as memory");
  }
}

function score(query,record){
  const q=new Set(tokens(query));
  if(!q.size) return 0;
  const hay=tokens([record.type,record.content,...(record.tags??[])].join(" "));
  let hits=0;
  for(const t of q) if(hay.includes(t)) hits++;
  return hits/q.size;
}

export function createMemoryService({store}){
  if(!store) throw new TypeError("store is required");
  return Object.freeze({
    async create(userId,input){
      const memory={
        id:input.id??createId("memory"),
        type:normalizeText(input.type)||"fact",
        content:normalizeText(input.content),
        scope:normalizeText(input.scope)||"user",
        tags:Array.isArray(input.tags)?input.tags.map(normalizeText).filter(Boolean):[],
        metadata:input.metadata&&typeof input.metadata==="object"?{...input.metadata}:{},
        createdAt:input.createdAt??now(),
        updatedAt:now()
      };
      if(!memory.content) throw new Error("Memory content is required");
      assertSafeMemory(memory);
      return store.putMemory(userId,memory,{overwrite:false});
    },
    async get(userId,id){return store.getMemory(userId,id);},
    async list(userId){return store.listMemories(userId);},
    async remove(userId,id){return store.removeMemory(userId,id);},
    async search(userId,query,{limit=8,scope}={}){
      const bounded=Math.max(1,Math.min(20,Number(limit)||8));
      const records=await store.listMemories(userId);
      return records
        .filter(r=>!scope||r.scope===scope)
        .map(r=>({...r,_relevance:score(query,r)}))
        .filter(r=>r._relevance>0)
        .sort((a,b)=>b._relevance-a._relevance || String(b.updatedAt).localeCompare(String(a.updatedAt)))
        .slice(0,bounded)
        .map(({_relevance,...r})=>r);
    },
    async buildContext(userId,query,options={}){
      const memories=await this.search(userId,query,options);
      return Object.freeze({query:String(query??""),memories});
    }
  });
}
