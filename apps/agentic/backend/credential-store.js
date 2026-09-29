import { encryptSecret, decryptSecret } from "./crypto.js";
import { AgenticError } from "./errors.js";
import { createId } from "./ids.js";

function now(){return new Date().toISOString();}

export function createCredentialService({store}={}) {
  const fallback=new Map();
  const durable=Boolean(
    store&&
    typeof store.listConnectionCredentials==="function"&&
    typeof store.getConnectionCredential==="function"&&
    typeof store.putConnectionCredential==="function"
  );

  async function put(ownerId,{connectionId,provider,secret}={}) {
    if(!ownerId||!connectionId||!provider) throw new AgenticError("INVALID_CREDENTIAL_REFERENCE","Credential reference tidak lengkap");
    if(typeof secret!=="string"||!secret) throw new AgenticError("INVALID_CREDENTIAL","Credential wajib diisi");
    if(!durable){
      const id=createId("cred");
      fallback.set(`${ownerId}--${connectionId}`,{id,ownerId,connectionId,provider,ciphertext:encryptSecret(secret),version:1,createdAt:now(),updatedAt:now(),revokedAt:null});
      return Object.freeze({type:"provider-credential",id,version:1});
    }
    const existing=await store.listConnectionCredentials(ownerId);
    const current=existing.find(x=>x.connectionId===connectionId&&!x.revokedAt);
    const record={
      id:current?.id||createId("cred"),
      connectionId,provider,
      ciphertext:encryptSecret(secret),
      version:(current?.version||0)+1,
      createdAt:current?.createdAt||now(),
      updatedAt:now(),
      revokedAt:null
    };
    await store.putConnectionCredential(ownerId,record,{overwrite:true});
    return Object.freeze({type:"provider-credential",id:record.id,version:record.version});
  }

  async function get(ownerId,credentialId){
    if(!durable){
      const record=[...fallback.values()].find(x=>x.id===credentialId&&x.ownerId===ownerId&&!x.revokedAt);
      if(!record) throw new AgenticError("CREDENTIAL_NOT_FOUND","Credential tidak ditemukan",404);
      return decryptSecret(record.ciphertext);
    }
    const record=await store.getConnectionCredential(ownerId,credentialId);
    if(!record||record.revokedAt) throw new AgenticError("CREDENTIAL_NOT_FOUND","Credential tidak ditemukan",404);
    return decryptSecret(record.ciphertext);
  }

  async function getForConnection(ownerId,connectionId){
    if(!durable){
      const record=fallback.get(`${ownerId}--${connectionId}`);
      if(!record||record.revokedAt) throw new AgenticError("CREDENTIAL_NOT_FOUND","Credential connection tidak ditemukan",404);
      return decryptSecret(record.ciphertext);
    }
    const record=(await store.listConnectionCredentials(ownerId)).find(x=>x.connectionId===connectionId&&!x.revokedAt);
    if(record) return get(ownerId,record.id);

    // One-way compatibility path for connections created before credential separation.
    const legacy=await store.getConnection?.(ownerId,connectionId);
    if(legacy?.credential){
      const secret=decryptSecret(legacy.credential);
      const ref=await put(ownerId,{connectionId,provider:legacy.provider||"unknown",secret});
      const migrated={...legacy,credentialRef:ref,updatedAt:now()};
      delete migrated.credential;
      await store.putConnection(ownerId,migrated,{expectedVersion:legacy._storage?.version});
      return secret;
    }
    throw new AgenticError("CREDENTIAL_NOT_FOUND","Credential connection tidak ditemukan",404);
  }

  async function revoke(ownerId,credentialId){
    if(!durable){
      const entry=[...fallback.entries()].find(([,x])=>x.id===credentialId&&x.ownerId===ownerId);
      if(!entry) return false;
      entry[1].revokedAt=now();
      entry[1].updatedAt=now();
      return true;
    }
    const record=await store.getConnectionCredential(ownerId,credentialId);
    if(!record) return false;
    await store.putConnectionCredential(ownerId,{...record,revokedAt:now(),updatedAt:now()},{expectedVersion:record._storage?.version});
    return true;
  }

  async function revokeForConnection(ownerId,connectionId){
    if(!durable){
      const record=fallback.get(`${ownerId}--${connectionId}`);
      return record?revoke(ownerId,record.id):false;
    }
    const record=(await store.listConnectionCredentials(ownerId)).find(x=>x.connectionId===connectionId&&!x.revokedAt);
    return record?revoke(ownerId,record.id):false;
  }

  async function metadata(ownerId,connectionId){
    if(!durable){
      const record=fallback.get(`${ownerId}--${connectionId}`);
      return record&&!record.revokedAt?{type:"provider-credential",id:record.id,version:record.version}:null;
    }
    const record=(await store.listConnectionCredentials(ownerId)).find(x=>x.connectionId===connectionId&&!x.revokedAt);
    return record?{type:"provider-credential",id:record.id,version:record.version}:null;
  }

  return Object.freeze({put,get,getForConnection,revoke,revokeForConnection,metadata});
}
