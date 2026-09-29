import { AgenticError } from "./errors.js";
import { decryptSecret } from "./crypto.js";
import { createGitHubConnector, GitHubConnectorError } from "../../../connectors/github/index.js";
import { createCredentialService } from "./credential-store.js";

function mapError(error) {
  if (!(error instanceof GitHubConnectorError)) return error;
  return new AgenticError(error.code,error.message,error.status,error.details);
}

export function createGitHubService({store,connections,connector=createGitHubConnector(),credentials=createCredentialService({store})}) {
  async function tokenFor(u,id) {
    const c=await connections.raw(u,id);
    if(!c||c.provider!=="github") throw new AgenticError("CONNECTION_NOT_FOUND","GitHub connection tidak ditemukan",404);
    if(c.status!=="active") throw new AgenticError("CONNECTION_INACTIVE","GitHub connection tidak aktif",409);
    try{return{connection:c,token:await credentials.getForConnection(u,id)}}
    catch(error){if(error instanceof AgenticError)throw error;throw new AgenticError("GITHUB_CREDENTIAL_INVALID","Credential GitHub tidak dapat digunakan",409)}
  }

  async function connect(u,{token,name="GitHub"}={}) {
    if(typeof token!=="string"||token.length<10) throw new AgenticError("INVALID_GITHUB_TOKEN","GitHub token tidak valid");
    try {
      const account=await connector.account(token);
      const connection=await connections.create(u,{
        provider:"github",name:String(name).trim().slice(0,120)||"GitHub",
        account,credentialRef:{type:"provider-credential",id:null},status:"active"
      });
      const ref=await credentials.put(u,{connectionId:connection.id,provider:"github",secret:token});
      const raw=await connections.raw(u,connection.id);
      await store.putConnection(u,{...raw,credentialRef:ref,updatedAt:new Date().toISOString()},{expectedVersion:raw._storage?.version});
      return typeof connections.get === "function" ? await connections.get(u,connection.id) : await connections.raw(u,connection.id);
    } catch(error){throw mapError(error)}
  }

  async function secretForConnection(u,connection) {
    if(connection?.credential) {
      try { return decryptSecret(connection.credential); }
      catch { throw new AgenticError("GITHUB_CREDENTIAL_INVALID","Credential GitHub tidak dapat digunakan",409); }
    }
    return credentials.getForConnection(u,connection.id);
  }
  async function validateConnection(u,{connection}) {
    try{return{status:"active",patch:{account:await connector.account(await secretForConnection(u,connection))}}}
    catch(error){throw mapError(error)}
  }
  async function healthConnection(u,{connection,credential}) {
    try {
      const secret=credential ? decryptSecret(credential) : await secretForConnection(u,connection);
      const limits=await connector.rateLimits(secret);
      return{health:{status:limits.remaining===0?"degraded":"healthy",rateLimitRemaining:limits.remaining,rateLimitLimit:limits.limit,resetAt:limits.resetAt,checkedAt:new Date().toISOString()}};
    } catch(error){throw mapError(error)}
  }
  async function repositories(u,id){const{token}=await tokenFor(u,id);try{return connector.repositories(token)}catch(e){throw mapError(e)}}
  async function repository(u,id,owner,name){const{token}=await tokenFor(u,id);try{return connector.repository(token,owner,name)}catch(e){throw mapError(e)}}
  async function branches(u,id,owner,name){const{token}=await tokenFor(u,id);try{return connector.branches(token,owner,name)}catch(e){throw mapError(e)}}
  async function tree(u,id,owner,name,branch=null){const{token}=await tokenFor(u,id);try{return connector.tree(token,owner,name,branch)}catch(e){throw mapError(e)}}
  async function file(u,id,owner,name,path,ref=null){const{token}=await tokenFor(u,id);try{return connector.file(token,owner,name,path,ref)}catch(e){throw mapError(e)}}
  async function search(u,id,owner,name,query,options={}){const{token}=await tokenFor(u,id);try{return connector.search(token,owner,name,query,options)}catch(e){throw mapError(e)}}
  async function repositoryContext(u,{connection,owner,name,branch}) {
    try {
      const token=await credentials.getForConnection(u,connection.id);
      const [repository,branches]=await Promise.all([connector.repository(token,owner,name),connector.branches(token,owner,name)]);
      const selected=branches.find(item=>item.name===branch);
      if(!selected) throw new AgenticError("GITHUB_BRANCH_NOT_FOUND",`Branch tidak ditemukan: ${branch}`,404);
      return{repository,branch:{name:selected.name,sha:selected.sha,protected:selected.protected},capabilities:["repository","branch","tree","file","search"],refreshedAt:new Date().toISOString()};
    } catch(error){throw mapError(error)}
  }

  async function revokeCredential(u,id){return credentials.revokeForConnection(u,id)}
  return Object.freeze({connect,validateConnection,healthConnection,repositories,repository,branches,tree,file,search,repositoryContext,revokeCredential,credentials});
}
