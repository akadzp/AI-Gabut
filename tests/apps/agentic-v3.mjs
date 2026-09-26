import assert from "node:assert/strict";
import test from "node:test";
import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";
process.env.AGENTIC_CREDENTIAL_KEY="test-only-agentic-key-that-is-long-enough";
const {createAuthService}=await import("../../apps/agentic/backend/auth.js");
const {encryptSecret,decryptSecret,hashPassword,verifyPassword}=await import("../../apps/agentic/backend/crypto.js");
const data={users:new Map(),auth:new Map(),sessions:new Map()};
const store={listUsers:async()=>[...data.users.values()],createUser:async u=>(data.users.set(u.id,u),u),putAuthSession:async s=>(data.auth.set(s.id,s),s),getAuthSession:async id=>data.auth.get(id)||null,getUser:async id=>data.users.get(id)||null,state:{put:async(_s,id,v)=>(data.auth.set(id,v),v)},putChatSession:async(u,s)=>(data.sessions.set(`${u}:${s.id}`,{...s,ownerId:u}),s),getChatSession:async(u,id)=>data.sessions.get(`${u}:${id}`)||null,listChatSessions:async u=>[...data.sessions.values()].filter(x=>x.ownerId===u)};
const auth=createAuthService({store});
test("password and credential crypto",async()=>{const h=hashPassword("test-password-123");assert.notEqual(h,"test-password-123");assert.equal(verifyPassword("test-password-123",h),true);assert.equal(verifyPassword("wrong-password",h),false);const e=encryptSecret("ghp_example_secret_value");assert.equal(e.includes("ghp_example"),false);assert.equal(decryptSecret(e),"ghp_example_secret_value")});
test("owned sessions are isolated",async()=>{const a=await auth.register({email:"a@example.com",password:"password-a-123",name:"A"});const b=await auth.register({email:"b@example.com",password:"password-b-123",name:"B"});await store.putChatSession(a.id,{id:"chat-a",title:"A session",messages:[],memories:[]});assert.equal((await store.getChatSession(a.id,"chat-a")).ownerId,a.id);assert.equal(await store.getChatSession(b.id,"chat-a"),null);assert.equal((await store.listChatSessions(b.id)).length,0)});
test("auth session lifecycle",async()=>{const r=await auth.login({email:"a@example.com",password:"password-a-123"});assert.equal((await auth.authenticate(r.token)).user.email,"a@example.com");await auth.logout(r.token);await assert.rejects(()=>auth.authenticate(r.token))});

