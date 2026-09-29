function normalizeOrigin(value){
  return String(value||"").trim().replace(/\/+$/,"");
}

export function loadAgenticDeployment(env=process.env,overrides={}) {
  const configured=String(env.AGENTIC_ALLOWED_ORIGINS||"").split(",").map(normalizeOrigin).filter(Boolean);
  const topology=env.AGENTIC_TOPOLOGY==="split"?"split":"same-origin";
  const config={
    topology,
    allowedOrigins:configured,
    apiBaseUrl:normalizeOrigin(env.AGENTIC_API_BASE_URL||""),
    trustProxy:env.AGENTIC_TRUST_PROXY==="true",
    bodyLimit:env.AGENTIC_BODY_LIMIT||"1mb",
    startupValidation:env.AGENTIC_STARTUP_VALIDATION!=="false",
    ...overrides
  };
  if(config.topology==="split"&&!config.allowedOrigins.length) throw new Error("AGENTIC_ALLOWED_ORIGINS wajib diisi pada topology split");
  if(config.apiBaseUrl&&!/^https?:\/\//i.test(config.apiBaseUrl)) throw new Error("AGENTIC_API_BASE_URL harus berupa http(s) URL");
  return Object.freeze(config);
}

export function assertAllowedOrigin(origin,config) {
  if(!origin) return true;
  const normalized=normalizeOrigin(origin);
  if(config.allowedOrigins.includes("*")) return true;
  return config.allowedOrigins.includes(normalized);
}

export function getSecurityHeaders({split=false}={}) {
  return Object.freeze({
    "X-Content-Type-Options":"nosniff",
    "X-Frame-Options":"DENY",
    "Referrer-Policy":"no-referrer",
    ...(split?{"Content-Security-Policy":"default-src 'self'; connect-src 'self' https:; frame-ancestors 'none'"}:{})
  });
}
