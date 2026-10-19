export class AgenticError extends Error { constructor(code,message,status=400){super(message);this.name='AgenticError';this.code=code;this.status=status;} }
