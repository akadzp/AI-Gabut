export const CONNECTOR_ERRORS = Object.freeze({
  VALIDATION: "CONNECTOR_VALIDATION",
  NOT_FOUND: "CONNECTOR_NOT_FOUND",
  DISABLED: "CONNECTOR_DISABLED",
  AUTH: "CONNECTOR_AUTH",
  RATE_LIMIT: "CONNECTOR_RATE_LIMIT",
  TIMEOUT: "CONNECTOR_TIMEOUT",
  TRANSPORT: "CONNECTOR_TRANSPORT",
  OPERATION: "CONNECTOR_OPERATION"
});

export class ConnectorError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "ConnectorError";
    this.code = code;
    this.details = details;
  }
}
