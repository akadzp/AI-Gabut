export const MEDIA_ERRORS = Object.freeze({
  VALIDATION: "MEDIA_VALIDATION",
  NOT_FOUND: "MEDIA_NOT_FOUND",
  UNSUPPORTED: "MEDIA_UNSUPPORTED",
  DISABLED: "MEDIA_DISABLED",
  TIMEOUT: "MEDIA_TIMEOUT",
  PROCESSING: "MEDIA_PROCESSING",
  TRANSPORT: "MEDIA_TRANSPORT"
});

export class MediaError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "MediaError";
    this.code = code;
    this.details = details;
  }
}
