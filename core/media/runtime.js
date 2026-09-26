import { MediaError, MEDIA_ERRORS } from "./errors.js";
import { normalizeMediaDescriptor, normalizeMediaOperation } from "./contracts.js";

const DEFAULT_TIMEOUT_MS = 60_000;

export function createMediaRuntime({
  registry,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  onEvent = null
} = {}) {
  if (!registry || typeof registry.resolve !== "function") {
    throw new MediaError(MEDIA_ERRORS.VALIDATION, "Media registry wajib tersedia");
  }

  async function emit(event) {
    if (typeof onEvent === "function") {
      await onEvent({ at: new Date().toISOString(), ...event });
    }
  }

  async function execute({ operation = {}, media = {} } = {}) {
    const normalizedOperation = normalizeMediaOperation(operation);
    const descriptor = normalizeMediaDescriptor(media);
    const entry = registry.resolve(normalizedOperation.processorId);

    if (!entry.definition.mediaTypes.includes(descriptor.mediaType)) {
      throw new MediaError(
        MEDIA_ERRORS.UNSUPPORTED,
        `Processor ${normalizedOperation.processorId} tidak mendukung media type ${descriptor.mediaType}`
      );
    }

    if (!entry.definition.operations.includes(normalizedOperation.type)) {
      throw new MediaError(
        MEDIA_ERRORS.UNSUPPORTED,
        `Processor ${normalizedOperation.processorId} tidak mendukung operation ${normalizedOperation.type}`
      );
    }

    if (entry.definition.metadata.enabled === false) {
      throw new MediaError(MEDIA_ERRORS.DISABLED, `Processor disabled: ${normalizedOperation.processorId}`);
    }

    const timeout = Math.max(100, Number(timeoutMs) || DEFAULT_TIMEOUT_MS);

    await emit({
      processorId: normalizedOperation.processorId,
      mediaId: descriptor.id,
      mediaType: descriptor.mediaType,
      operation: normalizedOperation.name,
      type: normalizedOperation.type,
      action: "start"
    });

    try {
      const result = await Promise.race([
        entry.processor.execute({
          operation: normalizedOperation,
          media: descriptor
        }),
        new Promise((_, reject) => {
          setTimeout(
            () => reject(new MediaError(MEDIA_ERRORS.TIMEOUT, `Media processing timeout setelah ${timeout}ms`)),
            timeout
          );
        })
      ]);

      await emit({
        processorId: normalizedOperation.processorId,
        mediaId: descriptor.id,
        mediaType: descriptor.mediaType,
        operation: normalizedOperation.name,
        type: normalizedOperation.type,
        action: "completed"
      });

      return {
        ok: true,
        processorId: normalizedOperation.processorId,
        media: descriptor,
        operation: normalizedOperation.name,
        type: normalizedOperation.type,
        result
      };
    } catch (error) {
      await emit({
        processorId: normalizedOperation.processorId,
        mediaId: descriptor.id,
        mediaType: descriptor.mediaType,
        operation: normalizedOperation.name,
        type: normalizedOperation.type,
        action: "failed",
        error: error instanceof Error ? error.message : String(error)
      });

      if (error instanceof MediaError) throw error;
      throw new MediaError(MEDIA_ERRORS.PROCESSING, "Media processing gagal", {
        cause: error instanceof Error ? error.message : String(error)
      });
    }
  }

  return Object.freeze({ execute });
}
