import assert from "node:assert/strict";
import {
  createMediaRegistry,
  createMediaRuntime,
  hashMediaBytes
} from "../../core/media/index.js";

const registry = createMediaRegistry();
const events = [];

registry.register(
  {
    id: "mock-media",
    name: "Mock Media Processor",
    mediaTypes: ["image", "audio"],
    operations: ["inspect", "transform"]
  },
  {
    execute: async ({ operation, media }) => ({
      operation: operation.type,
      mediaType: media.mediaType,
      checksum: media.checksum
    })
  }
);

const runtime = createMediaRuntime({
  registry,
  timeoutMs: 2_000,
  onEvent: async event => events.push(event)
});

const result = await runtime.execute({
  media: {
    id: "asset-1",
    mediaType: "image",
    mimeType: "image/png",
    size: 128,
    checksum: hashMediaBytes(Buffer.from("sample"))
  },
  operation: {
    processorId: "mock-media",
    name: "inspect-image",
    type: "inspect"
  }
});

assert.equal(result.ok, true);
assert.equal(result.result.mediaType, "image");
assert.equal(events[0].action, "start");
assert.equal(events.at(-1).action, "completed");

await assert.rejects(
  () => runtime.execute({
    media: { mediaType: "video", mimeType: "video/mp4" },
    operation: { processorId: "mock-media", name: "inspect-video", type: "inspect" }
  }),
  /tidak mendukung media type/
);

registry.seal();
assert.equal(registry.sealed, true);
assert.throws(
  () => registry.register(
    { id: "late", mediaTypes: ["image"], operations: ["inspect"] },
    { execute: async () => null }
  ),
  /sealed/
);

console.log("Media registry/runtime contract: PASS");
