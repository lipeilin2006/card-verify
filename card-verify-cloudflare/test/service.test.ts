import test from "node:test";
import assert from "node:assert/strict";
import { stableJson } from "../src/util.ts";

test("signed request canonicalization is deterministic", () => {
  const data = { z: 1, a: { y: true, x: "value" } };
  assert.equal(stableJson(data), '{"a":{"x":"value","y":true},"z":1}');
});
