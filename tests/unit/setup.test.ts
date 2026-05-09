import { describe, it, expect } from "vitest";

describe("project setup", () => {
  it("vitest runs successfully", () => {
    expect(1 + 1).toBe(2);
  });

  it("TypeScript types work", () => {
    const value: number = 42;
    expect(value).toBe(42);
  });
});
