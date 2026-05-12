/**
 * Test setup — polyfill window for Obsidian plugin compatibility.
 * Obsidian plugins use window.setTimeout/window.clearTimeout,
 * but tests run in Node.js where window doesn't exist.
 */

if (typeof globalThis.window === 'undefined') {
  // Create a proxy that always delegates to globalThis
  // This ensures vi.useFakeTimers() works correctly
  (globalThis as any).window = new Proxy(globalThis, {
    get(target, prop) {
      return (target as any)[prop];
    }
  });
}

if (typeof globalThis.activeDocument === 'undefined') {
  (globalThis as any).activeDocument = {
    querySelectorAll: () => [],
    createElement: (tag: string) => ({ id: '', textContent: '', style: {} }),
    head: { appendChild: () => {} },
    getElementById: () => null,
  };
}
