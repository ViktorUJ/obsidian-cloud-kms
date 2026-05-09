/**
 * Mock for the 'obsidian' module used in tests.
 * Provides minimal stubs for Obsidian API classes and functions.
 */

import { vi } from 'vitest';

/**
 * Helper to create a mock HTML element with nested createEl support.
 */
function createMockEl(_tag: string, _opts?: any): any {
  return {
    style: {},
    textContent: _opts?.text || '',
    className: _opts?.cls || '',
    empty: vi.fn(),
    remove: vi.fn(),
    createEl: (_t: string, _o?: any) => createMockEl(_t, _o),
  };
}

export class Notice {
  constructor(public message: string, public duration?: number) {}
}

export class ItemView {
  leaf: any;
  containerEl: any;
  app: any;

  constructor(leaf?: any) {
    this.leaf = leaf;
    this.containerEl = {
      children: [
        null,
        {
          empty: vi.fn(),
          createEl: (_tag: string, _opts?: any) => createMockEl(_tag, _opts),
        },
      ],
    };
    this.app = leaf?.app ?? new App();
  }

  getViewType(): string { return ''; }
  getDisplayText(): string { return ''; }
  getIcon(): string { return ''; }
  async onOpen(): Promise<void> {}
  async onClose(): Promise<void> {}
  getState(): Record<string, unknown> { return {}; }
  async setState(_state: any, _result?: any): Promise<void> {}
}

export class WorkspaceLeaf {
  view: any = null;
  app: any;

  constructor(app?: any) {
    this.app = app ?? new App();
  }

  async setViewState(_state: any): Promise<void> {}
}

export class Plugin {
  app = {
    vault: {
      getName: () => 'test-vault',
    },
    workspace: {
      detachLeavesOfType: vi.fn(),
      getLeaf: vi.fn(),
      revealLeaf: vi.fn(),
    },
  };
  addCommand = vi.fn();
  register = vi.fn();
  registerView = vi.fn();
  registerExtensions = vi.fn();
  registerEvent = vi.fn();
}

export class PluginSettingTab {
  app: any;
  containerEl: any;
  constructor(app: any, plugin: any) {
    this.app = app;
    this.containerEl = {
      empty() {},
      createEl(_tag: string, _opts?: any) {
        return {
          empty() {},
          createEl(_tag2: string, _opts2?: any) {
            return { style: {}, textContent: _opts2?.text || "", className: _opts2?.cls || "", remove() {} };
          },
          style: {},
          textContent: _opts?.text || "",
          className: _opts?.cls || "",
          remove() {},
        };
      },
    };
  }
  display() {}
  hide() {}
}

export class Setting {
  settingEl = document.createElement('div');
  controlEl: any;
  constructor(containerEl: any) {
    this.controlEl = {
      createEl(_tag: string, _opts?: any) {
        return { style: {}, textContent: _opts?.text || "", className: _opts?.cls || "", remove() {} };
      },
    };
  }
  setName(_name: string) { return this; }
  setDesc(_desc: string) { return this; }
  addText(cb: (text: any) => void) {
    const textComponent: any = {
      inputEl: { maxLength: 0, style: {} },
      _value: "",
      _onChange: null as ((value: string) => void) | null,
      setPlaceholder(_p: string) { return textComponent; },
      setValue(v: string) { textComponent._value = v; return textComponent; },
      getValue() { return textComponent._value; },
      onChange(fn: (value: string) => void) { textComponent._onChange = fn; return textComponent; },
    };
    cb(textComponent);
    return this;
  }
  addToggle(_cb: any) { return this; }
  addDropdown(_cb: any) { return this; }
  addButton(_cb: any) { return this; }
}

export class App {
  vault = {
    getName: () => 'test-vault',
    read: vi.fn(async () => ''),
    readBinary: vi.fn(async () => new ArrayBuffer(0)),
    adapter: {
      writeBinary: vi.fn(),
      rename: vi.fn(),
      remove: vi.fn(),
    },
  };
  workspace = {
    on: vi.fn(),
    getActiveViewOfType: vi.fn(),
    getLeaf: vi.fn(),
  };
}

export class TAbstractFile {
  path = '';
  name = '';
}

export class TFile extends TAbstractFile {
  extension = 'md';
  basename = '';
  stat = { ctime: 0, mtime: 0, size: 0 };
  vault: any = null;
  parent: any = null;
}

export class Vault {
  adapter = {
    writeBinary: vi.fn(),
    rename: vi.fn(),
    remove: vi.fn(),
  };
  read = vi.fn();
  getName() { return 'test-vault'; }
  on = vi.fn();
}

export class Editor {
  getSelection() { return ''; }
  replaceSelection(_text: string) {}
  getCursor() { return { line: 0, ch: 0 }; }
}

export class MarkdownView {
  file = { path: 'test.md' };
  app = new App();
  editor = new Editor();
}
