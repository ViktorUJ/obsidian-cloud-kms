import { describe, it, expect } from 'vitest';
import {
  encodeInlineBlock,
  decodeInlineBlock,
  findInlineBlock,
} from '../../../src/format/inline-codec';
import { PluginError } from '../../../src/providers/errors';

describe('inline-codec', () => {
  describe('encodeInlineBlock', () => {
    it('should wrap binary data in ocke-v1 fenced block with base64', () => {
      const data = new Uint8Array([0x4f, 0x43, 0x4b, 0x45, 0x00, 0x01]);
      const result = encodeInlineBlock(data);

      expect(result).toBe('```ocke-v1\nT0NLRQAB\n```');
    });

    it('should handle empty Uint8Array', () => {
      const data = new Uint8Array([]);
      const result = encodeInlineBlock(data);

      expect(result).toBe('```ocke-v1\n\n```');
    });

    it('should handle large binary data', () => {
      const data = new Uint8Array(1024);
      for (let i = 0; i < data.length; i++) {
        data[i] = i % 256;
      }
      const result = encodeInlineBlock(data);

      expect(result.startsWith('```ocke-v1\n')).toBe(true);
      expect(result.endsWith('\n```')).toBe(true);
    });
  });

  describe('decodeInlineBlock', () => {
    it('should decode a valid ocke-v1 fenced block', () => {
      const text = '```ocke-v1\nT0NLRQAB\n```';
      const result = decodeInlineBlock(text);

      expect(result).toEqual(new Uint8Array([0x4f, 0x43, 0x4b, 0x45, 0x00, 0x01]));
    });

    it('should return null if no ocke-v1 block is found', () => {
      const text = 'Just some regular markdown text';
      const result = decodeInlineBlock(text);

      expect(result).toBeNull();
    });

    it('should return null for empty base64 content', () => {
      const text = '```ocke-v1\n\n```';
      const result = decodeInlineBlock(text);

      expect(result).toBeNull();
    });

    it('should throw PluginError on malformed base64', () => {
      const text = '```ocke-v1\n!!!invalid-base64!!!\n```';

      expect(() => decodeInlineBlock(text)).toThrow(PluginError);
      expect(() => decodeInlineBlock(text)).toThrow('Malformed base64 content');
    });

    it('should throw PluginError with format category on malformed base64', () => {
      const text = '```ocke-v1\n@#$%^&*\n```';

      try {
        decodeInlineBlock(text);
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(PluginError);
        expect((e as PluginError).category).toBe('format');
      }
    });

    it('should handle base64 with whitespace trimming', () => {
      const text = '```ocke-v1\n  T0NLRQAB  \n```';
      const result = decodeInlineBlock(text);

      expect(result).toEqual(new Uint8Array([0x4f, 0x43, 0x4b, 0x45, 0x00, 0x01]));
    });

    it('should decode block embedded in larger text', () => {
      const text = 'Some text before\n```ocke-v1\nT0NLRQAB\n```\nSome text after';
      const result = decodeInlineBlock(text);

      expect(result).toEqual(new Uint8Array([0x4f, 0x43, 0x4b, 0x45, 0x00, 0x01]));
    });
  });

  describe('findInlineBlock', () => {
    it('should find the first ocke-v1 block and return position', () => {
      const text = '```ocke-v1\nT0NLRQAB\n```';
      const result = findInlineBlock(text);

      expect(result).not.toBeNull();
      expect(result!.start).toBe(0);
      expect(result!.end).toBe(text.length);
      expect(result!.content).toBe('T0NLRQAB');
    });

    it('should return null if no block is found', () => {
      const text = 'No encrypted block here';
      const result = findInlineBlock(text);

      expect(result).toBeNull();
    });

    it('should find block embedded in surrounding text', () => {
      const prefix = 'Some markdown text\n\n';
      const block = '```ocke-v1\nT0NLRQAB\n```';
      const suffix = '\n\nMore text after';
      const text = prefix + block + suffix;

      const result = findInlineBlock(text);

      expect(result).not.toBeNull();
      expect(result!.start).toBe(prefix.length);
      expect(result!.end).toBe(prefix.length + block.length);
      expect(result!.content).toBe('T0NLRQAB');
    });

    it('should find only the first block when multiple exist', () => {
      const text = '```ocke-v1\nZmlyc3Q=\n```\n\n```ocke-v1\nc2Vjb25k\n```';
      const result = findInlineBlock(text);

      expect(result).not.toBeNull();
      expect(result!.content).toBe('Zmlyc3Q=');
    });

    it('should not match blocks with different language identifiers', () => {
      const text = '```javascript\nconsole.log("hello")\n```';
      const result = findInlineBlock(text);

      expect(result).toBeNull();
    });

    it('should correctly report positions for extracted content', () => {
      const text = 'Hello\n```ocke-v1\nYWJj\n```\nWorld';
      const result = findInlineBlock(text);

      expect(result).not.toBeNull();
      // Verify the extracted text matches what's at those positions
      expect(text.substring(result!.start, result!.end)).toBe('```ocke-v1\nYWJj\n```');
    });
  });

  describe('round-trip', () => {
    it('should encode and decode back to original data', () => {
      const original = new Uint8Array([1, 2, 3, 4, 5, 100, 200, 255]);
      const encoded = encodeInlineBlock(original);
      const decoded = decodeInlineBlock(encoded);

      expect(decoded).toEqual(original);
    });

    it('should round-trip binary data with all byte values', () => {
      const original = new Uint8Array(256);
      for (let i = 0; i < 256; i++) {
        original[i] = i;
      }
      const encoded = encodeInlineBlock(original);
      const decoded = decodeInlineBlock(encoded);

      expect(decoded).toEqual(original);
    });

    it('should round-trip when block is embedded in markdown', () => {
      const original = new Uint8Array([0x4f, 0x43, 0x4b, 0x45]);
      const encoded = encodeInlineBlock(original);
      const markdown = `# My Note\n\nSome text\n\n${encoded}\n\nMore text`;

      const found = findInlineBlock(markdown);
      expect(found).not.toBeNull();

      const decoded = decodeInlineBlock(markdown);
      expect(decoded).toEqual(original);
    });
  });
});
