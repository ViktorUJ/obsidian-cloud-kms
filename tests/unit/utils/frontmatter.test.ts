import { describe, it, expect } from 'vitest';
import { splitFrontmatter } from '../../../src/utils/frontmatter';

describe('splitFrontmatter', () => {
  describe('notes with valid frontmatter', () => {
    it('splits a note with frontmatter and body', () => {
      const content = '---\ntitle: Hello\ntags: [test]\n---\nThis is the body.';
      const result = splitFrontmatter(content);

      expect(result.frontmatter).toBe('---\ntitle: Hello\ntags: [test]\n---\n');
      expect(result.body).toBe('This is the body.');
    });

    it('preserves frontmatter delimiters in the returned frontmatter', () => {
      const content = '---\nkey: value\n---\nbody content';
      const result = splitFrontmatter(content);

      expect(result.frontmatter!.startsWith('---\n')).toBe(true);
      expect(result.frontmatter!.endsWith('\n---\n')).toBe(true);
    });

    it('handles frontmatter with empty body', () => {
      const content = '---\ntitle: Test\n---\n';
      const result = splitFrontmatter(content);

      expect(result.frontmatter).toBe('---\ntitle: Test\n---\n');
      expect(result.body).toBe('');
    });

    it('handles frontmatter with multi-line body', () => {
      const content = '---\ntitle: Test\n---\nLine 1\nLine 2\nLine 3';
      const result = splitFrontmatter(content);

      expect(result.frontmatter).toBe('---\ntitle: Test\n---\n');
      expect(result.body).toBe('Line 1\nLine 2\nLine 3');
    });

    it('handles frontmatter ending at EOF without trailing newline', () => {
      const content = '---\ntitle: Test\n---';
      const result = splitFrontmatter(content);

      expect(result.frontmatter).toBe('---\ntitle: Test\n---');
      expect(result.body).toBe('');
    });

    it('handles frontmatter with --- in the YAML values', () => {
      const content = '---\ntitle: A---B\ndesc: test\n---\nbody here';
      const result = splitFrontmatter(content);

      expect(result.frontmatter).toBe('---\ntitle: A---B\ndesc: test\n---\n');
      expect(result.body).toBe('body here');
    });

    it('handles frontmatter with empty YAML content', () => {
      const content = '---\n\n---\nbody';
      const result = splitFrontmatter(content);

      expect(result.frontmatter).toBe('---\n\n---\n');
      expect(result.body).toBe('body');
    });
  });

  describe('notes without frontmatter', () => {
    it('returns null frontmatter and entire content as body for plain text', () => {
      const content = 'This is just a plain note.';
      const result = splitFrontmatter(content);

      expect(result.frontmatter).toBeNull();
      expect(result.body).toBe(content);
    });

    it('returns null frontmatter for empty content', () => {
      const result = splitFrontmatter('');

      expect(result.frontmatter).toBeNull();
      expect(result.body).toBe('');
    });

    it('returns null frontmatter when --- is not at position 0', () => {
      const content = ' ---\ntitle: Test\n---\nbody';
      const result = splitFrontmatter(content);

      expect(result.frontmatter).toBeNull();
      expect(result.body).toBe(content);
    });

    it('returns null frontmatter when opening --- has no newline after it', () => {
      const content = '---title: Test\n---\nbody';
      const result = splitFrontmatter(content);

      expect(result.frontmatter).toBeNull();
      expect(result.body).toBe(content);
    });

    it('returns null frontmatter when no closing delimiter is found', () => {
      const content = '---\ntitle: Test\nno closing delimiter here';
      const result = splitFrontmatter(content);

      expect(result.frontmatter).toBeNull();
      expect(result.body).toBe(content);
    });

    it('returns null frontmatter for content that is just ---\\n', () => {
      const content = '---\n';
      const result = splitFrontmatter(content);

      expect(result.frontmatter).toBeNull();
      expect(result.body).toBe(content);
    });
  });

  describe('edge cases', () => {
    it('handles body containing --- patterns', () => {
      const content = '---\ntitle: Test\n---\nBody with --- in it\nAnd more ---';
      const result = splitFrontmatter(content);

      expect(result.frontmatter).toBe('---\ntitle: Test\n---\n');
      expect(result.body).toBe('Body with --- in it\nAnd more ---');
    });

    it('uses the first valid closing delimiter', () => {
      const content = '---\ntitle: Test\n---\nbody\n---\nmore body';
      const result = splitFrontmatter(content);

      expect(result.frontmatter).toBe('---\ntitle: Test\n---\n');
      expect(result.body).toBe('body\n---\nmore body');
    });

    it('handles frontmatter with special characters in values', () => {
      const content = '---\ntitle: "Hello: World"\ntags: [a, b, c]\n---\nbody';
      const result = splitFrontmatter(content);

      expect(result.frontmatter).toBe('---\ntitle: "Hello: World"\ntags: [a, b, c]\n---\n');
      expect(result.body).toBe('body');
    });

    it('reconstructs original content from frontmatter + body', () => {
      const content = '---\ntitle: Test\n---\nHello world';
      const result = splitFrontmatter(content);

      const reconstructed = (result.frontmatter ?? '') + result.body;
      expect(reconstructed).toBe(content);
    });

    it('reconstructs original content when no frontmatter', () => {
      const content = 'Just a plain note';
      const result = splitFrontmatter(content);

      const reconstructed = (result.frontmatter ?? '') + result.body;
      expect(reconstructed).toBe(content);
    });
  });
});
