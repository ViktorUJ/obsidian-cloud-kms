import { describe, it, expect } from "vitest";
import {
  matchesEncryptedSuffix,
  matchesEncryptedAttachment,
} from "../../../src/policies/suffix-matcher";

describe("matchesEncryptedSuffix", () => {
  describe("case-sensitive suffix matching", () => {
    it("returns true when file name ends with the suffix", () => {
      expect(matchesEncryptedSuffix("notes.secret.md", ".secret.md")).toBe(true);
    });

    it("returns false when suffix case does not match", () => {
      expect(matchesEncryptedSuffix("notes.Secret.md", ".secret.md")).toBe(false);
    });

    it("returns false when suffix case differs in extension", () => {
      expect(matchesEncryptedSuffix("notes.secret.MD", ".secret.md")).toBe(false);
    });

    it("returns true when file name equals the suffix exactly", () => {
      expect(matchesEncryptedSuffix(".secret.md", ".secret.md")).toBe(true);
    });

    it("returns true for longer file names ending with suffix", () => {
      expect(
        matchesEncryptedSuffix("my-project/clients/acme.secret.md", ".secret.md")
      ).toBe(true);
    });

    it("returns false when suffix appears in the middle but not at end", () => {
      expect(
        matchesEncryptedSuffix(".secret.md.backup", ".secret.md")
      ).toBe(false);
    });
  });

  describe("default suffix", () => {
    it("uses .secret.md as default suffix", () => {
      expect(matchesEncryptedSuffix("notes.secret.md")).toBe(true);
    });

    it("does not match plain .md files with default suffix", () => {
      expect(matchesEncryptedSuffix("notes.md")).toBe(false);
    });
  });

  describe("custom suffixes", () => {
    it("matches custom suffix .encrypted.md", () => {
      expect(
        matchesEncryptedSuffix("data.encrypted.md", ".encrypted.md")
      ).toBe(true);
    });

    it("matches single character suffix", () => {
      expect(matchesEncryptedSuffix("file.x", ".x")).toBe(true);
    });
  });

  describe("edge cases", () => {
    it("returns false for empty file name", () => {
      expect(matchesEncryptedSuffix("", ".secret.md")).toBe(false);
    });

    it("returns false for empty suffix", () => {
      expect(matchesEncryptedSuffix("notes.secret.md", "")).toBe(false);
    });

    it("returns false when file name is shorter than suffix", () => {
      expect(matchesEncryptedSuffix("a.md", ".secret.md")).toBe(false);
    });
  });
});

describe("matchesEncryptedAttachment", () => {
  describe("case-insensitive matching", () => {
    it("matches .enc.png (lowercase)", () => {
      expect(matchesEncryptedAttachment("screenshot.enc.png")).toBe(true);
    });

    it("matches .ENC.PNG (uppercase)", () => {
      expect(matchesEncryptedAttachment("screenshot.ENC.PNG")).toBe(true);
    });

    it("matches .Enc.Jpg (mixed case)", () => {
      expect(matchesEncryptedAttachment("photo.Enc.Jpg")).toBe(true);
    });

    it("matches .enc.jpg", () => {
      expect(matchesEncryptedAttachment("photo.enc.jpg")).toBe(true);
    });

    it("matches .enc.pdf", () => {
      expect(matchesEncryptedAttachment("document.enc.pdf")).toBe(true);
    });

    it("matches .ENC.PDF (uppercase)", () => {
      expect(matchesEncryptedAttachment("document.ENC.PDF")).toBe(true);
    });
  });

  describe("non-matching files", () => {
    it("does not match plain .png", () => {
      expect(matchesEncryptedAttachment("screenshot.png")).toBe(false);
    });

    it("does not match .secret.md", () => {
      expect(matchesEncryptedAttachment("notes.secret.md")).toBe(false);
    });

    it("does not match unsupported encrypted extension .enc.gif", () => {
      expect(matchesEncryptedAttachment("animation.enc.gif")).toBe(false);
    });

    it("does not match .enc without extension", () => {
      expect(matchesEncryptedAttachment("file.enc")).toBe(false);
    });
  });

  describe("edge cases", () => {
    it("returns false for empty file name", () => {
      expect(matchesEncryptedAttachment("")).toBe(false);
    });

    it("matches when file name equals extension exactly", () => {
      expect(matchesEncryptedAttachment(".enc.png")).toBe(true);
    });
  });
});
