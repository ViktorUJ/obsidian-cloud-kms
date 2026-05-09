import { describe, it, expect } from "vitest";
import { validateAwsKmsArn } from "../../../src/utils/arn-validator";

describe("validateAwsKmsArn", () => {
  describe("empty/whitespace input", () => {
    it("returns error for empty string", () => {
      const result = validateAwsKmsArn("");
      expect(result).toEqual({ valid: false, error: "ARN is required" });
    });

    it("returns error for whitespace-only string", () => {
      const result = validateAwsKmsArn("   ");
      expect(result).toEqual({ valid: false, error: "ARN is required" });
    });

    it("returns error for tab/newline whitespace", () => {
      const result = validateAwsKmsArn("\t\n ");
      expect(result).toEqual({ valid: false, error: "ARN is required" });
    });
  });

  describe("valid ARNs", () => {
    it("accepts a standard AWS KMS key ARN", () => {
      const result = validateAwsKmsArn(
        "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
      );
      expect(result).toEqual({ valid: true });
    });

    it("accepts ARN with different region", () => {
      const result = validateAwsKmsArn(
        "arn:aws:kms:eu-west-1:999888777666:key/abcdef01-2345-6789-abcd-ef0123456789"
      );
      expect(result).toEqual({ valid: true });
    });

    it("accepts ARN with non-UUID key-id", () => {
      const result = validateAwsKmsArn(
        "arn:aws:kms:ap-southeast-2:111222333444:key/mrk-some-multi-region-key"
      );
      expect(result).toEqual({ valid: true });
    });

    it("accepts ARN with alias-style key-id", () => {
      const result = validateAwsKmsArn(
        "arn:aws:kms:us-west-2:123456789012:key/alias-key-name"
      );
      expect(result).toEqual({ valid: true });
    });
  });

  describe("invalid ARN formats", () => {
    it("rejects ARN missing arn: prefix", () => {
      const result = validateAwsKmsArn(
        "aws:kms:us-east-1:123456789012:key/12345678"
      );
      expect(result).toEqual({
        valid: false,
        error: "Invalid AWS KMS key ARN format",
      });
    });

    it("rejects ARN with wrong service (not kms)", () => {
      const result = validateAwsKmsArn(
        "arn:aws:s3:us-east-1:123456789012:key/12345678"
      );
      expect(result).toEqual({
        valid: false,
        error: "Invalid AWS KMS key ARN format",
      });
    });

    it("rejects ARN with non-12-digit account ID", () => {
      const result = validateAwsKmsArn(
        "arn:aws:kms:us-east-1:12345:key/12345678"
      );
      expect(result).toEqual({
        valid: false,
        error: "Invalid AWS KMS key ARN format",
      });
    });

    it("rejects ARN with 13-digit account ID", () => {
      const result = validateAwsKmsArn(
        "arn:aws:kms:us-east-1:1234567890123:key/12345678"
      );
      expect(result).toEqual({
        valid: false,
        error: "Invalid AWS KMS key ARN format",
      });
    });

    it("rejects ARN with non-numeric account ID", () => {
      const result = validateAwsKmsArn(
        "arn:aws:kms:us-east-1:12345678901a:key/12345678"
      );
      expect(result).toEqual({
        valid: false,
        error: "Invalid AWS KMS key ARN format",
      });
    });

    it("rejects ARN missing key/ prefix in resource", () => {
      const result = validateAwsKmsArn(
        "arn:aws:kms:us-east-1:123456789012:alias/my-key"
      );
      expect(result).toEqual({
        valid: false,
        error: "Invalid AWS KMS key ARN format",
      });
    });

    it("rejects ARN with empty region", () => {
      const result = validateAwsKmsArn(
        "arn:aws:kms::123456789012:key/12345678"
      );
      expect(result).toEqual({
        valid: false,
        error: "Invalid AWS KMS key ARN format",
      });
    });

    it("rejects ARN with empty key-id", () => {
      const result = validateAwsKmsArn(
        "arn:aws:kms:us-east-1:123456789012:key/"
      );
      expect(result).toEqual({
        valid: false,
        error: "Invalid AWS KMS key ARN format",
      });
    });

    it("rejects random string", () => {
      const result = validateAwsKmsArn("not-an-arn-at-all");
      expect(result).toEqual({
        valid: false,
        error: "Invalid AWS KMS key ARN format",
      });
    });
  });
});
