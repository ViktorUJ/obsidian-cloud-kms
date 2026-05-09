/**
 * AWS KMS ARN format validator.
 *
 * Validates that a string conforms to the AWS KMS key ARN pattern:
 *   arn:aws:kms:{region}:{account-id}:key/{key-id}
 *
 * Where:
 *   - region is a non-empty string
 *   - account-id is a 12-digit numeric string
 *   - key-id is a non-empty string
 */

/**
 * Result of ARN validation.
 */
export interface ArnValidationResult {
  valid: boolean;
  error?: string;
}

/**
 * Regex pattern for AWS KMS key ARN.
 * Format: arn:aws:kms:{region}:{12-digit-account}:key/{key-id}
 */
const AWS_KMS_ARN_PATTERN = /^arn:aws:kms:[^:]+:\d{12}:key\/.+$/;

/**
 * Validates an AWS KMS key ARN string.
 *
 * @param arn - The ARN string to validate
 * @returns Validation result with optional error message
 */
export function validateAwsKmsArn(arn: string): ArnValidationResult {
  if (!arn || arn.trim().length === 0) {
    return { valid: false, error: "ARN is required" };
  }

  if (!AWS_KMS_ARN_PATTERN.test(arn)) {
    return { valid: false, error: "Invalid AWS KMS key ARN format" };
  }

  return { valid: true };
}
