# Requirements Document

## Introduction

The `obsidian-cloud-kms-encryption` feature delivers an Obsidian plugin that provides
file-level envelope encryption of vault content (Markdown notes and binary attachments)
using Cloud KMS services (AWS KMS, Azure Key Vault, Google Cloud KMS) as the root of
trust for Customer Master Keys (CMKs). The plugin targets DevOps/SRE engineers who
store multi-client project documentation in Obsidian vaults backed by S3 or Git and
who require Zero Trust storage: no plaintext content must ever be written to persistent
storage, and access to content must be gated by identity-based cloud credentials
(AWS SSO, IAM Roles, Azure AD, Google Cloud IAM) rather than user-managed passwords.

The feature is delivered in three phases:

- **Phase 1 (PoC)**: Manual, command-triggered encryption and decryption of selected
  text against a single hardcoded AWS KMS CMK.
- **Phase 2 (MVP)**: Automatic transparent encryption of Markdown files matching a
  configurable suffix pattern (for example `*.secret.md`) plus basic encrypted image
  preview, still on AWS KMS.
- **Phase 3 (Advanced)**: Pluggable multi-provider KMS support (AWS, Azure, GCP) and
  per-folder "Encrypted Vault" policies for multi-client isolation.

Cross-cutting non-functional requirements cover security (Zero Trust, no cleartext on
disk), performance (interactive latency budgets), observability (Access Transparency
via cloud audit logs), and extensibility (modular provider architecture).

This document also enumerates correctness properties intended to be verified through
Property-Based Testing (PBT), including encrypt/decrypt round-trip invariants,
ciphertext stability in the absence of KMS access, and the non-leakage of plaintext
into persisted artifacts.

## Glossary

- **Plugin**: The Obsidian plugin implemented by this feature, running inside the
  Obsidian desktop application on the user's machine.
- **Vault**: An Obsidian vault: a directory tree on the user's local file system
  (optionally backed by S3 or Git) containing Markdown notes and binary attachments.
- **Note**: A UTF-8 encoded Markdown file (`.md`) inside a Vault.
- **Attachment**: A binary file inside a Vault, such as PNG, JPEG, PDF, or audio.
- **Frontmatter**: The YAML block at the top of a Markdown note between `---`
  delimiters, used by Obsidian for metadata, tags, and indexing.
- **Body**: The portion of a Markdown note following the Frontmatter.
- **DEK**: Data Encryption Key. A 256-bit symmetric key generated locally by the
  Plugin and used for AES-256-GCM encryption of Note body or Attachment content.
- **CMK**: Customer Master Key. A symmetric key managed by Cloud KMS (for example
  an AWS KMS key identified by ARN, an Azure Key Vault key, or a Google Cloud KMS
  key) that never leaves the Cloud KMS service.
- **KMS**: Cloud Key Management Service, referring to any of AWS KMS, Azure Key
  Vault, or Google Cloud KMS.
- **Envelope Encryption**: The encryption scheme in which a locally generated DEK
  encrypts the payload and the DEK itself is encrypted ("wrapped") by a CMK held in
  Cloud KMS.
- **Wrapped DEK**: The ciphertext produced by the CMK encrypting the DEK.
- **Nonce**: A 96-bit initialization vector used once per DEK for AES-256-GCM.
- **Encrypted File**: A file on disk containing the Wrapped DEK, the Nonce, the
  AES-256-GCM ciphertext of the payload, and an authentication tag, serialized in a
  documented on-disk format.
- **On-Disk Format**: The documented binary or text layout used to serialize an
  Encrypted File, including magic bytes, version field, provider identifier, CMK
  identifier, Wrapped DEK, Nonce, authentication tag, and ciphertext.
- **Plaintext**: The original unencrypted Note body or Attachment bytes.
- **Ciphertext**: The AES-256-GCM encrypted form of the Plaintext.
- **Cloud Credentials**: Identity-based credentials resolved by the Cloud SDK from
  the local environment (AWS SSO profile, IAM Role, Azure AD token, Google Cloud
  Application Default Credentials).
- **Provider Adapter**: A module implementing a uniform KMS interface
  (`generateDataKey`, `encrypt`, `decrypt`) for a specific Cloud KMS provider.
- **Encrypted Vault Policy**: A per-folder configuration binding a folder path to
  a specific Provider Adapter and CMK identifier.
- **Zero Trust Storage**: A storage model in which persistent storage (disk, S3,
  Git remote) is assumed untrusted and must never contain Plaintext.
- **Access Transparency**: The property that every DEK unwrap (decryption) call to
  the CMK is recorded in the cloud provider's audit log (for example AWS
  CloudTrail).
- **PoC**: Phase 1 deliverable, Proof of Concept on AWS only.
- **MVP**: Phase 2 deliverable, Minimum Viable Product with transparent file
  encryption on AWS.
- **Advanced**: Phase 3 deliverable, multi-provider and per-folder policies.

## Requirements

### Phase 1 — PoC (AWS)

#### Requirement 1: Manual Text Encryption Command

**User Story:** As a DevOps engineer, I want to encrypt a selected block of
Markdown text against a hardcoded AWS KMS CMK via a command, so that I can validate
envelope encryption end to end before investing in deeper integration.

##### Acceptance Criteria

1. THE Plugin SHALL register an Obsidian command named "Encrypt selection with AWS
   KMS" in the command palette, available only when an active Markdown editor
   view is focused.
2. WHEN the user invokes the "Encrypt selection with AWS KMS" command with a text
   selection of between 1 and 1,048,576 characters in the active Markdown editor,
   THE Plugin SHALL generate a fresh 256-bit DEK locally using a cryptographically
   secure random source.
3. WHEN the "Encrypt selection with AWS KMS" command is invoked with a configured
   CMK ARN available, THE Plugin SHALL call AWS KMS `GenerateDataKey` or `Encrypt`
   against the configured CMK ARN to obtain the Wrapped DEK, completing the call
   within 10 seconds.
4. WHEN the DEK is available, THE Plugin SHALL encrypt the selected text with
   AES-256-GCM using a freshly generated 96-bit Nonce from a cryptographically
   secure random source and produce a 128-bit authentication tag.
5. WHEN encryption succeeds, THE Plugin SHALL replace only the selected text in
   the editor with a single serialized Encrypted File block containing the
   provider identifier, CMK ARN, Wrapped DEK, Nonce, authentication tag, and
   Ciphertext, leaving all surrounding document content unchanged.
6. IF the "Encrypt selection with AWS KMS" command is invoked with no active
   Markdown editor, with an empty selection, or with a selection exceeding
   1,048,576 characters, THEN THE Plugin SHALL abort the command and display an
   Obsidian notice describing the condition for at least 5 seconds.
7. IF the "Encrypt selection with AWS KMS" command is invoked when no CMK ARN is
   configured, THEN THE Plugin SHALL abort the command without calling AWS KMS and
   display an Obsidian notice instructing the user to configure the CMK ARN for at
   least 5 seconds.
8. IF AWS KMS returns an error, the AWS KMS call exceeds the 10-second timeout, or
   local AES-256-GCM encryption fails during the "Encrypt selection with AWS KMS"
   command, THEN THE Plugin SHALL leave the selected text unchanged, discard any
   generated DEK from process memory, and display an Obsidian notice describing
   the failure category for at least 5 seconds.

#### Requirement 2: Manual Text Decryption Command

**User Story:** As a DevOps engineer, I want to decrypt a previously encrypted
block in-place, so that I can read the original content during the PoC.

##### Acceptance Criteria

1. WHEN the Plugin finishes loading, THE Plugin SHALL register an Obsidian command
   named "Decrypt selection with AWS KMS" in the command palette.
2. WHEN the user invokes the "Decrypt selection with AWS KMS" command with a
   non-empty selection containing a serialized Encrypted File block in which all
   required fields (block start and end markers, Wrapped DEK, Nonce, Ciphertext,
   and authentication tag) are present and parseable, THE Plugin SHALL call AWS
   KMS `Decrypt` against the Wrapped DEK to obtain the DEK, completing the call
   within 10 seconds.
3. WHEN the DEK is unwrapped, THE Plugin SHALL decrypt the Ciphertext with
   AES-256-GCM using the stored Nonce and verify the authentication tag.
4. WHEN decryption and authentication tag verification both succeed, THE Plugin
   SHALL replace the selected Encrypted File block with the original Plaintext in
   the active editor buffer without writing changes to disk until the user
   explicitly saves the file.
5. IF the AES-256-GCM authentication tag verification fails, THEN THE Plugin
   SHALL leave the selected text unchanged and display an "Integrity check
   failed" notice in the Obsidian UI for at least 5 seconds.
6. IF AWS KMS returns an error during the "Decrypt selection with AWS KMS"
   command, THEN THE Plugin SHALL leave the selected text unchanged and display
   an Obsidian notice containing the provider error message for at least 5
   seconds.
7. IF the user invokes the "Decrypt selection with AWS KMS" command when the
   selection is empty or does not contain a parseable serialized Encrypted File
   block as defined in criterion 2, THEN THE Plugin SHALL leave the editor buffer
   unchanged and display a notice indicating that no valid Encrypted File block
   is selected for at least 5 seconds.
8. IF the AWS KMS `Decrypt` call does not return a response within 10 seconds,
   THEN THE Plugin SHALL abort the operation, leave the selected text unchanged,
   and display a notice indicating that the decryption request timed out for at
   least 5 seconds.

#### Requirement 3: Identity-Based AWS Credential Resolution

**User Story:** As a DevOps engineer, I want the Plugin to use my existing AWS
SSO or IAM Role credentials, so that I never enter or store a password inside
Obsidian.

##### Acceptance Criteria

1. THE Plugin SHALL resolve AWS credentials exclusively through the AWS SDK
   default credential provider chain (environment variables, shared config files,
   SSO cache, IAM Role), completing the resolution within 10 seconds per attempt.
2. THE Plugin SHALL NOT read, store, or prompt for AWS access keys, secret keys,
   or session tokens through its own user interface, and SHALL NOT persist any
   resolved credential material to disk, logs, or telemetry.
3. IF the AWS SDK default credential provider chain yields no credentials or
   exceeds the 10-second resolution timeout, THEN THE Plugin SHALL display a
   notice instructing the user to configure AWS SSO or IAM Role credentials,
   SHALL abort the in-progress encryption or decryption command, and SHALL leave
   the editor buffer and any targeted file on disk unchanged.
4. IF AWS KMS rejects a request with an authentication, authorization, or expired
   credential error, THEN THE Plugin SHALL abort the in-progress encryption or
   decryption command, display a notice identifying the credential failure for
   at least 5 seconds, and leave the editor buffer and any targeted file on disk
   unchanged.

#### Requirement 4: Hardcoded PoC CMK Configuration

**User Story:** As a DevOps engineer running the PoC, I want a single CMK ARN
configured in plugin settings, so that I can exercise the flow without building
a full configuration system.

##### Acceptance Criteria

1. THE Plugin SHALL expose a single text input field labeled "AWS KMS Key ARN"
   in its settings tab that accepts up to 512 characters.
2. WHEN the "AWS KMS Key ARN" field value is empty or contains only whitespace
   characters, THE Plugin SHALL disable the "Encrypt selection with AWS KMS" and
   "Decrypt selection with AWS KMS" commands such that invoking either command
   from the command palette produces no encryption or decryption action.
3. IF the "AWS KMS Key ARN" field contains a non-empty value that does not
   conform to the AWS KMS key ARN format
   `arn:aws:kms:{region}:{account-id}:key/{key-id}` where region is a non-empty
   string, account-id is a 12-digit numeric string, and key-id is a non-empty
   string, THEN THE Plugin SHALL display a validation error message in the
   settings tab indicating the ARN format is invalid and SHALL keep the "Encrypt
   selection with AWS KMS" and "Decrypt selection with AWS KMS" commands
   disabled.
4. WHEN the "AWS KMS Key ARN" field contains a value that conforms to the AWS
   KMS key ARN format defined in criterion 3, THE Plugin SHALL remove any
   previously displayed validation error from the settings tab and enable the
   "Encrypt selection with AWS KMS" and "Decrypt selection with AWS KMS"
   commands.
5. WHEN the user changes the "AWS KMS Key ARN" field value, THE Plugin SHALL
   persist the updated value such that the same value is loaded on subsequent
   plugin initializations and Obsidian restarts.

### Phase 2 — MVP (Transparent File Encryption on AWS)

#### Requirement 5: Suffix-Based Transparent Note Encryption

**User Story:** As a DevOps engineer, I want notes with a configured suffix to
be automatically encrypted on save, so that sensitive notes are protected
without manual commands.

##### Acceptance Criteria

1. THE Plugin SHALL expose a settings field "Encrypted note suffix" that accepts
   a non-empty string of 1 to 64 characters with a default value of `.secret.md`,
   and IF the user submits a value that is empty or exceeds 64 characters, THEN
   THE Plugin SHALL reject the change and display an error message indicating
   the invalid length.
2. WHEN a Note whose file name ends with the configured "Encrypted note suffix"
   using a case-sensitive exact suffix match on the full file name including
   extension is saved by Obsidian, THE Plugin SHALL intercept the write
   operation before the Plaintext Body is persisted to disk.
3. WHEN intercepting a save of a suffix-matching Note that contains a
   Frontmatter block, THE Plugin SHALL preserve the Frontmatter as Plaintext in
   the output and encrypt only the Body using envelope encryption against the
   configured CMK.
4. WHEN intercepting a save of a suffix-matching Note that contains no
   Frontmatter block, THE Plugin SHALL encrypt the entire Note content as the
   Body using envelope encryption against the configured CMK.
5. WHEN intercepting a save of a suffix-matching Note, THE Plugin SHALL write a
   file at the original Note path whose contents consist of the Plaintext
   Frontmatter (if any) followed by a single serialized Encrypted File block
   representing the Body, and SHALL ensure the previous on-disk contents of the
   Note remain unchanged if the write does not complete successfully.
6. IF no CMK is configured or the encryption operation fails when intercepting a
   save of a suffix-matching Note, THEN THE Plugin SHALL abort the write, leave
   the previous on-disk contents of the Note unchanged, and display an error
   message identifying the affected Note and the failure category.
7. WHEN a suffix-matching Note is opened in Obsidian, THE Plugin SHALL detect
   the serialized Encrypted File block, unwrap the DEK via AWS KMS within 10
   seconds, decrypt the Body in memory, and present the concatenation of the
   Plaintext Frontmatter and decrypted Body to the editor.
8. IF decryption of a suffix-matching Note fails for any reason, including KMS
   unavailability, KMS request timeout exceeding 10 seconds, DEK unwrap failure,
   CMK access denial, or ciphertext integrity failure, THEN THE Plugin SHALL
   open the Note in a read-only view displaying the raw on-disk content and an
   error banner identifying the affected Note and the failure category.

#### Requirement 6: Encrypted Attachment Preview

**User Story:** As a DevOps engineer, I want encrypted images in my vault to
render in preview, so that I can view screenshots without leaving Obsidian.

##### Acceptance Criteria

1. THE Plugin SHALL register handling for Attachments whose file names end, with
   case-insensitive matching, in `.enc.png`, `.enc.jpg`, or `.enc.pdf`.
2. WHEN an Attachment with a registered encrypted extension of at most 50 MB on
   disk is requested by the Obsidian renderer, THE Plugin SHALL read the
   Encrypted File from disk, unwrap the DEK via AWS KMS completing the call
   within 10 seconds, decrypt the payload in memory, and expose the Plaintext
   bytes to the renderer through a Blob URL whose backing buffer is retained
   only in process memory.
3. WHEN every Obsidian view that referenced a decrypted Attachment has been
   closed, THE Plugin SHALL revoke the corresponding Blob URL and release the
   associated in-memory Plaintext buffer within 5 seconds of the last close
   event.
4. THE Plugin SHALL NOT write the decrypted bytes of any Attachment to any
   persistent storage location, including the Vault directory, Obsidian cache
   directories, Obsidian application data directory, operating system temporary
   directories, or any Plugin-created log, diagnostic, or backup file.
5. IF the AWS KMS unwrap call fails, exceeds the 10-second timeout, or returns
   an authorization error during Attachment decryption, THEN THE Plugin SHALL
   abort the render, release any in-memory Plaintext buffer associated with the
   Attachment, avoid creating any Blob URL, and surface an error indication to
   the renderer identifying the failure category.
6. IF AES-256-GCM decryption or authentication tag verification fails for an
   Attachment, THEN THE Plugin SHALL abort the render, release any in-memory
   Plaintext buffer associated with the Attachment, avoid creating any Blob URL,
   and surface an integrity error indication to the renderer.
7. IF an Attachment with a registered encrypted extension exceeds 50 MB on
   disk, THEN THE Plugin SHALL refuse to decrypt the Attachment, avoid creating
   any Blob URL, and surface an error indication to the renderer identifying the
   size limit.

#### Requirement 7: Encrypt Existing File Command

**User Story:** As a DevOps engineer, I want a command to encrypt an existing
Note or Attachment in place, so that I can migrate existing content into the
encrypted scheme.

##### Acceptance Criteria

1. THE Plugin SHALL register an Obsidian command "Encrypt current file with AWS
   KMS" that is enabled for any file (not folder) in the Vault and is available
   from the command palette and the file context menu.
2. WHEN the "Encrypt current file with AWS KMS" command is invoked on a Note
   that does not already match the encrypted naming scheme, THE Plugin SHALL
   rename the file to insert the configured "Encrypted note suffix" before the
   `.md` extension and SHALL replace the Body on disk with an Encrypted File
   block, completing any AWS KMS call within 30 seconds, with the rename and
   content replacement executed atomically such that either both succeed or the
   file is restored to its pre-command state.
3. WHEN the "Encrypt current file with AWS KMS" command is invoked on an
   Attachment that does not already match the encrypted naming scheme, THE
   Plugin SHALL rename the file by inserting `.enc` before its extension and
   SHALL replace its contents with an Encrypted File, completing any AWS KMS
   call within 30 seconds, with the rename and content replacement executed
   atomically such that either both succeed or the file is restored to its
   pre-command state.
4. IF the target file already matches the encrypted naming scheme (a Note whose
   name ends with the configured "Encrypted note suffix" or an Attachment whose
   extension is preceded by `.enc`), THEN THE Plugin SHALL abort the command
   without modifying or renaming the file and SHALL display a notice indicating
   that the file is already encrypted.
5. IF encryption, rename, or content replacement fails for any reason during the
   "Encrypt current file with AWS KMS" command, THEN THE Plugin SHALL restore
   the file to its pre-command name and contents and SHALL display a notice
   identifying the failure category.

#### Requirement 8: On-Disk Format Versioning

**User Story:** As a DevOps engineer, I want a versioned on-disk format, so
that future plugin versions can read files produced today.

##### Acceptance Criteria

1. THE Plugin SHALL prefix every Encrypted File with a fixed-length magic
   identifier of at least 4 bytes, immediately followed by an unsigned integer
   format version field of fixed width of at least 16 bits, placed at byte
   offset 0 before any ciphertext or metadata.
2. IF the Plugin reads a file whose format version field is greater than the
   highest format version supported by the installed Plugin, THEN THE Plugin
   SHALL abort decryption, leave the file unchanged on disk, and display a
   user-visible error notification instructing the user to upgrade the Plugin.
3. IF the Plugin reads a file whose leading bytes do not match the magic
   identifier defined in criterion 1, THEN THE Plugin SHALL classify the file
   as non-encrypted, skip decryption entirely, and return the file contents to
   the caller unchanged.
4. WHEN the Plugin reads an Encrypted File whose magic identifier matches and
   whose format version is less than or equal to the highest supported version,
   THE Plugin SHALL decrypt the file using the decryption logic associated with
   that specific version.
5. IF the Plugin reads a file that begins with the magic identifier but is
   shorter than the combined length of the magic identifier and version field,
   or whose version field cannot be parsed as an unsigned integer, THEN THE
   Plugin SHALL abort decryption, leave the file unchanged on disk, and display
   a user-visible error notification indicating that the file header is
   corrupted or truncated.

### Phase 3 — Advanced (Multi-Provider and Per-Folder Policies)

#### Requirement 9: Multi-Provider KMS Support

**User Story:** As a DevOps engineer serving clients across AWS, Azure, and
GCP, I want the Plugin to work with the client's KMS provider, so that I do
not force a single cloud on the customer.

##### Acceptance Criteria

1. THE Plugin SHALL ship Provider Adapters for AWS KMS, Azure Key Vault, and
   Google Cloud KMS.
2. THE Plugin SHALL define a single internal Provider Adapter interface
   exposing `generateDataKey`, `wrapDek`, and `unwrapDek` operations.
3. WHEN the Plugin encrypts content, THE Plugin SHALL record in the Encrypted
   File header the active provider identifier as a 1 to 32 character ASCII
   string drawn from the enumerated set of supported provider identifiers
   (`aws-kms`, `azure-key-vault`, `gcp-kms`).
4. WHEN the Plugin decrypts an Encrypted File whose header contains a provider
   identifier belonging to the enumerated supported set, THE Plugin SHALL
   dispatch the unwrap operation to the Provider Adapter corresponding to that
   identifier.
5. IF the provider identifier in an Encrypted File header is not in the
   enumerated supported set of the installed Plugin version, THEN THE Plugin
   SHALL abort decryption, leave the file on disk unchanged, and display a
   notice naming the missing provider for at least 5 seconds.
6. IF the provider identifier field in an Encrypted File header is missing,
   empty, longer than 32 characters, or contains non-ASCII characters, THEN THE
   Plugin SHALL abort decryption, leave the file on disk unchanged, and display
   a notice indicating that the file header is malformed for at least 5 seconds.
7. IF a Provider Adapter returns an authentication error, authorization error,
   network error, or any other runtime failure during wrap or unwrap, THEN THE
   Plugin SHALL abort the operation, leave any targeted file on disk unchanged,
   and display a notice identifying the failing provider and the failure
   category for at least 5 seconds.

#### Requirement 10: Per-Folder Encrypted Vault Policies

**User Story:** As a DevOps engineer handling multiple clients, I want to bind
specific vault folders to specific CMKs, so that each client's notes are
encrypted under that client's key.

##### Acceptance Criteria

1. THE Plugin SHALL expose in its settings tab a list of Encrypted Vault
   Policies, where each policy binds a folder path within the Vault to a
   provider identifier and a CMK identifier.
2. WHEN a Note or Attachment is saved inside a folder that is or is a
   descendant of a folder bound by an Encrypted Vault Policy, THE Plugin SHALL
   encrypt that file using the policy's provider and CMK regardless of the file
   name suffix.
3. IF a file is simultaneously covered by an Encrypted Vault Policy and the
   suffix rule from Requirement 5, THEN THE Plugin SHALL apply the Encrypted
   Vault Policy and ignore the suffix rule for that file.
4. IF two or more Encrypted Vault Policies cover the same file through distinct
   folder paths, THEN THE Plugin SHALL apply the policy whose folder path is the
   longest prefix match of the file's Vault-relative path.
5. IF two Encrypted Vault Policies bind the same folder path, THEN THE Plugin
   SHALL reject the configuration with a validation error in the settings tab
   and SHALL apply no Encrypted Vault Policy to that folder until the conflict
   is resolved.
6. IF the provider or CMK named by a matching Encrypted Vault Policy is
   unavailable at save time (provider not registered, credentials missing,
   or CMK access denied), THEN THE Plugin SHALL abort the save, leave the file
   on disk unchanged, and display a notice identifying the Encrypted Vault
   Policy and the failure category for at least 5 seconds.

#### Requirement 11: Key Rotation Command

**User Story:** As a DevOps engineer, I want to rotate the CMK used for an
Encrypted File without decrypting the payload on disk, so that I can respond
to key lifecycle events.

##### Acceptance Criteria

1. THE Plugin SHALL register an Obsidian command "Rotate CMK for current file".
2. WHEN the "Rotate CMK for current file" command is invoked on an Encrypted
   File and the user confirms a target provider and CMK through the rotation
   dialog, THE Plugin SHALL unwrap the DEK using the file's current provider
   and CMK, SHALL re-wrap the same DEK using the selected target provider and
   CMK, and SHALL atomically replace the on-disk Encrypted File with the
   resulting Encrypted File such that the Ciphertext and Nonce bytes are
   byte-for-byte identical to the original.
3. IF unwrap of the existing Wrapped DEK fails, THEN THE Plugin SHALL abort
   the rotation, SHALL leave the file on disk unchanged, and SHALL display an
   error indication to the user identifying the failed unwrap step.
4. IF the "Rotate CMK for current file" command is invoked when there is no
   active file or when the active file is not an Encrypted File, THEN THE
   Plugin SHALL abort the rotation without reading or modifying any file and
   SHALL display an indication that the command requires an active Encrypted
   File.
5. IF the user cancels or closes the rotation dialog before confirming a target
   provider and CMK, THEN THE Plugin SHALL abort the rotation and SHALL leave
   the file on disk unchanged.
6. IF re-wrap of the DEK with the target provider and CMK fails, or IF writing
   the resulting Encrypted File to disk fails after a successful unwrap, THEN
   THE Plugin SHALL abort the rotation, SHALL leave the file on disk unchanged,
   SHALL discard the unwrapped DEK from memory, and SHALL display an error
   indication to the user identifying the failed step.

### Non-Functional Requirements

#### Requirement 12: Zero Cleartext on Disk

**User Story:** As a security-conscious engineer, I want a guarantee that
Plaintext Body and Attachment bytes never touch persistent storage, so that
the Vault remains safe when synced to untrusted S3 or Git remotes.

##### Acceptance Criteria

1. THE Plugin SHALL hold decrypted Plaintext and decrypted Attachment bytes
   only in volatile process memory allocated within the Plugin's runtime.
2. THE Plugin SHALL NOT write decrypted Plaintext or decrypted Attachment bytes
   to any file under the Vault directory, Obsidian's application data directory,
   the operating system temporary directory, or any Plugin-created log,
   diagnostic, telemetry, cache, or backup file.
3. WHEN an editor view displaying a decrypted Note is closed, THE Plugin SHALL
   overwrite the in-memory Plaintext buffer associated with that view with zero
   bytes and release the buffer within 1 second of the close event.
4. WHEN the Obsidian application quits, THE Plugin SHALL overwrite all
   in-memory decrypted Plaintext and decrypted Attachment buffers with zero
   bytes before process exit and SHALL leave no Plugin-created file on disk
   containing decrypted Plaintext or decrypted Attachment bytes.
5. IF the Plugin emits a log, error trace, or diagnostic output, THEN THE
   Plugin SHALL exclude decrypted Plaintext and decrypted Attachment bytes from
   that output.

#### Requirement 13: Local-Only Cryptographic Operations

**User Story:** As a DevOps engineer, I want all symmetric encryption and
decryption of payloads to run on my machine, so that note content is never
transmitted to a cloud endpoint.

##### Acceptance Criteria

1. THE Plugin SHALL perform AES-256-GCM encryption and decryption of Note
   bodies and Attachments locally within the Obsidian process on the user's
   machine and SHALL NOT invoke any remote service or network endpoint to carry
   out the symmetric cipher operation.
2. WHEN the Plugin performs a DEK wrap operation against Cloud KMS, THE Plugin
   SHALL transmit to Cloud KMS only the plaintext DEK bytes, and WHEN the
   Plugin performs a DEK unwrap operation against Cloud KMS, THE Plugin SHALL
   transmit to Cloud KMS only the Wrapped DEK bytes.
3. THE Plugin SHALL NOT transmit Plaintext Note bodies, Attachment bytes, or
   decrypted DEK material to any network endpoint, and SHALL NOT include any of
   those values in logs, telemetry, error reports, or crash diagnostics.
4. IF local AES-256-GCM encryption or decryption fails due to authentication
   tag mismatch, ciphertext corruption, or any cryptographic library error,
   THEN THE Plugin SHALL abort the operation, surface an error indication to
   the caller, and SHALL NOT persist partial plaintext or partial ciphertext
   to any file or network endpoint.

#### Requirement 14: Performance Budgets

**User Story:** As a DevOps engineer, I want encrypted notes to open fast
enough to stay in flow, so that encryption does not harm my workflow.

##### Acceptance Criteria

1. WHEN an Encrypted File smaller than 1 MiB is opened and Cloud KMS responds
   to the unwrap request within 200 ms, THE Plugin SHALL complete decryption
   and render the content within 500 ms on a baseline machine defined as an
   8-core 2.5 GHz x86-64 CPU.
2. WHEN an Encrypted File is saved, THE Plugin SHALL complete local
   AES-256-GCM encryption of a 1 MiB Body in under 100 ms on a baseline machine
   defined as an 8-core 2.5 GHz x86-64 CPU.
3. WHILE a Cloud KMS call is in flight, THE Plugin SHALL execute the call on a
   non-blocking asynchronous path and SHALL NOT block the Obsidian UI main
   thread for more than 50 ms at any single synchronous point during the call.
4. IF a Cloud KMS unwrap call does not return a response within 5 seconds,
   THEN THE Plugin SHALL abort the operation, leave the targeted file on disk
   unchanged, and surface a timeout error indication to the user.

#### Requirement 15: Observability and Access Transparency

**User Story:** As an SRE, I want every decryption to produce an audit event
in the cloud provider's log, so that I can prove who accessed which note and
when.

##### Acceptance Criteria

1. THE Plugin SHALL perform each DEK unwrap through the Cloud KMS provider's
   standard API so that the provider's native audit log (for example AWS
   CloudTrail) records the unwrap event, with no use of client-side caching of
   unwrapped DEKs across distinct unwrap calls.
2. WHEN the Plugin calls a Cloud KMS unwrap API, THE Plugin SHALL include in
   the request an encryption context containing the Vault name, the
   Vault-relative file path, and the on-disk format version, and SHALL use the
   same encryption context values for both the original wrap and every
   subsequent unwrap of the same Encrypted File.
3. WHEN the Plugin encrypts a file, THE Plugin SHALL emit a structured log
   entry at level `info` within 1 second of the encryption completing,
   containing the provider identifier, CMK identifier, Vault-relative file
   path, encrypted payload byte length, and a timestamp in ISO-8601 UTC.
4. WHEN the Plugin decrypts a file, THE Plugin SHALL emit a structured log
   entry at level `info` within 1 second of the decryption completing,
   containing the provider identifier, CMK identifier, Vault-relative file
   path, on-disk format version, and a timestamp in ISO-8601 UTC.
5. IF a Cloud KMS unwrap or wrap call fails, THEN THE Plugin SHALL emit a
   structured log entry at level `error` within 1 second of the failure
   containing the provider identifier, CMK identifier, Vault-relative file
   path, provider error code or category, and a timestamp in ISO-8601 UTC.
6. THE Plugin SHALL exclude Plaintext content, DEK bytes, Wrapped DEK bytes,
   authentication tag bytes, and Cloud credential material from every log
   entry, audit event payload, and telemetry record emitted by the Plugin.

#### Requirement 16: Extensibility Through Provider Adapter Interface

**User Story:** As a maintainer, I want a clean extension point for new KMS
providers, so that adding a new cloud does not require changes to the
encryption core.

##### Acceptance Criteria

1. THE Plugin SHALL isolate all provider-specific code behind the Provider
   Adapter interface defined in Requirement 9, such that no encryption-core
   module imports any Cloud KMS provider SDK package or API directly.
2. THE Plugin SHALL allow registering a new Provider Adapter by adding a
   single module that implements every method of the Provider Adapter
   interface and declares a provider identifier matching the format defined
   in Requirement 9 (1 to 32 character lowercase ASCII alphanumeric with
   hyphens) that is unique among the adapters registered at Plugin startup.
3. THE Plugin SHALL bundle provider SDKs (`@aws-sdk/client-kms`,
   `@azure/keyvault-keys`, `@google-cloud/kms`) such that, for each SDK, the
   SDK is included in the shipped plugin bundle if and only if its
   corresponding provider is enabled in the build configuration.
4. IF two Provider Adapters declare the same provider identifier at Plugin
   startup, THEN THE Plugin SHALL reject the second registration, retain the
   first adapter as the active one for that identifier, and emit an error
   indication identifying the conflicting identifier.
5. IF a Provider Adapter does not implement every method of the Provider
   Adapter interface at registration time, THEN THE Plugin SHALL reject the
   registration and emit an error indication listing the missing methods.

#### Requirement 17: Dependency and Supply Chain Hygiene

**User Story:** As a security reviewer, I want pinned, minimal cryptographic
dependencies, so that the plugin's attack surface is small and auditable.

##### Acceptance Criteria

1. THE Plugin SHALL pin every direct dependency in its package manifest to an
   exact version string that contains no semver range operators (`^`, `~`, `*`,
   `>`, `<`, `>=`, `<=`, `x`, ` - `).
2. THE Plugin SHALL use the WebCrypto API provided by the Obsidian runtime for
   AES-256-GCM encryption and decryption operations and SHALL NOT depend,
   directly or transitively in production dependencies, on any third-party
   symmetric cipher library.
3. IF the build-time dependency audit identifies a known advisory of severity
   `high` or `critical` (as reported by `npm audit` or an equivalent audit tool)
   against any direct or transitive dependency, THEN THE build SHALL terminate
   with a non-zero exit status, SHALL surface an error indication naming the
   affected dependency and advisory identifier, and SHALL NOT produce a plugin
   artifact.
4. THE Plugin repository SHALL commit a lockfile pinning every transitive
   dependency to an exact resolved version with a recorded integrity hash.
5. WHEN the Plugin build runs, THE Plugin SHALL execute the dependency audit
   defined in criterion 3 before producing the plugin artifact and SHALL
   complete the audit within 120 seconds.

### Parser, Serializer, and Round-Trip Properties

#### Requirement 18: Encrypted File Serializer and Parser

**User Story:** As a maintainer, I want a documented serializer and parser
for the On-Disk Format, so that files produced and consumed by the Plugin
are interchangeable across versions and platforms.

##### Acceptance Criteria

1. THE Plugin SHALL provide a serializer that encodes an Encrypted File
   record (magic bytes, version, provider identifier, CMK identifier,
   Wrapped DEK, Nonce, authentication tag, Ciphertext) into a byte sequence
   following the documented On-Disk Format, and IF any field of the input
   record violates its declared length or type constraint, THEN THE serializer
   SHALL abort and return an error identifying the first invalid field
   without producing any output bytes.
2. THE Plugin SHALL provide a parser that decodes a byte sequence in the
   documented On-Disk Format into an Encrypted File record, completing the
   parse within 100 ms for inputs up to 50 MB on a baseline machine defined
   as an 8-core 2.5 GHz x86-64 CPU.
3. IF the parser receives a byte sequence that does not conform to the
   On-Disk Format grammar (missing or mismatched magic bytes, unsupported
   format version, truncated field, field length exceeding its declared
   bound, or trailing bytes after the final declared field), THEN THE parser
   SHALL abort and return a descriptive parse error identifying the first
   invalid field and SHALL NOT return a partially populated Encrypted File
   record.
4. FOR ALL Encrypted File records produced by the serializer, parsing the
   serialized bytes SHALL yield a record whose every field is byte-for-byte
   equal to the original record (serialize then parse round-trip property).
5. FOR ALL byte sequences accepted by the parser, serializing the parsed
   record SHALL yield a byte sequence of the same length and byte-for-byte
   equal to the input (parse then serialize round-trip property).
6. IF the serializer is invoked with a format version greater than the
   highest version supported by the installed Plugin, THEN THE serializer
   SHALL abort and return an error identifying the unsupported version
   without producing any output bytes.

### Correctness Properties for Property-Based Testing

#### Requirement 19: Encrypt and Decrypt Round-Trip

**User Story:** As a developer, I want a verified round-trip property over
the encryption pipeline, so that no input is silently corrupted.

##### Acceptance Criteria

1. THE Plugin SHALL ensure that for every Plaintext byte sequence `P` with
   length in the range 0 to 64 MiB, every registered Provider Adapter `A`,
   and every CMK `K` for which `A` grants wrap and unwrap access,
   `decrypt(A, K, encrypt(A, K, P)) = P` holds byte-for-byte.
2. THE Plugin SHALL ensure that for every Plaintext byte sequence `P` with
   length in the range 0 to 64 MiB and every CMK `K`, two sequential
   `encrypt(A, K, P)` invocations yield two Encrypted Files whose DEK bytes
   differ in at least one position and whose Nonce bytes differ in at least
   one position.
3. IF any single byte of `E.Ciphertext`, `E.Nonce`, `E.WrappedDek`, or
   `E.AuthenticationTag` in an Encrypted File `E` is modified before decrypt,
   THEN `decrypt` SHALL abort with an integrity error, SHALL NOT return any
   Plaintext bytes, and SHALL NOT produce an on-disk side effect.
4. IF a CMK `K` is not granted unwrap access through Provider Adapter `A`,
   THEN `decrypt(A, K, E)` SHALL abort with an authorization error, SHALL
   NOT return any Plaintext bytes, and SHALL surface the authorization
   failure to the caller.

#### Requirement 20: Ciphertext Stability Without KMS Access

**User Story:** As a security engineer, I want on-disk ciphertext to remain
unchanged when KMS access is unavailable, so that offline or read-only
usage cannot silently corrupt Vault files.

##### Acceptance Criteria

1. WHILE the Plugin cannot reach Cloud KMS (network error, authentication
   failure, or no response within 10 seconds), WHEN the user opens an
   Encrypted File, THE Plugin SHALL leave the file's on-disk bytes byte-for-byte
   unchanged.
2. WHILE the Plugin cannot reach Cloud KMS (network error, authentication
   failure, or no response within 10 seconds), WHEN the user views a folder
   containing Encrypted Files, THE Plugin SHALL leave every Encrypted File's
   on-disk bytes byte-for-byte unchanged, regardless of the number of
   Encrypted Files in the folder.
3. IF a save is attempted for a Note whose encryption would require a
   currently unreachable Cloud KMS, THEN THE Plugin SHALL abort the save and
   SHALL leave the Note's on-disk bytes byte-for-byte unchanged.
4. IF a save is aborted due to the Plugin being unable to reach Cloud KMS,
   THEN THE Plugin SHALL surface a user-visible error indication identifying
   the affected Note and the Cloud KMS unreachability for at least 5 seconds.

#### Requirement 21: No Plaintext in Persistent Artifacts

**User Story:** As a security engineer, I want an automatically checkable
property that no Plaintext leaks into persistent artifacts, so that Zero
Trust Storage is enforced by test.

##### Acceptance Criteria

1. THE Plugin SHALL ensure that for every Plaintext byte sequence `P` of at
   least 32 bytes written through the Plugin's save path to a file covered by
   an Encrypted Vault Policy or the suffix rule, the resulting on-disk byte
   sequence does not contain `P` as a contiguous substring.
2. THE Plugin SHALL ensure that for every Plaintext byte sequence `P` of at
   least 32 bytes written through the Plugin's save path to a file covered by
   an Encrypted Vault Policy or the suffix rule, the resulting on-disk byte
   sequence does not contain any 32-byte contiguous substring of `P` whose
   Shannon entropy exceeds 3 bits per byte.
3. THE Plugin SHALL ensure that for every Plaintext byte sequence `P` of at
   least 32 bytes decrypted through the Plugin's open path, no file under the
   Vault directory, Obsidian's application data directory, or the operating
   system temporary directory is created or modified to contain `P` as a
   contiguous substring during the open session or within 60 seconds after
   the in-memory Plaintext buffer is released.
4. THE Plugin SHALL ensure that for every DEK byte sequence `D` generated by
   the Plugin, no file under the Vault directory, Obsidian's application
   data directory, or the operating system temporary directory contains `D`
   as a contiguous substring, and SHALL ensure no such file contains any
   16-byte contiguous substring of `D`.
5. IF the Plugin detects during its save path that a non-encrypted on-disk
   artifact it is about to produce would contain a prohibited Plaintext or
   DEK substring per criteria 1 through 4, THEN THE Plugin SHALL abort the
   write, leave the previous on-disk contents unchanged, and display a
   user-visible error indication identifying the affected artifact for at
   least 5 seconds.

#### Requirement 22: Confluence of Provider Adapter Dispatch

**User Story:** As a maintainer, I want provider dispatch to be
order-independent, so that the behavior does not depend on provider
registration order.

##### Acceptance Criteria

1. WHEN the Plugin is initialized with any finite set of Provider Adapters
   `S` of size up to 64 and any permutation `S'` of `S`, THE Plugin SHALL
   yield the same success-or-failure classification and, on success, produce
   decrypted Plaintext byte-for-byte equal across both registration orders
   for every `encrypt` and `decrypt` invocation over identical inputs.
2. WHEN the Plugin dispatches decryption of an Encrypted File `E` whose
   header references a provider identifier present in the registered set,
   THE Plugin SHALL select the Provider Adapter matching that identifier
   independent of the registration order of Provider Adapters.
3. IF an Encrypted File's header references a provider identifier not
   present in the registered set of Provider Adapters, THEN THE Plugin
   SHALL abort decryption, leave the file on disk unchanged, and surface
   an error indication identifying the missing provider identifier.
4. IF two Provider Adapters with the same provider identifier are supplied
   during Plugin registration, THEN THE Plugin SHALL reject the registration,
   surface an error indication identifying the duplicate provider identifier,
   and refuse to initialize until the conflict is resolved.
