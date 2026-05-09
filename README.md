# Obsidian Cloud KMS Encryption

Плагин для [Obsidian](https://obsidian.md), обеспечивающий **file-level шифрование** заметок и вложений с использованием облачных KMS-сервисов (AWS KMS, Azure Key Vault, Google Cloud KMS).

## Зачем

Если вы храните Obsidian-хранилище в S3, Git или любом другом удалённом хранилище — содержимое заметок доступно любому, кто получит доступ к storage. Этот плагин реализует модель **Zero Trust Storage**: на диске и в remote всегда лежит только шифротекст. Расшифровка происходит локально, в памяти, только при наличии доступа к Cloud KMS.

## Ключевые принципы

- **Envelope Encryption** — каждый файл шифруется уникальным DEK (AES-256-GCM), а сам DEK оборачивается CMK в облачном KMS
- **Identity-based Auth** — никаких паролей; используются системные credentials (AWS SSO, IAM Role)
- **Local-First Crypto** — симметричное шифрование выполняется локально через WebCrypto API; в KMS уходит только DEK для wrap/unwrap
- **Zero Cleartext on Disk** — расшифрованный контент существует только в оперативной памяти процесса Obsidian
- **Access Transparency** — каждый вызов unwrap записывается в CloudTrail (или аналог), обеспечивая полный аудит доступа

## Возможности (текущая версия)

### Phase 1 — PoC (ручные команды)

| Команда | Описание |
|---------|----------|
| `Encrypt selection with AWS KMS` | Шифрует выделенный текст в inline-блок |
| `Decrypt selection with AWS KMS` | Расшифровывает inline-блок обратно в текст |

- Настройка: единственное поле "AWS KMS Key ARN" в настройках плагина
- Валидация ARN-формата с inline-ошибкой

### Phase 2 — MVP (прозрачное шифрование)

| Функция | Описание |
|---------|----------|
| Transparent encryption on save | Заметки с суффиксом `*.secret.md` автоматически шифруются при сохранении |
| Transparent decryption on open | При открытии зашифрованной заметки — расшифровка в памяти, отображение plaintext |
| Encrypted attachment preview | Файлы `.enc.png`, `.enc.jpg`, `.enc.pdf` расшифровываются в Blob URL для preview |
| Encrypt current file | Команда для миграции существующего файла в зашифрованный формат |
| Frontmatter preservation | YAML-метаданные (теги, title) остаются в plaintext для поиска и индексации |

### Безопасность

- Расшифрованные данные хранятся в `SecureBuffer` с гарантированным zero-fill при освобождении
- DEK обнуляется сразу после использования (даже при ошибке)
- Blob URL для вложений отзывается при закрытии view
- Structured logging без утечки plaintext, DEK или credentials
- Atomic file writes с rollback при сбое

## Установка

### Требования

- Obsidian ≥ 1.4.0 (desktop)
- AWS CLI настроен (`aws sso login` или IAM Role)
- Node.js ≥ 18 (для сборки из исходников)

### Из GitHub Releases (рекомендуется)

1. Перейдите в [Releases](https://github.com/your-org/obsidian-cloud-kms/releases)
2. Скачайте из последнего релиза: `main.js`, `manifest.json`
3. Создайте папку `.obsidian/plugins/obsidian-cloud-kms-encryption/` в вашем хранилище
4. Положите скачанные файлы в эту папку
5. Перезапустите Obsidian → Settings → Community Plugins → включите "Cloud KMS Encryption"

### BRAT (автообновления)

Если используете [BRAT](https://github.com/TfTHacker/obsidian42-brat):

1. Settings → BRAT → Add Beta Plugin
2. Введите: `your-org/obsidian-cloud-kms`
3. Плагин установится и будет обновляться автоматически при новых релизах

### Из исходников (для разработки)

```bash
git clone https://github.com/your-org/obsidian-cloud-kms.git
cd obsidian-cloud-kms
npm install
npm run build
```

Скопируйте `main.js` и `manifest.json` в `.obsidian/plugins/obsidian-cloud-kms-encryption/` вашего хранилища.

### Настройка AWS

1. Создайте KMS-ключ (symmetric, encrypt/decrypt):
   ```bash
   aws kms create-key --key-spec SYMMETRIC_DEFAULT --key-usage ENCRYPT_DECRYPT
   ```

2. Скопируйте ARN ключа (формат: `arn:aws:kms:{region}:{account}:key/{key-id}`)

3. В Obsidian: Settings → Cloud KMS Encryption → вставьте ARN

4. Убедитесь, что credentials доступны:
   ```bash
   aws sts get-caller-identity
   ```

## Использование

### Ручное шифрование (Phase 1)

1. Выделите текст в заметке
2. `Ctrl+P` → "Encrypt selection with AWS KMS"
3. Выделенный текст заменяется на зашифрованный блок `` ```ocke-v1 ... ``` ``
4. Для расшифровки: выделите блок → "Decrypt selection with AWS KMS"

### Прозрачное шифрование (Phase 2)

1. Создайте заметку с суффиксом `.secret.md` (например, `client-passwords.secret.md`)
2. Пишите как обычно — при сохранении body автоматически шифруется
3. При открытии — автоматическая расшифровка в памяти
4. Frontmatter (теги, title) остаётся в plaintext для поиска

### Миграция существующих файлов

1. Откройте файл
2. `Ctrl+P` → "Encrypt current file with AWS KMS"
3. Файл переименовывается (добавляется суффикс) и шифруется

## On-Disk Format

Зашифрованные файлы используют бинарный формат OCKE v1:

```
[Magic: "OCKE" 4B][Version: uint16 BE][ProviderIdLen: 1B][ProviderId: N B]
[CmkIdLen: uint16 BE][CmkId: M B][WrappedDekLen: uint16 BE][WrappedDek: W B]
[Nonce: 12B][AuthTag: 16B][CiphertextLen: uint32 BE][Ciphertext: C B]
```

- Magic bytes: `0x4F434B45` ("OCKE")
- Все multi-byte integers — big-endian
- Формат версионирован для forward compatibility

## Архитектура

```
src/
├── core/           # CryptoEngine, SecureBuffer, WebCrypto wrapper
├── format/         # On-Disk Format serializer/parser, inline codec
├── providers/      # Provider Adapter interface + AWS KMS implementation
├── hooks/          # Save hook, open hook, attachment hook
├── commands/       # Encrypt/decrypt selection, encrypt file
├── policies/       # Suffix matcher (+ policy resolver в Phase 3)
├── ui/             # Settings tab, encrypted view, notices
├── logging/        # Structured logger + sanitizer
└── utils/          # ARN validator, frontmatter splitter, atomic write
```

## Разработка

```bash
# Запуск тестов
npm test

# Запуск только property-based тестов
npm run test:property

# Watch mode
npm run test:watch

# Production build
npm run build

# Dev build (watch)
npm run dev
```

## Roadmap

- [x] Phase 1 — PoC: ручные команды encrypt/decrypt с AWS KMS
- [x] Phase 2 — MVP: прозрачное шифрование, attachment preview, encrypt file
- [ ] Phase 3 — Advanced: multi-provider (Azure, GCP), per-folder policies, key rotation

## Лицензия

MIT
