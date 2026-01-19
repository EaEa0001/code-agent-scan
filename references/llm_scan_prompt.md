# LLM Script Scan Prompt (Malicious + Encryption)

Goal: Review SKILL.md and scripts/* content for malicious/backdoor behavior and suspicious encryption/obfuscation. Do NOT assume intent; focus on evidence.

Input: file path + file content (plain text)
Output: compact findings list with risk, evidence, and reasoning.

## Required checks
- Backdoor behavior (hidden execution, persistence, stealth flags, auto-run)
- Credential access (tokens, keys, env scraping, ~/.ssh, keychain, browser data)
- Exfiltration (compress + upload, scp/rsync, unusual outbound)
- Privilege escalation (sudo, UAC bypass, system config edits)
- Obfuscation/encryption (base64 blobs, XOR, custom cipher, dynamic decrypt+exec)

## Encryption/obfuscation signals (high priority)
- Large base64/hex blobs decoded at runtime
- Custom AES/RSA or ad-hoc XOR routines not tied to a clear business purpose
- Decrypt -> exec or eval patterns
- High-entropy strings used as keys or payloads
- Multi-stage decoding (base64 -> zlib -> exec)

## Output format (one line per finding)
`<risk> <file> <evidence> <reason>`

## Risk levels
- high: clear malicious pattern or decrypt/exec flow
- medium: suspicious pattern without clear malicious action
- low: benign but security-relevant behavior

## Example
high scripts/installer.py "base64.b64decode(payload); exec(...)" decrypt+exec pattern
medium scripts/setup.sh "curl ... | sh" download+exec without verification
low scripts/config.py "requests.post(...)" outbound request but no exfil indicators
