// SPDX-License-Identifier: Apache-2.0
//
// Secret-input guard (aligned with @qorechain/mcp-core/src/guard.ts):
// refuses mnemonics or private-key-looking fields passed into MCP tools.

const SECRET_KEY_NAME_RE = /(?:mnemonic|seed_?phrase|private_?key|secret_?key|passphrase|privkey|sk_hex)/i;
const MNEMONIC_WORD_RE = /^[a-z]+(?:\s+[a-z]+){11,23}$/;

export class SecretInputError extends Error {
  public readonly code = "SECRET_INPUT_REFUSED";

  constructor(message: string) {
    super(message);
    this.name = "SecretInputError";
  }
}

/**
 * Recursively inspects untrusted MCP tool input and refuses any field name or
 * value that looks like a secret key or BIP-39 recovery phrase.
 */
export function refuseSecretInputs(
  input: unknown,
  allowedHexFields: ReadonlySet<string> = new Set(),
  path = "input",
): void {
  if (input === null || input === undefined) return;
  if (typeof input === "string") {
    const trimmed = input.trim();
    if (MNEMONIC_WORD_RE.test(trimmed)) {
      const words = trimmed.split(/\s+/);
      if (words.length === 12 || words.length === 15 || words.length === 18 || words.length === 21 || words.length === 24) {
        throw new SecretInputError(
          `Refused secret-looking recovery phrase at ${path}. Never pass mnemonics or private keys to MCP tools.`,
        );
      }
    }
    return;
  }
  if (Array.isArray(input)) {
    input.forEach((item, idx) => refuseSecretInputs(item, allowedHexFields, `${path}[${idx}]`));
    return;
  }
  if (typeof input === "object") {
    for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
      if (SECRET_KEY_NAME_RE.test(k) && !allowedHexFields.has(k)) {
        throw new SecretInputError(
          `Refused secret field "${path}.${k}". QoreGuard MCP tools verify public envelopes and never accept private keys.`,
        );
      }
      refuseSecretInputs(v, allowedHexFields, `${path}.${k}`);
    }
  }
}
