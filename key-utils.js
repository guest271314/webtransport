/**
 * key-utils.js
 * PEM and DER conversion utilities.
 */
export async function importPrivateKey(pemString) {
  const b64 = pemString
    .replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s/g, "");
  const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

  return crypto.subtle.importKey(
    "pkcs8",
    der,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
}

export function pemToDer(pemString) {
  const b64 = pemString
    .replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/g, "");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
