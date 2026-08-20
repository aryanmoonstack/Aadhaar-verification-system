/**
 * Cross-language signature agreement — the test that saves an afternoon.
 *
 * ★ THE EXPECTED HASHES BELOW ARE NOT COMPUTED HERE.
 *
 *   They were produced by the Python service's own `avs.security.build_signature`
 *   and pasted in. That is the entire point: a test that derived them with the
 *   same code it is testing would pass no matter how wrong both were. These are
 *   the other implementation's answers, frozen.
 *
 *   Regenerate with:
 *
 *       PYTHONPATH=src python3 -c "
 *       from avs.security import build_signature
 *       print(build_signature('a'*64, '1755500000', 'abc123', b'hello'))"
 */

import { describe, expect, it } from 'vitest';

import { buildMultipart, canonicalMessage, signature, signedHeaders } from '../avsSignature';

/** Not a real secret. 64 chars so it clears the 32-character floor. */
const SECRET = 'a'.repeat(64);

describe('agreement with the Python service', () => {
  const vectors: ReadonlyArray<readonly [string, string, Buffer, string]> = [
    // [timestamp, nonce, body, expected hex from Python]
    [
      '1755500000',
      'abc123',
      Buffer.from(''),
      '4fb817979d37bfd9126361de4a7e6d31931fc75c25639abe943144e7b9b06631',
    ],
    [
      '1755500000',
      'abc123',
      Buffer.from('hello'),
      '7f3dc315bf8af0b97729e153fba625567e26ff7b6ad807f9fccc0467d933f7fc',
    ],
    [
      '12',
      '3',
      Buffer.from('x'),
      '62aeb7bb951a82b7783c51519a807eb70682f4289537568f067aaf0bdb66f75b',
    ],
    [
      '1',
      '23',
      Buffer.from('x'),
      '755c9bd26fbce9a8179a3a37d2858e45d921770c75b075c41f74668afbd0efc9',
    ],
    // Binary body — bytes that are not valid UTF-8. A string round trip here
    // would corrupt them silently and only for some files.
    [
      '1755500001',
      'deadbeef',
      Buffer.from([0x00, 0xff, 0x10, 0x80]),
      '6fd4c07a0ba866ce45401d22057ebfab6091643328657f10158aeae148c6e854',
    ],
    // PDF magic bytes plus CRLF and a boundary marker — the shape of a real
    // multipart body carrying an e-Aadhaar.
    [
      '1755500002',
      'f'.repeat(32),
      Buffer.from('%PDF-1.7\n\r\n--boundary--'),
      '1438812e229450cdf2f77d4ea586b091492e2bd6cbc95ea0732847f40b7a7fd6',
    ],
  ];

  it.each(vectors)('matches Python for (%s, %s)', (timestamp, nonce, body, expected) => {
    expect(signature(SECRET, timestamp, nonce, body)).toBe(expected);
  });
});

describe('the dot separators', () => {
  it('prevents a canonicalisation collision', () => {
    /**
     * ⛔ The reason the separators exist.
     *
     * Without them, ("12", "3", "x") and ("1", "23", "x") both canonicalise to
     * "123x" and hash identically — letting an attacker move bytes between the
     * timestamp and the nonce while the signature stays valid. That is a replay
     * window, not a curiosity.
     */
    const a = signature(SECRET, '12', '3', Buffer.from('x'));
    const b = signature(SECRET, '1', '23', Buffer.from('x'));
    expect(a).not.toBe(b);

    // And the naive concatenation these would collide under:
    expect('12' + '3' + 'x').toBe('1' + '23' + 'x');
  });

  it('puts the body after the final dot, with nothing between', () => {
    expect(canonicalMessage('7', 'n', Buffer.from('BODY')).toString('latin1')).toBe('7.n.BODY');
  });

  it('leaves an empty body as a bare trailing dot', () => {
    // ⚠ What a signed GET looks like. The body is an empty Buffer, not a
    //   skipped component — dropping the dot would break every poll.
    expect(canonicalMessage('7', 'n', Buffer.alloc(0)).toString('latin1')).toBe('7.n.');
  });
});

describe('binary safety', () => {
  it('does not corrupt bytes that are not valid UTF-8', () => {
    const raw = Buffer.from([0xff, 0xfe, 0x00, 0x80, 0x7f]);
    const message = canonicalMessage('1', 'a', raw);
    expect(message.subarray(4)).toEqual(raw);
  });
});

describe('signed headers', () => {
  it('emits all four headers AVS reads', () => {
    const headers = signedHeaders(SECRET, 'm-one-prod', Buffer.from('x'));
    expect(Object.keys(headers).sort()).toEqual([
      'X-AVS-Nonce',
      'X-AVS-Signature',
      'X-AVS-Tenant',
      'X-AVS-Timestamp',
    ]);
    expect(headers['X-AVS-Tenant']).toBe('m-one-prod');
  });

  it('uses a fresh nonce every time', () => {
    // ⛔ AVS rejects a replayed nonce. A cached or derived value would turn the
    //    second request of every session into a 401.
    const nonces = new Set(
      Array.from({ length: 50 }, () => signedHeaders(SECRET, 't', Buffer.alloc(0))['X-AVS-Nonce']),
    );
    expect(nonces.size).toBe(50);
  });

  it('sends seconds, not milliseconds', () => {
    // A millisecond timestamp is ~1000x the expected value and lands far
    // outside the replay window, so every request fails as "too old".
    const headers = signedHeaders(SECRET, 't', Buffer.alloc(0), () => 1_755_500_000_000);
    expect(headers['X-AVS-Timestamp']).toBe('1755500000');
  });

  it('never puts the secret in a header', () => {
    const headers = signedHeaders(SECRET, 't', Buffer.alloc(0));
    expect(JSON.stringify(headers)).not.toContain(SECRET);
  });
});

describe('multipart assembly', () => {
  const pdf: Parameters<typeof buildMultipart>[0] = [
    {
      field: 'front',
      filename: 'aadhaar.pdf',
      contentType: 'application/pdf',
      data: Buffer.from('%PDF-1.7 body'),
    },
  ];

  it('declares the same boundary it used in the body', () => {
    // ⚠ A mismatch makes the server parse a body with no parts in it, which
    //   surfaces as a puzzling 422 rather than an obvious parse error.
    const { body, contentType } = buildMultipart(pdf);
    const boundary = contentType.split('boundary=')[1];
    expect(boundary).toBeTruthy();
    expect(body.toString('latin1')).toContain(`--${boundary}\r\n`);
    expect(body.toString('latin1').endsWith(`--${boundary}--\r\n`)).toBe(true);
  });

  it('preserves file bytes exactly', () => {
    const raw = Buffer.from([0x25, 0x50, 0x44, 0x46, 0x00, 0xff, 0x80]);
    const { body } = buildMultipart([
      { field: 'front', filename: 'a.pdf', contentType: 'application/pdf', data: raw },
    ]);
    expect(body.includes(raw)).toBe(true);
  });

  it('omits empty and absent fields rather than sending blanks', () => {
    // An empty `password` part would be read as "the password is the empty
    // string" and fail differently from not supplying one at all.
    const { body } = buildMultipart(pdf, { password: '', job_id: undefined });
    expect(body.toString('latin1')).not.toContain('name="password"');
    expect(body.toString('latin1')).not.toContain('name="job_id"');
  });

  it('includes fields that do have a value', () => {
    const { body } = buildMultipart(pdf, { password: 'RAME1990' });
    const text = body.toString('latin1');
    expect(text).toContain('name="password"');
    expect(text).toContain('RAME1990');
  });

  it('omits the back part when only one file is supplied', () => {
    // CONTRACTS.md §11 — one PDF stands alone.
    const { body } = buildMultipart(pdf);
    expect(body.toString('latin1')).not.toContain('name="back"');
  });

  it('neutralises quotes and newlines in a filename', () => {
    /**
     * ⛔ Header injection. A filename containing CRLF could otherwise close the
     *    headers early and inject parts of its own — the multipart equivalent
     *    of an unescaped SQL string. Filenames come from the user's device.
     */
    const { body } = buildMultipart([
      {
        field: 'front',
        filename: 'a"\r\nContent-Type: text/html\r\n\r\n<script>.pdf',
        contentType: 'application/pdf',
        data: Buffer.from('x'),
      },
    ]);
    const header = body.toString('latin1').split('\r\n\r\n')[0] ?? '';

    // ⚠ The property is that no CR or LF SURVIVES, so the attacker cannot end
    //   the header block early. Literal text like `<script>` remaining inside
    //   the quoted filename is harmless — it is a filename, not markup, and
    //   nothing renders it. An earlier version of this test asserted the text
    //   was absent, which would have failed a correct implementation.
    const disposition = header.split('\r\n').find((line) => line.startsWith('Content-Disposition'));
    expect(disposition).toBeDefined();
    expect(disposition).not.toMatch(/[\r\n]/);
    expect(disposition!.match(/"/g)?.length).toBe(4); // name="..." filename="..."

    // The injected header did not become a real one.
    expect(header.match(/^Content-Type:/gm)?.length).toBe(1);
  });

  it('produces a body whose signature is stable', () => {
    // The bytes signed must be the bytes sent — signing the same Buffer twice
    // must agree, or nothing downstream can be trusted.
    const { body } = buildMultipart(pdf);
    expect(signature(SECRET, '1', 'a', body)).toBe(signature(SECRET, '1', 'a', body));
  });
});
