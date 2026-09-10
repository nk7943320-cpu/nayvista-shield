import { describe, it, expect } from 'vitest';
import { validateTargetUrl, ValidationError } from '../src/services/urlValidator.js';

describe('Target URL and SSRF Validator', () => {
  it('rejects unconfirmed authorization', async () => {
    await expect(validateTargetUrl('https://example.com', false)).rejects.toThrow(
      'Security testing must be explicitly authorized'
    );
  });

  it('rejects unsupported schemes like ftp or javascript', async () => {
    await expect(validateTargetUrl('ftp://example.com', true)).rejects.toThrow(
      "Unsupported scheme 'ftp'"
    );
    await expect(validateTargetUrl('javascript:alert(1)', true)).rejects.toThrow();
  });

  it('blocks loopback and cloud metadata SSRF targets', async () => {
    await expect(validateTargetUrl('http://127.0.0.1', true)).rejects.toThrow('SSRF Protection');
    await expect(validateTargetUrl('http://localhost:8080', true)).rejects.toThrow('SSRF Protection');
    await expect(validateTargetUrl('http://169.254.169.254/latest/meta-data', true)).rejects.toThrow('SSRF Protection');
  });

  it('accepts valid public domain targets', async () => {
    const validated = await validateTargetUrl('https://example.com/path?foo=bar', true);
    expect(validated.hostname).toBe('example.com');
    expect(validated.scheme).toBe('https');
    expect(validated.port).toBe(443);
    expect(validated.url).toBe('https://example.com/path?foo=bar');
  });
});
