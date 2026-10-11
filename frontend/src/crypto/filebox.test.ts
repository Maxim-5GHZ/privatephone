import { describe, expect, it } from 'vitest'
import { b64decode, b64encode, openFile, parseFileKey, sealFile } from './filebox'

describe('filebox', () => {
  it('seal/open round-trips bytes', async () => {
    const data = new TextEncoder().encode('тактическая схема 123')
    const sealed = await sealFile(data)
    // iv(12) prefix + ciphertext, nothing in clear
    expect(sealed.raw.length).toBeGreaterThan(data.length + 12)
    expect(Buffer.from(sealed.raw).toString('utf8')).not.toContain('схема')
    const plain = await openFile(sealed.raw, sealed.fileKey)
    expect(new TextDecoder().decode(plain)).toBe('тактическая схема 123')
  })

  it('wrong key fails to open', async () => {
    const sealed = await sealFile(new TextEncoder().encode('secret'))
    const wrong = new Uint8Array(32)
    crypto.getRandomValues(wrong)
    await expect(openFile(sealed.raw, wrong)).rejects.toThrow()
  })

  it('b64 round-trips binary', () => {
    const raw = new Uint8Array([0, 1, 250, 255, 128, 77])
    expect(b64decode(b64encode(raw))).toEqual(raw)
  })

  it('parseFileKey validates envelope JSON', () => {
    expect(parseFileKey('not json')).toBeNull()
    expect(parseFileKey('{"name":"x"}')).toBeNull()
    const info = parseFileKey('{"k":"a2V5","name":"план.png","mime":"image/png","size":42}')
    expect(info).toEqual({ k: 'a2V5', name: 'план.png', mime: 'image/png', size: 42 })
  })
})
