import { describe, expect, it } from 'vitest'
import { encId, recipientList } from './content'

describe('recipientList', () => {
  it('empty means broadcast', () => {
    expect(recipientList('')).toEqual([])
  })
  it('single callsign is direct', () => {
    expect(recipientList('alpha')).toEqual(['alpha'])
  })
  it('parses a JSON array group', () => {
    expect(recipientList('["alpha","bravo"]')).toEqual(['alpha', 'bravo'])
  })
  it('malformed array falls back to a single recipient', () => {
    expect(recipientList('["alpha"')).toEqual(['["alpha"'])
  })
})

describe('encId', () => {
  it('is deterministic for the same content', () => {
    expect(encId('ms', 'alpha', 'hello')).toBe(encId('ms', 'alpha', 'hello'))
  })
  it('differs across kinds, senders and content', () => {
    const a = encId('ms', 'alpha', 'hello')
    expect(encId('mk', 'alpha', 'hello')).not.toBe(a)
    expect(encId('ms', 'bravo', 'hello')).not.toBe(a)
    expect(encId('ms', 'alpha', 'world')).not.toBe(a)
  })
  it('embeds the kind and sender for traceability', () => {
    expect(encId('mk', 'alpha', 'x')).toContain('mk:alpha')
  })
})