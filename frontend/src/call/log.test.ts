import { describe, expect, it } from 'vitest'
import { appendCallLog, callLogKey, clearCallLog, loadCallLog, pushTalker } from './log'

// vitest runs in node (no DOM localStorage): stub an in-memory one.
if (typeof localStorage === 'undefined') {
  const mem = new Map<string, string>()
  ;(globalThis as unknown as { localStorage: Storage }).localStorage = {
    getItem: (k: string) => (mem.has(k) ? mem.get(k)! : null),
    setItem: (k: string, v: string) => void mem.set(k, v),
    removeItem: (k: string) => void mem.delete(k),
    clear: () => mem.clear(),
    key: (i: number) => [...mem.keys()][i] ?? null,
    get length() {
      return mem.size
    },
  }
}

describe('call log', () => {
  it('appends and caps at 50', () => {
    clearCallLog('tester')
    for (let i = 0; i < 55; i++) {
      appendCallLog('tester', { peer: `p${i}`, dir: 'out', result: 'ended', at: i })
    }
    const log = loadCallLog('tester')
    expect(log).toHaveLength(50)
    expect(log[0].peer).toBe('p5')
    expect(localStorage.getItem(callLogKey('tester'))).toContain('p54')
    clearCallLog('tester')
    expect(loadCallLog('tester')).toEqual([])
  })

  it('pushTalker skips consecutive dup and caps at 5', () => {
    let q = pushTalker([], 'a', 1)
    q = pushTalker(q, 'a', 2)
    expect(q).toHaveLength(1)
    for (const w of ['b', 'c', 'd', 'e', 'f']) q = pushTalker(q, w)
    expect(q.map((t) => t.who)).toEqual(['b', 'c', 'd', 'e', 'f'])
  })
})
