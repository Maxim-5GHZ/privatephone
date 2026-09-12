let ac: AudioContext | null = null

function ctx(): AudioContext | null {
  try {
    if (!ac) ac = new AudioContext()
    if (ac.state === 'suspended') void ac.resume()
    return ac
  } catch {
    return null
  }
}

export function beep(freq = 880, dur = 0.15, when = 0) {
  const c = ctx()
  if (!c) return
  const o = c.createOscillator()
  const g = c.createGain()
  o.type = 'square'
  o.frequency.value = freq
  g.gain.value = 0.05
  o.connect(g)
  g.connect(c.destination)
  const t = c.currentTime + when
  o.start(t)
  o.stop(t + dur)
}

export function playAlarm() {
  const seq = [0, 0.28, 0.56, 0.95, 1.23, 1.51]
  seq.forEach((t) => beep(950, 0.13, t))
}

export function playAck() {
  beep(1245, 0.08, 0)
  beep(1245, 0.08, 0.12)
}