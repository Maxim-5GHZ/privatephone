import { useEffect, useMemo, useRef } from 'react'

// PttAudio: React-rendered <audio> sink for PTT peers. The controller only
// reports streams via onStream; the tags live and die with this component.
function PttAudio({ stream, muted }: { stream: MediaStream; muted: boolean }) {
  const audioRef = useRef<HTMLAudioElement>(null)

  useEffect(() => {
    const el = audioRef.current
    if (!el || !stream) return
    el.srcObject = stream
    el.volume = muted ? 0 : 1
    void el.play().catch(() => {})
  }, [stream, muted])

  return <audio ref={audioRef} autoPlay style={{ display: 'none' }} />
}

export function PttAudioRenderer({ streams, talker }: { streams: Map<string, MediaStream>; talker: string | null }) {
  const items = useMemo(() => Array.from(streams.entries()), [streams])
  if (items.length === 0) return null
  return (
    <>
      {items.map(([peer, stream]) => (
        <PttAudio key={peer} stream={stream} muted={peer !== talker} />
      ))}
    </>
  )
}