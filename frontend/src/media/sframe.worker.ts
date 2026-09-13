// SFrame transform worker: attached to RTCRtpScriptTransform on the sender
// (encrypt) or receiver (decrypt) side. Runs inside the WebRTC encoded-media
// pipeline, so audio frames never leave the page unencrypted.
//
// The worker is Vite-bundled as a module worker; options carry the group
// SFrame key (structured-clone to a private copy) and the direction's keyId.

import { SFrameCodec } from './sframe'

interface SFrameWorkerOptions {
  key?: ArrayBuffer
  outKeyId?: number
  inKeyId?: number
}

const selfAny = self as unknown as {
  onrtctransform?: (event: unknown) => void
}

selfAny.onrtctransform = (event) => {
  const transformer = (event as { transformer?: { readable: ReadableStream; writable: WritableStream; options?: unknown } }).transformer
  if (!transformer) return
  const opts = (transformer.options ?? {}) as SFrameWorkerOptions
  if (!opts.key) return
  const codec = new SFrameCodec(new Uint8Array(opts.key))
  const mode = opts.outKeyId !== undefined && opts.inKeyId === undefined ? 'encrypt' : 'decrypt'
  void run(transformer.readable, transformer.writable, codec, mode, opts)
}

async function run(
  readable: ReadableStream<unknown>,
  writable: WritableStream<unknown>,
  codec: SFrameCodec,
  mode: 'encrypt' | 'decrypt',
  opts: SFrameWorkerOptions,
): Promise<void> {
  const reader = readable.getReader()
  const writer = writable.getWriter()
  let counter = 0
  try {
    for (;;) {
      const { value, done } = await reader.read()
      if (done) break
      const frame = value as RTCEncodedAudioFrame & { data: ArrayBuffer }
      const bytes = new Uint8Array(frame.data)
      try {
        if (mode === 'encrypt') {
          const out = await codec.encrypt(bytes, opts.outKeyId!, counter++)
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          ;(frame.data as any) = out.buffer
        } else {
          const opened = await codec.decrypt(bytes, [opts.inKeyId!])
          if (!opened) continue
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          ;(frame.data as any) = opened.pt.buffer
        }
      } catch {
        continue
      }
      await writer.write(value)
    }
  } finally {
    try {
      await writer.close()
    } catch {
      /* peer gone */
    }
  }
}