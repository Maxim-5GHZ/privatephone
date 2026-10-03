import { useEffect, useRef, useState } from 'react'
import { WSHandle } from './api/client'
import { getCallsign } from './crypto/signing'
import { useMesh } from './hooks/useMesh'
import { SignalFn, useRtc } from './hooks/useRtc'
import { AdminView } from './views/AdminView'
import { AlertBanner } from './views/AlertBanner'
import { CallOverlay } from './views/CallOverlay'
import { ChatView } from './views/ChatView'
import { Login } from './views/Login'
import { MapView } from './views/MapView'
import { PttAudioRenderer } from './views/PttAudio'
import { PttPanel } from './views/PttPanel'
import './index.css'

type Tab = 'map' | 'chat' | 'admin'

export default function App() {
  const [callsign, setCallsign] = useState<string | null>(() => getCallsign())
  const [tab, setTab] = useState<Tab>('map')

  const wsRef = useRef<WSHandle | null>(null)
  const pubsRef = useRef<Map<string, string>>(new Map())
  const signalRef = useRef<SignalFn>(() => {})

  const mesh = useMesh({ callsign, wsRef, pubsRef, signalRef })
  const rtc = useRtc({ callsign, wsRef, pubsRef, onError: mesh.setNotice })

  useEffect(() => {
    signalRef.current = rtc.handleSignal
  }, [rtc.handleSignal])

  const doLogout = () => {
    rtc.reset()
    mesh.logoutLocal()
    setCallsign(null)
    setTab('map')
  }

  if (!callsign) return <Login onLogin={setCallsign} />

  return (
    <div className="app">
      <header>
        <div className="brand">ПАК АСК</div>
        <nav>
          <button className={tab === 'map' ? 'active' : ''} onClick={() => setTab('map')}>
            Карта
          </button>
          <button className={tab === 'chat' ? 'active' : ''} onClick={() => setTab('chat')}>
            Сообщения
          </button>
          <button className={tab === 'admin' ? 'active' : ''} onClick={() => setTab('admin')}>
            Админ
          </button>
          <button className={rtc.pttOpen ? 'active' : ''} onClick={() => rtc.setPttOpen((v) => !v)}>
            Рация
          </button>
        </nav>
        <div className="status">
          <span className={`dot ${mesh.connected ? 'ok' : 'bad'}`} /> {mesh.connected ? 'связь' : 'нет канала'}
        </div>
        <div className="who">
          <span className="callsign">{callsign}</span>
          <button className="ghost" onClick={doLogout}>
            Выйти
          </button>
        </div>
      </header>

      {mesh.notice && (
        <div className="notice" onClick={() => mesh.setNotice(null)}>
          {mesh.notice}
        </div>
      )}

      <div className="toasts">
        {mesh.toasts.map((t) => (
          <div key={t.id} className="event-toast">
            {t.text}
          </div>
        ))}
      </div>

      <AlertBanner
        alerts={mesh.hydratedAlerts}
        myCallsign={callsign}
        isAdmin={mesh.isAdmin}
        onAck={(a) => void mesh.ackAlert(a)}
        onClear={(a) => void mesh.clearAlert(a)}
      />

      {rtc.pttOpen && (
        <PttPanel
          online={mesh.online}
          myCallsign={callsign}
          session={rtc.pttSession}
          talker={rtc.pttTalker}
          talkingMe={rtc.pttTalking}
          secure={rtc.pttSecure}
          onStart={rtc.startPtt}
          onKey={rtc.keyPtt}
          onEnd={rtc.endPtt}
        />
      )}
      <PttAudioRenderer streams={rtc.pttStreams} talker={rtc.pttTalker} />

      {tab === 'map' && (
        <MapView
          markers={mesh.hydratedMarkers}
          zones={mesh.hydratedZones}
          myCallsign={callsign}
          onSubmit={(m) => void mesh.sendMarker(m)}
          onUpdate={(m, type, desc) => void mesh.updateMarker(m, type, desc)}
          onDelete={(m) => void mesh.deleteMarker(m)}
          onAlert={(t) => void mesh.sendAlert(t)}
          onZoneSubmit={(points, name, color) => void mesh.sendZone(points, name, color)}
          onZoneUpdate={(z, name, color) => void mesh.updateZone(z, name, color)}
          onZoneDelete={(z) => void mesh.deleteZone(z)}
        />
      )}
      {tab === 'chat' && (
        <ChatView
          messages={mesh.hydratedMessages}
          chats={mesh.chats}
          subscribers={mesh.subscribers}
          online={mesh.online}
          myCallsign={callsign}
          onSend={(b, r) => void mesh.sendMessage(b, r)}
          onCall={rtc.startCall}
        />
      )}
      {tab === 'admin' && (
        <AdminView
          subscribers={mesh.subscribers}
          chats={mesh.chats}
          isAdmin={mesh.isAdmin}
          onCreate={mesh.createSubscriber}
          onRefresh={mesh.refreshSubscribers}
          onRevoke={mesh.changeSubscriberStatus}
          onChatCreate={mesh.createChat}
          onChatUpdate={mesh.updateChat}
          onChatDelete={mesh.deleteChat}
          onChatsRefresh={mesh.refreshChats}
        />
      )}

      <CallOverlay
        call={rtc.call}
        remote={rtc.remote}
        secure={rtc.callSecure}
        onAccept={rtc.acceptCall}
        onReject={rtc.rejectCall}
        onHangup={rtc.hangupCall}
      />
    </div>
  )
}
