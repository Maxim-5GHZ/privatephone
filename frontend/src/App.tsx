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

  // Sidebar badges: unread = messages from others, sos = active alerts,
  // talking = active PTT session. Admin entry is admin-only.
  const unread = mesh.hydratedMessages.filter((m) => m.sender !== callsign).length
  const sosCount = mesh.hydratedAlerts.length
  const talking = rtc.pttTalking || rtc.pttTalker !== null

  return (
    <div className="app">
      <header>
        <div className="brand">ПАК АСК</div>
        <nav aria-label="Основная навигация">
          <button className={tab === 'map' ? 'active' : ''} onClick={() => setTab('map')}>
            Карта{sosCount > 0 && <span className="nav-badge danger">{sosCount}</span>}
          </button>
          <button className={tab === 'chat' ? 'active' : ''} onClick={() => setTab('chat')}>
            Сообщения{unread > 0 && <span className="nav-badge">{unread > 99 ? '99+' : unread}</span>}
          </button>
          {mesh.isAdmin && (
            <button className={tab === 'admin' ? 'active' : ''} onClick={() => setTab('admin')} title="Панель оператора">
              ⚙ Админ
            </button>
          )}
          <button
            className={rtc.pttOpen ? 'active' : ''}
            onClick={() => rtc.setPttOpen((v) => !v)}
            title="Рация — док-панель поверх текущего экрана"
          >
            Рация{talking && <span className="nav-badge talk">●</span>}
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
        <div className="notice" role="alert" onClick={() => mesh.setNotice(null)}>
          {mesh.notice}
        </div>
      )}

      <div className="toasts" aria-live="polite">
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
          recent={rtc.pttRecent}
          callLog={rtc.callLog}
          onClearLog={rtc.clearHistory}
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
          files={mesh.hydratedFiles}
          messagesMore={mesh.messagesMore}
          typing={mesh.typing}
          reads={mesh.reads}
          chats={mesh.chats}
          subscribers={mesh.subscribers}
          online={mesh.online}
          myCallsign={callsign}
          onSend={(b, r) => void mesh.sendMessage(b, r)}
          onUpdateMessage={(m, b) => mesh.updateMessage(m, b)}
          onDeleteMessage={(m) => void mesh.deleteMessage(m)}
          onSendFile={(name, mime, data, r) => mesh.sendFile(name, mime, data, r)}
          onEnsureBlob={(f) => mesh.ensureFileBlob(f)}
          onLoadHistory={() => void mesh.loadHistory()}
          onTyping={(to) => mesh.sendTyping(to)}
          onRead={(to, n) => mesh.sendRead(to, n)}
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
