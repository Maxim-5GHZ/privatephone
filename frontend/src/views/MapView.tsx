import { useEffect, useRef, useState } from 'react'
import L from 'leaflet'
import 'leaflet/dist/leaflet.css'
import { MARKER_COLORS, MARKER_LABEL, MARKER_LABELS, MARKER_QUICK, Marker, Zone, timeAgo } from '../types'

interface Props {
  markers: Marker[]
  zones: Zone[]
  myCallsign: string
  onSubmit: (m: { lat: number; lon: number; type: string; desc: string }) => void
  onUpdate: (m: Marker, type: string, desc: string) => void
  onDelete: (m: Marker) => void
  onAlert: (type: string) => void
  onZoneSubmit: (points: [number, number][], name: string, color: string) => void
  onZoneUpdate: (z: Zone, name: string, color: string) => void
  onZoneDelete: (z: Zone) => void
}

interface ZoneDraft {
  points: [number, number][]
  name: string
  color: string
}

function parseZonePoints(z: Zone): [number, number][] {
  try {
    const arr = JSON.parse(z.points) as unknown
    if (Array.isArray(arr)) {
      return arr
        .filter((p) => Array.isArray(p) && p.length === 2)
        .map((p) => {
          const lat = Number((p as [number, number])[0])
          const lon = Number((p as [number, number])[1])
          return Number.isFinite(lat) && Number.isFinite(lon) ? [lat, lon] : null
        })
        .filter((p): p is [number, number] => p !== null)
    }
  } catch {
    /* ignore */
  }
  return []
}

export function MapView({
  markers,
  zones,
  myCallsign,
  onSubmit,
  onUpdate,
  onDelete,
  onAlert,
  onZoneSubmit,
  onZoneUpdate,
  onZoneDelete,
}: Props) {
  const divRef = useRef<HTMLDivElement>(null)
  const mapRef = useRef<L.Map | null>(null)
  const layerRef = useRef<L.LayerGroup | null>(null)
  const drawLayerRef = useRef<L.LayerGroup | null>(null)
  const drawingRef = useRef(false)
  const [form, setForm] = useState<{ lat: number; lon: number } | null>(null)
  const [type, setType] = useState('enemy')
  const [desc, setDesc] = useState('')
  const [editing, setEditing] = useState<Marker | null>(null)
  const [editType, setEditType] = useState('')
  const [editDesc, setEditDesc] = useState('')
  const [hideOld, setHideOld] = useState(false)
  const [drawing, setDrawing] = useState(false)
  const [draft, setDraft] = useState<ZoneDraft | null>(null)
  const [editingZone, setEditingZone] = useState<Zone | null>(null)

  useEffect(() => {
    if (!divRef.current || mapRef.current) return
    const map = L.map(divRef.current, {
      center: [55.7517, 37.6175],
      zoom: 6,
      minZoom: 0,
      maxZoom: 18,
    })
    L.tileLayer('/tiles/{z}/{x}/{y}.png', { maxZoom: 18 }).addTo(map)
    map.on('click', (e: L.LeafletMouseEvent) => {
      if (drawingRef.current) {
        addVertex([Number(e.latlng.lat.toFixed(6)), Number(e.latlng.lng.toFixed(6))])
        return
      }
      setEditing(null)
      setEditingZone(null)
      setForm({ lat: Number(e.latlng.lat.toFixed(6)), lon: Number(e.latlng.lng.toFixed(6)) })
    })
    mapRef.current = map
    layerRef.current = L.layerGroup().addTo(map)
    drawLayerRef.current = L.layerGroup().addTo(map)
    return () => {
      map.remove()
      mapRef.current = null
      layerRef.current = null
      drawLayerRef.current = null
    }
  }, [])

  const addVertex = (pt: [number, number]) => {
    drawPoints.current.push(pt)
    redrawPreview()
  }

  const drawPoints = useRef<[number, number][]>([])

  const redrawPreview = () => {
    const layer = drawLayerRef.current
    if (!layer) return
    layer.clearLayers()
    const pts = drawPoints.current
    for (const p of pts) {
      L.circleMarker(p, { radius: 4, color: '#ff3b30', fillColor: '#ff3b30', fillOpacity: 1 }).addTo(layer)
    }
    if (pts.length > 1) {
      L.polyline(pts, { color: '#ff3b30', weight: 2, dashArray: '6 6' }).addTo(layer)
    }
    if (pts.length >= 3) {
      L.polygon([...pts, pts[0]], { color: '#ff3b30', fillColor: '#ff3b30', fillOpacity: 0.15 }).addTo(layer)
    }
  }

  useEffect(() => {
    drawingRef.current = drawing
    drawPoints.current = []
    drawLayerRef.current?.clearLayers()
  }, [drawing])

  useEffect(() => {
    const layer = layerRef.current
    if (!layer) return
    layer.clearLayers()
    const now = Date.now()
    for (const m of markers) {
      if (hideOld && m.created_at && now - new Date(m.created_at).getTime() > 24 * 3600_000) continue
      const color = MARKER_COLORS[m.type] ?? MARKER_COLORS.other
      const mine = m.sender === myCallsign
      const c = L.circleMarker([m.lat, m.lon], {
        radius: mine ? 10 : 8,
        color,
        fillColor: color,
        fillOpacity: 0.65,
        weight: 2,
      })
      const label = MARKER_LABEL[m.type] ?? m.type
      const actions = mine
        ? `<button class="pop-btn" data-act="edit" data-n="${escapeHtml(m.n)}">изменить</button> ` +
          `<button class="pop-btn" data-act="del" data-n="${escapeHtml(m.n)}">удалить</button>`
        : ''
      c.bindPopup(
        `<b>${escapeHtml(m.sender)}</b> — ${escapeHtml(label)}<br>` +
          `${escapeHtml(m.desc || '')}<br><span class="muted">${timeAgo(m.created_at)}</span>${actions}`,
      )
      c.on('popupopen', () => {
        document.querySelectorAll<HTMLButtonElement>('.pop-btn').forEach((b) => {
          b.onclick = () => {
            const act = b.dataset.act
            const n = b.dataset.n ?? ''
            const mm = markers.find((x) => x.sender === myCallsign && x.n === n)
            if (!mm) return
            if (act === 'edit') {
              setEditing(mm)
              setEditType(mm.type)
              setEditDesc(mm.desc)
            } else if (act === 'del') {
              onDelete(mm)
            }
          }
        })
      })
      c.bindTooltip(m.sender, { direction: 'top', opacity: 0.9 })
      c.addTo(layer)
    }

    for (const z of zones) {
      const pts = parseZonePoints(z)
      if (pts.length < 3) continue
      const mine = z.sender === myCallsign
      const poly = L.polygon(pts, {
        color: z.color,
        weight: 2,
        fillColor: z.color,
        fillOpacity: 0.18,
      })
      const actions = mine
        ? `<button class="pop-btn" data-zact="edit" data-n="${escapeHtml(z.n)}">изменить</button> ` +
          `<button class="pop-btn" data-zact="del" data-n="${escapeHtml(z.n)}">удалить</button>`
        : ''
      poly.bindPopup(
        `<b>${escapeHtml(z.name)}</b> — ${escapeHtml(z.sender)}<br>` +
          `<span class="muted">${pts.length} точек · ${timeAgo(z.created_at)}</span>${actions}`,
      )
      poly.on('popupopen', () => {
        document.querySelectorAll<HTMLButtonElement>('[data-zact]').forEach((b) => {
          b.onclick = () => {
            const act = b.dataset.zact
            const n = b.dataset.n ?? ''
            const zz = zones.find((x) => x.sender === myCallsign && x.n === n)
            if (!zz) return
            if (act === 'edit') setEditingZone(zz)
            else if (act === 'del') onZoneDelete(zz)
          }
        })
      })
      poly.addTo(layer)
    }
  }, [markers, zones, myCallsign, hideOld])

  const quickAdd = (qt: string) => {
    if (!form) return
    onSubmit({ lat: form.lat, lon: form.lon, type: qt, desc: '' })
    setForm(null)
  }

  const submit = () => {
    if (!form) return
    onSubmit({ lat: form.lat, lon: form.lon, type, desc })
    setForm(null)
    setDesc('')
  }

  const saveEdit = () => {
    if (!editing) return
    onUpdate(editing, editType, editDesc)
    setEditing(null)
  }

  const closeDrawing = () => {
    const pts = drawPoints.current
    if (pts.length < 3) {
      setDrawing(false)
      return
    }
    setDraft({ points: pts.slice(), name: '', color: '#ff3b30' })
  }

  const cancelDrawing = () => {
    setDrawing(false)
    drawPoints.current = []
    drawLayerRef.current?.clearLayers()
  }

  const saveZone = () => {
    if (!draft) return
    onZoneSubmit(draft.points, draft.name || 'Зона', draft.color)
    setDraft(null)
    setDrawing(false)
    drawPoints.current = []
    drawLayerRef.current?.clearLayers()
  }

  const saveZoneEdit = () => {
    if (!editingZone) return
    onZoneUpdate(editingZone, editingZone.name || 'Зона', editingZone.color || '#ff3b30')
    setEditingZone(null)
  }

  return (
    <div className="map-wrap">
      <div ref={divRef} className="map" />
      <div className="map-toolbar">
        <button className={drawing ? 'active' : ''} onClick={() => setDrawing((d) => !d)}>
          Полигон
        </button>
        <button onClick={() => onAlert('sos')} style={{ background: '#c62828', color: '#fff' }}>
          SOS
        </button>
        <button onClick={() => onAlert('gather')} style={{ background: '#ef6c00', color: '#fff' }}>
          СБОР
        </button>
        <label className="muted">
          <input type="checkbox" checked={hideOld} onChange={(e) => setHideOld(e.target.checked)} /> скрыть старые (&gt;24ч)
        </label>
      </div>

      {drawing && (
        <div className="draw-help">
          Кликните не менее 3 точек для контура полигона, затем <b>«Завершить»</b>.
          <button onClick={closeDrawing}>Завершить</button>
          <button className="ghost" onClick={cancelDrawing}>
            Отмена
          </button>
        </div>
      )}

      {form && (
        <div className="marker-form">
          <h3>Новая метка</h3>
          <p className="muted">
            {form.lat.toFixed(6)}, {form.lon.toFixed(6)}
          </p>
          <div className="quick">
            {MARKER_QUICK.map((q) => (
              <button key={q} style={{ background: MARKER_COLORS[q] }} onClick={() => quickAdd(q)}>
                {MARKER_LABEL[q] ?? q}
              </button>
            ))}
          </div>
          <select value={type} onChange={(e) => setType(e.target.value)}>
            {MARKER_LABELS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
          <input placeholder="Описание (необязательно)" value={desc} onChange={(e) => setDesc(e.target.value)} />
          <div className="row">
            <button onClick={submit}>Отправить (подписано ЭЦП)</button>
            <button className="ghost" onClick={() => setForm(null)}>
              Отмена
            </button>
          </div>
        </div>
      )}

      {editing && (
        <div className="marker-form">
          <h3>Изменить метку {editing.sender}</h3>
          <select value={editType} onChange={(e) => setEditType(e.target.value)}>
            {MARKER_LABELS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
          <input placeholder="Описание" value={editDesc} onChange={(e) => setEditDesc(e.target.value)} />
          <div className="row">
            <button onClick={saveEdit}>Сохранить</button>
            <button className="ghost" onClick={() => setEditing(null)}>
              Отмена
            </button>
          </div>
        </div>
      )}

      {draft && (
        <div className="marker-form">
          <h3>Новый полигон ({draft.points.length} точек)</h3>
          <input
            placeholder="Название"
            value={draft.name}
            onChange={(e) => setDraft((d) => (d ? { ...d, name: e.target.value } : d))}
          />
          <input
            type="color"
            value={draft.color}
            onChange={(e) => setDraft((d) => (d ? { ...d, color: e.target.value } : d))}
          />
          <div className="row">
            <button onClick={saveZone}>Сохранить (подписано ЭЦП)</button>
            <button className="ghost" onClick={() => setDraft(null)}>
              Отмена
            </button>
          </div>
        </div>
      )}

      {editingZone && (
        <div className="marker-form">
          <h3>Полигон {editingZone.name}</h3>
          <input
            placeholder="Название"
            value={editingZone.name}
            onChange={(e) => setEditingZone({ ...editingZone, name: e.target.value })}
          />
          <input
            type="color"
            value={editingZone.color}
            onChange={(e) => setEditingZone({ ...editingZone, color: e.target.value })}
          />
          <div className="row">
            <button onClick={saveZoneEdit}>Сохранить</button>
            <button className="ghost" onClick={() => setEditingZone(null)}>
              Отмена
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!)
}