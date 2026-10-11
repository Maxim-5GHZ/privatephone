import { useEffect, useRef, useState } from 'react'
import 'ol/ol.css'
import Map from 'ol/Map'
import View from 'ol/View'
import TileLayer from 'ol/layer/Tile'
import VectorLayer from 'ol/layer/Vector'
import XYZ from 'ol/source/XYZ'
import VectorSource from 'ol/source/Vector'
import Feature from 'ol/Feature'
import Point from 'ol/geom/Point'
import Polygon from 'ol/geom/Polygon'
import LineString from 'ol/geom/LineString'
import { fromLonLat, toLonLat } from 'ol/proj'
import { Style, Circle as CircleStyle, Fill, Stroke, Text } from 'ol/style'
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

type TileSource = 'osm' | 'sat'

const VIEW_KEY = 'pp.map.view'
const BASE_KEY = 'pp.map.base'
const HIDEOLD_KEY = 'pp.map.hideOld'

function loadView(): { center: [number, number]; zoom: number } {
  try {
    const raw = localStorage.getItem(VIEW_KEY)
    if (raw) {
      const v = JSON.parse(raw) as { lon?: number; lat?: number; zoom?: number }
      if (typeof v.lon === 'number' && typeof v.lat === 'number' && typeof v.zoom === 'number') {
        if (Number.isFinite(v.lon) && Number.isFinite(v.lat) && v.zoom >= 0 && v.zoom <= 16) {
          return { center: [v.lon, v.lat], zoom: v.zoom }
        }
      }
    }
  } catch {
    /* ignore */
  }
  return { center: [37.6175, 55.7517], zoom: 6 }
}

function loadBase(): TileSource {
  try {
    if (localStorage.getItem(BASE_KEY) === 'sat') return 'sat'
  } catch {
    /* ignore */
  }
  return 'osm'
}

function loadHideOld(): boolean {
  try {
    return localStorage.getItem(HIDEOLD_KEY) === '1'
  } catch {
    return false
  }
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

function markerStyle(m: Marker, mine: boolean): Style {
  const color = MARKER_COLORS[m.type] ?? MARKER_COLORS.other
  return new Style({
    image: new CircleStyle({
      radius: mine ? 10 : 8,
      fill: new Fill({ color: color + 'A6' }),
      stroke: new Stroke({ color, width: 2 }),
    }),
    text: new Text({
      text: m.sender,
      offsetY: -16,
      fill: new Fill({ color: '#fff' }),
      stroke: new Stroke({ color: '#000', width: 3 }),
      font: '12px sans-serif',
    }),
  })
}

function zoneStyle(z: Zone): Style {
  return new Style({
    fill: new Fill({ color: (z.color || '#ff3b30') + '2E' }),
    stroke: new Stroke({ color: z.color || '#ff3b30', width: 2 }),
  })
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
  const mapRef = useRef<Map | null>(null)
  const markerSourceRef = useRef<VectorSource | null>(null)
  const drawSourceRef = useRef<VectorSource | null>(null)
  const osmLayerRef = useRef<TileLayer<XYZ> | null>(null)
  const satLayerRef = useRef<TileLayer<XYZ> | null>(null)
  const drawingRef = useRef(false)
  const drawPointsRef = useRef<[number, number][]>([])

  const [base, setBase] = useState<TileSource>(loadBase)
  const [form, setForm] = useState<{ lat: number; lon: number } | null>(null)
  const [type, setType] = useState('enemy')
  const [desc, setDesc] = useState('')
  const [editing, setEditing] = useState<Marker | null>(null)
  const [editType, setEditType] = useState('')
  const [editDesc, setEditDesc] = useState('')
  const [hideOld, setHideOld] = useState(loadHideOld)
  // Two-step alarm confirm: first tap arms the button (prevents a stray
  // glove tap from broadcasting SOS/СБОР), second tap within 5s sends it.
  const [armedAlert, setArmedAlert] = useState<string | null>(null)
  const armTimer = useRef<number | null>(null)
  const [drawing, setDrawing] = useState(false)
  const [draft, setDraft] = useState<ZoneDraft | null>(null)
  const [editingZone, setEditingZone] = useState<Zone | null>(null)
  const [selectedMarker, setSelectedMarker] = useState<Marker | null>(null)
  const [selectedZone, setSelectedZone] = useState<Zone | null>(null)

  // latest callbacks/props for the once-registered map click handler (no stale closures)
  const liveRef = useRef({ markers, zones, myCallsign, drawing, onDelete, onZoneDelete })
  liveRef.current = { markers, zones, myCallsign, drawing, onDelete, onZoneDelete }

  useEffect(() => {
    if (!divRef.current || mapRef.current) return
    const osm = new TileLayer({
      source: new XYZ({
        url: '/tiles/osm/{z}/{x}/{y}.png',
        maxZoom: 16,
        attributions: '© OpenStreetMap contributors',
      }),
    })
    const sat = new TileLayer({
      source: new XYZ({
        url: '/tiles/sat/{z}/{x}/{y}.png',
        maxZoom: 16,
        attributions: '© Esri World Imagery',
      }),
      visible: false,
    })
    const markerSource = new VectorSource()
    const markersLayer = new VectorLayer({ source: markerSource, zIndex: 10 })
    const drawSource = new VectorSource()
    const drawLayer = new VectorLayer({
      source: drawSource,
      zIndex: 20,
      style: new Style({
        image: new CircleStyle({ radius: 4, fill: new Fill({ color: '#ff3b30' }) }),
        stroke: new Stroke({ color: '#ff3b30', width: 2, lineDash: [6, 6] }),
        fill: new Fill({ color: '#ff3b3026' }),
      }),
    })
    const map = new Map({
      target: divRef.current,
      layers: [osm, sat, markersLayer, drawLayer],
      view: new View({ center: fromLonLat(loadView().center), zoom: loadView().zoom, minZoom: 0, maxZoom: 16 }),
    })
    // Persist viewport so switching tabs (MapView remounts) keeps the place.
    map.getView().on('change:center', () => {
      try {
        const [lon, lat] = toLonLat(map.getView().getCenter() ?? fromLonLat([37.6175, 55.7517]))
        const zoom = map.getView().getZoom() ?? 6
        localStorage.setItem(VIEW_KEY, JSON.stringify({ lon, lat, zoom }))
      } catch {
        /* ignore */
      }
    })
    map.getView().on('change:resolution', () => {
      try {
        const [lon, lat] = toLonLat(map.getView().getCenter() ?? fromLonLat([37.6175, 55.7517]))
        const zoom = map.getView().getZoom() ?? 6
        localStorage.setItem(VIEW_KEY, JSON.stringify({ lon, lat, zoom }))
      } catch {
        /* ignore */
      }
    })
    map.on('click', (e) => {
      const live = liveRef.current
      const feats = map.getFeaturesAtPixel(e.pixel)
      const hit = feats.find((f) => f.get('ppKind') === 'marker' || f.get('ppKind') === 'zone')
      if (hit) {
        const kind = hit.get('ppKind') as string
        if (kind === 'marker') {
          const key = hit.get('ppKey') as string
          const mm = live.markers.find((x) => `${x.sender}|${x.n}` === key) ?? null
          setSelectedMarker(mm)
          setSelectedZone(null)
        } else {
          const key = hit.get('ppKey') as string
          const zz = live.zones.find((x) => `${x.sender}|${x.n}` === key) ?? null
          setSelectedZone(zz)
          setSelectedMarker(null)
        }
        setForm(null)
        return
      }
      setSelectedMarker(null)
      setSelectedZone(null)
      if (live.drawing) {
        const [lon, lat] = toLonLat(e.coordinate)
        addVertex([Number(lat.toFixed(6)), Number(lon.toFixed(6))])
        return
      }
      const [lon, lat] = toLonLat(e.coordinate)
      setEditing(null)
      setEditingZone(null)
      setForm({ lat: Number(lat.toFixed(6)), lon: Number(lon.toFixed(6)) })
    })
    mapRef.current = map
    markerSourceRef.current = markerSource
    drawSourceRef.current = drawSource
    osmLayerRef.current = osm
    satLayerRef.current = sat
    return () => {
      map.setTarget(undefined)
      mapRef.current = null
      markerSourceRef.current = null
      drawSourceRef.current = null
      osmLayerRef.current = null
      satLayerRef.current = null
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const addVertex = (pt: [number, number]) => {
    drawPointsRef.current.push(pt)
    redrawPreview()
  }

  const redrawPreview = () => {
    const src = drawSourceRef.current
    if (!src) return
    src.clear()
    const pts = drawPointsRef.current.map(([lat, lon]) => fromLonLat([lon, lat]))
    if (pts.length === 0) return
    for (const p of pts) src.addFeature(new Feature(new Point(p)))
    if (pts.length > 1) src.addFeature(new Feature(new LineString(pts)))
    if (pts.length >= 3) src.addFeature(new Feature(new Polygon([[...pts, pts[0]]])));
  }

  useEffect(() => {
    drawingRef.current = drawing
    drawPointsRef.current = []
    drawSourceRef.current?.clear()
    if (!drawing) setDraft(null)
  }, [drawing])

  useEffect(() => {
    osmLayerRef.current?.setVisible(base === 'osm')
    satLayerRef.current?.setVisible(base === 'sat')
    try {
      localStorage.setItem(BASE_KEY, base)
    } catch {
      /* ignore */
    }
  }, [base])

  useEffect(() => {
    try {
      localStorage.setItem(HIDEOLD_KEY, hideOld ? '1' : '0')
    } catch {
      /* ignore */
    }
  }, [hideOld])

  useEffect(() => {
    return () => {
      if (armTimer.current !== null) window.clearTimeout(armTimer.current)
    }
  }, [])

  const pressAlert = (kind: string) => {
    if (armedAlert !== kind) {
      setArmedAlert(kind)
      if (armTimer.current !== null) window.clearTimeout(armTimer.current)
      armTimer.current = window.setTimeout(() => setArmedAlert(null), 5000)
      return
    }
    if (armTimer.current !== null) window.clearTimeout(armTimer.current)
    setArmedAlert(null)
    onAlert(kind)
  }

  // rebuild vector features from props (clears stale popups implicitly)
  useEffect(() => {
    const src = markerSourceRef.current
    if (!src) return
    src.clear()
    const now = Date.now()
    for (const m of markers) {
      if (hideOld && m.created_at && now - new Date(m.created_at).getTime() > 24 * 3600_000) continue
      const f = new Feature({ geometry: new Point(fromLonLat([m.lon, m.lat])) })
      f.set('ppKind', 'marker')
      f.set('ppKey', `${m.sender}|${m.n}`)
      f.setStyle(markerStyle(m, m.sender === myCallsign))
      src.addFeature(f)
    }
    for (const z of zones) {
      const pts = parseZonePoints(z)
      if (pts.length < 3) continue
      const ring = pts.map(([lat, lon]) => fromLonLat([lon, lat]))
      ring.push(ring[0])
      const f = new Feature({ geometry: new Polygon([ring]) })
      f.set('ppKind', 'zone')
      f.set('ppKey', `${z.sender}|${z.n}`)
      f.setStyle(zoneStyle(z))
      src.addFeature(f)
    }
    // drop selection if the object vanished
    if (selectedMarker && !markers.some((x) => x.sender === selectedMarker.sender && x.n === selectedMarker.n)) {
      setSelectedMarker(null)
    }
    if (selectedZone && !zones.some((x) => x.sender === selectedZone.sender && x.n === selectedZone.n)) {
      setSelectedZone(null)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
    const pts = drawPointsRef.current
    if (pts.length < 3) {
      setDrawing(false)
      return
    }
    setDraft({ points: pts.slice(), name: '', color: '#ff3b30' })
  }

  const cancelDrawing = () => {
    setDrawing(false)
    drawPointsRef.current = []
    drawSourceRef.current?.clear()
  }

  const saveZone = () => {
    if (!draft) return
    onZoneSubmit(draft.points, draft.name || 'Зона', draft.color)
    setDraft(null)
    setDrawing(false)
    drawPointsRef.current = []
    drawSourceRef.current?.clear()
  }

  const saveZoneEdit = () => {
    if (!editingZone) return
    onZoneUpdate(editingZone, editingZone.name || 'Зона', editingZone.color || '#ff3b30')
    setEditingZone(null)
  }

  const selMarkerMine = selectedMarker?.sender === myCallsign
  const selZoneMine = selectedZone?.sender === myCallsign

  return (
    <div className="map-wrap">
      <div ref={divRef} className="map" />
      <div className="map-toolbar">
        <label className="sr-only" htmlFor="map-base">
          Слой карты
        </label>
        <select id="map-base" value={base} onChange={(e) => setBase(e.target.value as TileSource)} title="Слой карты">
          <option value="osm">Схема</option>
          <option value="sat">Спутник</option>
        </select>
        <button className={drawing ? 'active' : ''} onClick={() => setDrawing((d) => !d)}>
          Полигон{drawing ? ' ✓' : ''}
        </button>
        <button
          onClick={() => pressAlert('sos')}
          className={armedAlert === 'sos' ? 'alarm-armed' : ''}
          style={{ background: armedAlert === 'sos' ? '#ff5252' : '#c62828', color: '#fff' }}
          title={armedAlert === 'sos' ? 'Нажмите ещё раз для отправки SOS' : 'SOS — требуется подтверждение'}
        >
          {armedAlert === 'sos' ? 'SOS?! ЖМИ' : 'SOS'}
        </button>
        <button
          onClick={() => pressAlert('gather')}
          className={armedAlert === 'gather' ? 'alarm-armed' : ''}
          style={{ background: armedAlert === 'gather' ? '#ff9800' : '#ef6c00', color: '#fff' }}
          title={armedAlert === 'gather' ? 'Нажмите ещё раз для отправки СБОР' : 'СБОР — требуется подтверждение'}
        >
          {armedAlert === 'gather' ? 'СБОР?! ЖМИ' : 'СБОР'}
        </button>
        <label className="muted">
          <input type="checkbox" checked={hideOld} onChange={(e) => setHideOld(e.target.checked)} /> скрыть старые (&gt;24ч)
        </label>
      </div>

      {selectedMarker && (
        <div className="marker-form">
          <h3>
            {selectedMarker.sender} — {MARKER_LABEL[selectedMarker.type] ?? selectedMarker.type}
          </h3>
          <p className="muted">
            {selectedMarker.desc || '—'}
            <br />
            <span>{timeAgo(selectedMarker.created_at)}</span>
          </p>
          <div className="row">
            {selMarkerMine && (
              <>
                <button
                  onClick={() => {
                    setEditing(selectedMarker)
                    setEditType(selectedMarker.type)
                    setEditDesc(selectedMarker.desc)
                    setSelectedMarker(null)
                  }}
                >
                  Изменить
                </button>
                <button
                  className="ghost"
                  onClick={() => {
                    onDelete(selectedMarker)
                    setSelectedMarker(null)
                  }}
                >
                  Удалить
                </button>
              </>
            )}
            <button className="ghost" onClick={() => setSelectedMarker(null)}>
              Закрыть
            </button>
          </div>
        </div>
      )}

      {selectedZone && !selectedMarker && (
        <div className="marker-form">
          <h3>{selectedZone.name}</h3>
          <p className="muted">
            {selectedZone.sender} · {parseZonePoints(selectedZone).length} точек · {timeAgo(selectedZone.created_at)}
          </p>
          <div className="row">
            {selZoneMine && (
              <>
                <button
                  onClick={() => {
                    setEditingZone(selectedZone)
                    setSelectedZone(null)
                  }}
                >
                  Изменить
                </button>
                <button
                  className="ghost"
                  onClick={() => {
                    onZoneDelete(selectedZone)
                    setSelectedZone(null)
                  }}
                >
                  Удалить
                </button>
              </>
            )}
            <button className="ghost" onClick={() => setSelectedZone(null)}>
              Закрыть
            </button>
          </div>
        </div>
      )}

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
