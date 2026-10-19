import { useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { DbmlViewer, darkTheme } from 'dbml-erd-viewer'
import 'dbml-erd-viewer/styles.css'
import './styles.css'

const positionsKey = 'foltivo-dbml-preview-positions'

function readSavedPositions() {
  try {
    return JSON.parse(localStorage.getItem(positionsKey) ?? '{}')
  } catch {
    return {}
  }
}

function App() {
  const [dbml, setDbml] = useState('')
  const [error, setError] = useState('')
  const [positions, setPositions] = useState(readSavedPositions)
  const [refreshKey, setRefreshKey] = useState(0)

  useEffect(() => {
    let active = true
    fetch(`/schema.dbml?updated=${refreshKey}`)
      .then((response) => {
        if (!response.ok) throw new Error(`Could not load DBML (${response.status})`)
        return response.text()
      })
      .then((source) => {
        if (active) {
          setDbml(source)
          setError('')
        }
      })
      .catch((loadError) => {
        if (active) setError(loadError.message)
      })
    return () => {
      active = false
    }
  }, [refreshKey])

  function savePositions(next) {
    setPositions(next)
    localStorage.setItem(positionsKey, JSON.stringify(next))
  }

  function resetPositions() {
    localStorage.removeItem(positionsKey)
    setPositions({})
    setRefreshKey((key) => key + 1)
  }

  return (
    <main className="app-shell">
      <header className="toolbar">
        <div className="brand">
          <strong>Foltivo</strong>
          <span>Database design preview</span>
        </div>
        <div className="toolbar-actions">
          <button type="button" onClick={() => setRefreshKey((key) => key + 1)}>
            Reload DBML
          </button>
          <button type="button" onClick={resetPositions}>
            Reset layout
          </button>
          <a href="/schema.dbml" target="_blank" rel="noreferrer">
            View DBML source
          </a>
        </div>
      </header>
      {error ? (
        <div className="error-panel" role="alert">{error}</div>
      ) : dbml ? (
        <section className="diagram" aria-label="Interactive database diagram">
          <DbmlViewer
            key={refreshKey}
            dbml={dbml}
            theme={darkTheme}
            nodePositions={positions}
            onNodePositionsChange={savePositions}
            layoutOptions={{ algorithm: 'elk', direction: 'LR', horizontalGap: 120, verticalGap: 48 }}
            showControls
            showMiniMap
          />
        </section>
      ) : (
        <div className="loading">Loading DBML…</div>
      )}
    </main>
  )
}

createRoot(document.getElementById('root')).render(<App />)
