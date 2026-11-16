
import { useState, useEffect } from "react";
import "./style.css";

const API = "http://127.0.0.1:8000";

export default function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState([]);

  async function loadHistory() {
    try {
      const response = await fetch(`${API}/api/history`);
      if (!response.ok) throw new Error("History unavailable");

      const data = await response.json();
      setHistory(data.history || []);
    } catch (err) {
      console.error("Could not load scan history:", err);
    }
  }

  useEffect(() => {
    loadHistory();
  }, []);

  async function scan(e) {
    e.preventDefault();
    setResult(null);
    setError("");
    setLoading(true);

    try {
      const response = await fetch(`${API}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail?.[0]?.msg ||
          "Please enter a valid complete URL."
        );
      }

      setResult(data);
      await loadHistory();
    } catch (err) {
      setError(
        err.message ||
        "Could not reach the backend. Check that it is running."
      );
    } finally {
      setLoading(false);
    }
  }

  const totalScans = history.length;

  const highRisk = history.filter(
    item => item.risk_level === "High"
  ).length;

  const mediumRisk = history.filter(
    item => item.risk_level === "Medium"
  ).length;

  const lowRisk = history.filter(
    item => item.risk_level === "Low"
  ).length;

  return (
    <main className="page">

      <nav>
        <div className="brand">
          ✦ TRUSTSHIELD <b>AI</b>
        </div>
        <span>URL SECURITY SCANNER · MVP</span>
      </nav>

      <section className="hero">

        <div className="eyebrow">
          YOUR FIRST LINE OF DIGITAL DEFENCE
        </div>

        <h1>
          Spot risky links.
          <br />
          <em>Browse smarter.</em>
        </h1>

        <p className="intro">
          Scan suspicious URLs and identify potential
          online threats using intelligent security checks.
        </p>

        {/* DASHBOARD STATISTICS */}

        <section className="stats-grid">

          <div className="stat-card">
            <span>Total Scans</span>
            <h2>{totalScans}</h2>
            <small>Recorded scans</small>
          </div>

          <div className="stat-card high-stat">
            <span>High Risk</span>
            <h2>{highRisk}</h2>
            <small>Potential threats</small>
          </div>

          <div className="stat-card medium-stat">
            <span>Medium Risk</span>
            <h2>{mediumRisk}</h2>
            <small>Suspicious URLs</small>
          </div>

          <div className="stat-card low-stat">
            <span>Low Risk</span>
            <h2>{lowRisk}</h2>
            <small>Fewer warning signs</small>
          </div>

        </section>

        <form onSubmit={scan} className="panel">

          <label htmlFor="url">Website URL</label>

          <div className="inputrow">

            <input
              id="url"
              type="url"
              required
              placeholder="https://example.com"
              value={url}
              onChange={e => setUrl(e.target.value)}
            />

            <button disabled={loading}>
              {loading ? "Checking..." : "Scan URL →"}
            </button>

          </div>

          <small>
            Enter a complete URL, including https:// or http://
          </small>

        </form>

        {error && (
          <p className="error">{error}</p>
        )}

        {/* SCAN RESULT */}

        {result && (
          <section className="panel result">

            <div className="resulttop">

              <div>
                <div className="eyebrow">SCAN RESULT</div>
                <h2>{result.risk_level} Risk</h2>
              </div>

              <div className={`score ${result.risk_level.toLowerCase()}`}>
                {result.risk_score}
                <small>/100</small>
              </div>

            </div>

            <p className="scanned">{result.url}</p>

            <div className="google-status">
              <strong>Google Safe Browsing</strong>
              <span>
                {result.google_safe_browsing?.status === "success"
                  ? result.google_safe_browsing.is_malicious
                    ? "⚠ Threat detected"
                    : "✓ No known threat detected"
                  : result.google_safe_browsing?.status === "not_configured"
                    ? "Not configured"
                    : "Service unavailable"}
              </span>
            </div>

            <h3>Signals detected</h3>

            {result.indicators.length ? (
              <ul>
                {result.indicators.map((item, index) => (
                  <li key={index}>
                    <span>{item.name}</span>
                    <b>+{item.points}</b>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted">
                No warning signs detected by these checks.
              </p>
            )}

            <p className="muted disclaimer">
              {result.disclaimer}
            </p>

          </section>
        )}

      </section>

      {/* SCAN HISTORY */}

      <section className="panel history-panel">

        <div className="eyebrow">THREAT INTELLIGENCE</div>

        <h2>Recent scans</h2>

        {history.length === 0 ? (
          <p className="muted">
            No scan history available yet.
          </p>
        ) : (

          <div className="history-list">

            {history.map(item => (

              <div
                className={`history-item risk-${item.risk_level.toLowerCase()}`}
                key={item.id}
              >

                <div>
                  <strong>{item.risk_level} Risk</strong>
                  <p>{item.url}</p>
                  <small>
                    {new Date(item.scanned_at).toLocaleString()}
                  </small>
                </div>

                <span>{item.risk_score}/100</span>

              </div>

            ))}

          </div>

        )}

      </section>

      <footer>
        <b>TRUSTSHIELD AI</b>
        <span>
          Educational prototype · Not a guarantee of website safety
        </span>
      </footer>

    </main>
  );
}
