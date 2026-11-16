import React, { useState, useEffect } from "react";
import "./style.css";

const API = "http://127.0.0.1:8000";

export default function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState([]);
  const [analytics, setAnalytics] = useState({
    total_scans: 0,
    high_risk_count: 0,
    medium_risk_count: 0,
    low_risk_count: 0,
    average_risk_score: 0,
  });

  // Load analytics & history from backend
  async function loadDashboardData() {
    try {
      const [historyRes, analyticsRes] = await Promise.all([
        fetch(`${API}/api/history`),
        fetch(`${API}/api/analytics`),
      ]);

      if (historyRes.ok) {
        const historyData = await historyRes.json();
        setHistory(historyData.history || []);
      }

      if (analyticsRes.ok) {
        const analyticsData = await analyticsRes.json();
        setAnalytics(analyticsData);
      }
    } catch (err) {
      console.error("Could not load dashboard data:", err);
    }
  }

  useEffect(() => {
    loadDashboardData();
  }, []);

  // Handle URL scanning
  async function scan(e) {
    e.preventDefault();
    if (!url.trim()) return;

    setResult(null);
    setError("");
    setLoading(true);

    try {
      const response = await fetch(`${API}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim() }),
      });

      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.detail?.[0]?.msg || "Failed to scan URL");
      }

      const data = await response.json();
      setResult(data);
      loadDashboardData(); // Refresh history and analytics stats
    } catch (err) {
      setError(err.message || "Could not connect to backend server.");
    } finally {
      setLoading(false);
    }
  }

  const getRiskBadgeClass = (level) => {
    if (level === "High") return "badge high-risk";
    if (level === "Medium") return "badge medium-risk";
    return "badge low-risk";
  };

  return (
    <div className="dashboard-container">
      {/* Header Banner */}
      <header className="header">
        <div className="logo-brand">
          <span className="shield-icon">🛡️</span>
          <div>
            <h1>TRUSTSHIELD AI</h1>
            <p className="tagline">Next-Gen AI Phishing & Malicious Web Threat Engine</p>
          </div>
        </div>
      </header>

      {/* Analytics Counter Grid */}
      <section className="analytics-grid">
        <div className="stat-card">
          <span className="stat-label">Total Scans</span>
          <span className="stat-value">{analytics.total_scans}</span>
        </div>
        <div className="stat-card high">
          <span className="stat-label">High Risk Threats</span>
          <span className="stat-value">{analytics.high_risk_count}</span>
        </div>
        <div className="stat-card medium">
          <span className="stat-label">Medium Risk Warnings</span>
          <span className="stat-value">{analytics.medium_risk_count}</span>
        </div>
        <div className="stat-card low">
          <span className="stat-label">Clean / Safe Websites</span>
          <span className="stat-value">{analytics.low_risk_count}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Avg Threat Score</span>
          <span className="stat-value">{analytics.average_risk_score} / 100</span>
        </div>
      </section>

      {/* URL Scanner Form Section */}
      <section className="scanner-section">
        <h2>Inspect & Analyze URL</h2>
        <form onSubmit={scan} className="scan-form">
          <input
            type="text"
            placeholder="Enter web link to scan (e.g. http://paypal-verify-login.xyz)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={loading}
            className="scan-input"
          />
          <button type="submit" disabled={loading} className="scan-button">
            {loading ? "Analyzing..." : "Scan URL 🔍"}
          </button>
        </form>

        {error && <div className="error-banner">⚠️ {error}</div>}
      </section>

      {/* Detailed Scan Result Component */}
      {result && (
        <section className="result-section">
          <div className="result-header">
            <div>
              <h3>Security Assessment Report</h3>
              <p className="scanned-url">{result.url}</p>
            </div>
            <div className={getRiskBadgeClass(result.risk_level)}>
              {result.risk_level.toUpperCase()} RISK
            </div>
          </div>

          <div className="risk-score-container">
            <div className="score-meter">
              <span className="score-number">{result.risk_score}</span>
              <span className="score-max">/100</span>
            </div>
            <div className="score-bar-bg">
              <div
                className={`score-bar-fill ${result.risk_level.toLowerCase()}`}
                style={{ width: `${result.risk_score}%` }}
              ></div>
            </div>
          </div>

          {/* Google Safe Browsing status banner */}
          <div className="safe-browsing-status">
            <strong>Google Safe Browsing Check: </strong>
            {result.google_safe_browsing.is_malicious ? (
              <span className="text-danger">🚨 FLAGGED MALICIOUS</span>
            ) : result.google_safe_browsing.status === "success" ? (
              <span className="text-success">✅ Clean in Google Database</span>
            ) : (
              <span className="text-muted">ℹ️ Standalone Heuristic Scan</span>
            )}
          </div>

          {/* Detailed Risk Indicators List */}
          <div className="indicators-block">
            <h4>Detected Security Indicators ({result.indicators.length})</h4>
            {result.indicators.length === 0 ? (
              <p className="no-indicators">✅ No suspicious security patterns detected for this URL.</p>
            ) : (
              <ul className="indicators-list">
                {result.indicators.map((ind, i) => (
                  <li key={i} className="indicator-item">
                    <span className={`severity-tag ${(ind.severity || "medium").toLowerCase()}`}>
                      {ind.severity || "Warning"}
                    </span>
                    <span className="indicator-name">{ind.name}</span>
                    <span className="indicator-points">+{ind.points} Risk Pts</span>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <p className="disclaimer">{result.disclaimer}</p>
        </section>
      )}

      {/* History Feed Table */}
      <section className="history-section">
        <h2>Recent Scan Intelligence Log</h2>
        {history.length === 0 ? (
          <p className="no-history">No scan logs available yet. Try scanning a URL above!</p>
        ) : (
          <div className="history-table-container">
            <table className="history-table">
              <thead>
                <tr>
                  <th>Target URL</th>
                  <th>Risk Score</th>
                  <th>Risk Level</th>
                  <th>Detected Threats</th>
                  <th>Scanned Time</th>
                </tr>
              </thead>
              <tbody>
                {history.map((item) => (
                  <tr key={item.id}>
                    <td className="url-cell" title={item.url}>{item.url}</td>
                    <td><strong>{item.risk_score} / 100</strong></td>
                    <td>
                      <span className={getRiskBadgeClass(item.risk_level)}>
                        {item.risk_level}
                      </span>
                    </td>
                    <td>{item.indicators.length} issue(s)</td>
                    <td className="time-cell">
                      {new Date(item.scanned_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}