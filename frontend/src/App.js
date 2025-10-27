import React, { useState } from "react";
import { analyzeEmail } from "./api";
import "./App.css";

function App() {
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleAnalyze = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    setResult(null);
    try {
      const res = await analyzeEmail(subject, body);
      setResult(res);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container">
      <h1>PhishScope Lite</h1>
      <form onSubmit={handleAnalyze}>
        <input
          placeholder="Subject"
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
        />
        <textarea
          placeholder="Paste email body here..."
          value={body}
          onChange={(e) => setBody(e.target.value)}
          rows={10}
        />
        <button type="submit" disabled={loading}>
          {loading ? "Analyzing..." : "Analyze"}
        </button>
      </form>

      {error && <div className="error">Error: {error}</div>}

      {result && (
        <div className="result">
          <h2>Result: {result.label.toUpperCase()} ({(result.phishing_probability*100).toFixed(1)}%)</h2>
          <div>
            <strong>Regex flags:</strong>
            <pre>{JSON.stringify(result.regex_flags, null, 2)}</pre>
          </div>
          <div>
            <strong>Top tokens:</strong>
            <pre>{JSON.stringify(result.top_tokens, null, 2)}</pre>
          </div>
          <div>
            <strong>Domain analysis:</strong>
            <pre>{JSON.stringify(result.domain_reports, null, 2)}</pre>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
