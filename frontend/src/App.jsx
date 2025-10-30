import { useState } from 'react'
import axios from 'axios'

function App() {
  const [url, setUrl] = useState('')
  const [text, setText] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    
    try {
      const response = await axios.post('/analyze', { url, text })
      setResult(response.data)
    } catch (error) {
      console.error('Error:', error)
      setResult({ error: error.response?.data?.detail || 'Failed to analyze. Please try again.' })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-100 py-6 flex flex-col justify-center sm:py-12">
      <div className="relative py-3 sm:max-w-xl sm:mx-auto">
        <div className="absolute inset-0 bg-gradient-to-r from-cyan-400 to-light-blue-500 shadow-lg transform -skew-y-6 sm:skew-y-0 sm:-rotate-6 sm:rounded-3xl"></div>
        <div className="relative px-4 py-10 bg-white shadow-lg sm:rounded-3xl sm:p-20">
          <div className="max-w-md mx-auto">
            <div className="divide-y divide-gray-200">
              <div className="py-8 text-base leading-6 space-y-4 text-gray-700 sm:text-lg sm:leading-7">
                <h1 className="text-3xl font-bold text-center mb-8">PhishScope Lite</h1>
                <form onSubmit={handleSubmit} className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700">URL to analyze</label>
                    <input
                      type="url"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-cyan-500 focus:ring-cyan-500"
                      placeholder="https://example.com"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Text content</label>
                    <textarea
                      value={text}
                      onChange={(e) => setText(e.target.value)}
                      className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-cyan-500 focus:ring-cyan-500"
                      rows="4"
                      placeholder="Paste the suspicious text here..."
                      required
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={loading}
                    className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-cyan-600 hover:bg-cyan-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyan-500 disabled:opacity-50"
                  >
                    {loading ? 'Analyzing...' : 'Analyze'}
                  </button>
                </form>

                {result && (
                  <div className="mt-8 p-4 bg-gray-50 rounded-lg">
                    {result.error ? (
                      <p className="text-red-600">{result.error}</p>
                    ) : (
                      <div className="space-y-2">
                        <p>
                          <span className="font-semibold">Prediction:</span>{' '}
                          <span className={result.prediction ? 'text-red-600' : 'text-green-600'}>
                            {result.prediction ? 'Phishing' : 'Legitimate'}
                          </span>
                        </p>
                        <p>
                          <span className="font-semibold">Confidence:</span>{' '}
                          {(result.ml_score * 100).toFixed(2)}%
                        </p>
                        <div>
                          <span className="font-semibold">Domain Analysis:</span>
                          <ul className="list-disc list-inside mt-1">
                            {Object.entries(result.domain_analysis).map(([key, value]) => (
                              <li key={key}>
                                {key}: {value.toString()}
                              </li>
                            ))}
                          </ul>
                        </div>
                        <div>
                          <span className="font-semibold">Suspicious Patterns:</span>
                          <ul className="list-disc list-inside mt-1">
                            {result.suspicious_patterns.map((pattern, index) => (
                              <li key={index}>{pattern}</li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default App