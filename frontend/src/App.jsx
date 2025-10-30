import React, { useState } from 'react';
import axios from 'axios'; // Used to call our backend

export default function App() {
  const [text, setText] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null); // Will store { prediction, confidence }
  const [error, setError] = useState(null);

  // The API URL our backend is running on
  // Make sure your backend (app.py) is running!
  const API_URL = 'http://127.0.0.1:5001/predict';

  const handleSubmit = async (e) => {
    e.preventDefault(); // Stop the form from refreshing the page
    setLoading(true);
    setResult(null);
    setError(null);

    try {
      // Make the POST request to our Flask backend
      const response = await axios.post(API_URL, { text: text });
      
      // Update state with the result
      setResult(response.data);
    } catch (err) {
      // Handle errors (e.g., backend is down)
      setError('Could not connect to the model. Is the backend server running?');
      console.error(err);
    } finally {
      // Always stop loading, even if there was an error
      setLoading(false);
    }
  };

  // Helper to determine the result panel's border color
  const getResultClasses = () => {
    if (!result) return 'border-gray-600';
    if (result.prediction === 'Phishing') return 'border-red-500 bg-red-900 bg-opacity-30';
    return 'border-green-500 bg-green-900 bg-opacity-30';
  };

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100 flex items-center justify-center p-4 font-sans">
      <div className="w-full max-w-2xl">
        <h1 className="text-4xl font-bold text-center mb-2 text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-cyan-300">
          Phishing Detector
        </h1>
        <p className="text-center text-gray-400 mb-8">
          Paste the full text of an email below to analyze it for phishing threats.
        </p>

        {/* --- Form --- */}
        <form onSubmit={handleSubmit}>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            className="w-full h-48 p-4 bg-gray-800 border-2 border-gray-700 rounded-lg text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200"
            placeholder="Paste your email content here..."
          />
          <button
            type="submit"
            disabled={loading || !text} // Disable button if loading or no text
            className="w-full mt-4 p-4 bg-blue-600 font-bold rounded-lg text-white hover:bg-blue-500 transition duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center"
          >
            {loading ? (
              // Simple loading spinner
              <svg className="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
            ) : (
              'Analyze Text'
            )}
          </button>
        </form>

        {/* --- Error Message --- */}
        {error && (
          <div className="mt-6 p-4 border-2 border-yellow-500 bg-yellow-900 bg-opacity-30 rounded-lg text-center text-yellow-300">
            <strong>Error:</strong> {error}
          </div>
        )}

        {/* --- Result Panel (shows only after a result) --- */}
        {result && (
          <div className={`mt-6 p-6 border-2 rounded-lg ${getResultClasses()} transition-all`}>
            <h2 className="text-2xl font-bold mb-4">Analysis Result:</h2>
            <div className="flex justify-between items-center">
              <span className="text-lg text-gray-300">Prediction:</span>
              <span className={`text-2xl font-bold ${result.prediction === 'Phishing' ? 'text-red-400' : 'text-green-400'}`}>
                {result.prediction}
              </span>
            </div>
            <div className="flex justify-between items-center mt-2">
              <span className="text-lg text-gray-300">Confidence:</span>
              <span className={`text-2xl font-bold ${result.prediction === 'Phishing' ? 'text-red-400' : 'text-green-400'}`}>
                {(result.confidence * 100).toFixed(2)}%
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}