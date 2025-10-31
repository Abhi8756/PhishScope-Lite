import React, { useState, useMemo } from 'react';
import axios from 'axios';

// --- Icon Components (unchanged) ---
const CheckIcon = () => (
  <svg className="w-5 h-5 text-green-400 mr-3 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
  </svg>
);
const AlertIcon = () => (
  <svg className="w-5 h-5 text-red-400 mr-3 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
  </svg>
);
const LoadingSpinner = () => (
  <svg className="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
  </svg>
);

// --- NEW: Simple Email Regex ---
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export default function App() {
  const [sender, setSender] = useState('');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  // --- NEW: Email Validation State ---
  const isSenderEmailValid = useMemo(() => {
    // It's valid if it's empty OR it matches the regex
    return sender.length === 0 || EMAIL_REGEX.test(sender);
  }, [sender]);

  const API_URL = 'http://127.0.0.1:5001/predict';

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!isSenderEmailValid) return; // Don't submit if email is invalid

    setLoading(true);
    setResult(null);
    setError(null);

    try {
      const response = await axios.post(API_URL, { 
        sender: sender,
        subject: subject,
        body: body 
      });
      setResult(response.data);
    } catch (err) {
      if (err.response && err.response.data && err.response.data.error) {
          setError(err.response.data.error);
      } else {
          setError('Could not connect to the model. Is the backend server running?');
      }
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const getResultClasses = () => {
    if (!result) return 'border-gray-600';
    if (result.prediction === 'Phishing') return 'border-red-500 bg-red-900 bg-opacity-30';
    return 'border-green-500 bg-green-900 bg-opacity-30';
  };
  
  // Form is valid if: email is valid AND one of the fields is filled
  const isFormValid = isSenderEmailValid && (sender || subject || body);

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100 flex items-center justify-center p-4 font-sans">
      <div className="w-full max-w-2xl">
        <h1 className="text-4xl font-bold text-center mb-2 text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-cyan-300">
          Phishing Detector V4
        </h1>
        <p className="text-center text-gray-400 mb-8">
          Enter the email details below to analyze it for phishing threats.
        </p>

        <form onSubmit={handleSubmit}>
          <div className="space-y-4">
            <div>
              <label htmlFor="sender" className="block text-sm font-medium text-gray-300 mb-1">Sender Email</label>
              <input
                type="text"
                id="sender"
                value={sender}
                onChange={(e) => setSender(e.target.value)}
                // --- NEW: Dynamic border color for validation ---
                className={`w-full p-3 bg-gray-800 border-2 rounded-lg text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200 ${
                  isSenderEmailValid ? 'border-gray-700' : 'border-red-500 ring-2 ring-red-500'
                }`}
                placeholder="e.g., support@google.com"
              />
              {!isSenderEmailValid && (
                <p className="text-red-400 text-sm mt-1">Please enter a valid email format.</p>
              )}
            </div>
            
            <div>
              <label htmlFor="subject" className="block text-sm font-medium text-gray-300 mb-1">Subject</label>
              <input
                type="text"
                id="subject"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                className="w-full p-3 bg-gray-800 border-2 border-gray-700 rounded-lg text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200"
                placeholder="e.g., URGENT: Action Required"
              />
            </div>

            <div>
              <label htmlFor="body" className="block text-sm font-medium text-gray-300 mb-1">Email Body</label>
              <textarea
                id="body"
                value={body}
                onChange={(e) => setBody(e.target.value)}
                className="w-full h-40 p-3 bg-gray-800 border-2 border-gray-700 rounded-lg text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200"
                placeholder="Paste the email content here..."
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading || !isFormValid}
            className="w-full mt-6 p-4 bg-blue-600 font-bold rounded-lg text-white hover:bg-blue-500 transition duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center"
          >
            {loading ? <LoadingSpinner /> : 'Analyze Email'}
          </button>
        </form>

        {error && (
          <div className="mt-6 p-4 border-2 border-yellow-500 bg-yellow-900 bg-opacity-30 rounded-lg text-center text-yellow-300">
            <strong>Error:</strong> {error}
          </div>
        )}

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
              <span className="text-lg text-gray-300">Phishing Confidence:</span>
              <span className={`text-2xl font-bold ${result.prediction === 'Phishing' ? 'text-red-400' : 'text-green-400'}`}>
                {(result.confidence * 100).toFixed(2)}%
              </span>
            </div>
            
            {result.reasons && result.reasons.length > 0 && (
              <div className="mt-6">
                <h3 className="text-lg font-semibold mb-3">Analysis Details:</h3>
                <ul className="space-y-2">
                  {result.reasons.map((reason, index) => (
                    <li key={index} className="flex items-start">
                      {result.prediction === 'Phishing' ? <AlertIcon /> : <CheckIcon />}
                      <span className="text-gray-300">{reason}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            
          </div>
        )}
      </div>
    </div>
  );
}