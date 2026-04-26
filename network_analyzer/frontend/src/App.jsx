import React from 'react'
import Dashboard from './components/Dashboard'

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("React Error Boundary caught:", error, errorInfo);
    this.setState({ errorInfo });
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          minHeight: '100vh',
          backgroundColor: '#0f172a',
          color: '#f8fafc',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '32px'
        }}>
          <div style={{
            maxWidth: '600px',
            backgroundColor: '#1e293b',
            padding: '32px',
            borderRadius: '12px',
            border: '1px solid #ef4444'
          }}>
            <h2 style={{ color: '#ef4444', marginBottom: '16px' }}>⚠️ Something went wrong</h2>
            <p style={{ color: '#94a3b8', marginBottom: '16px' }}>The app encountered an error:</p>
            <pre style={{
              backgroundColor: '#0f172a',
              padding: '16px',
              borderRadius: '8px',
              overflow: 'auto',
              fontSize: '12px',
              color: '#fca5a5',
              maxHeight: '200px'
            }}>
              {this.state.error && this.state.error.toString()}
              {this.state.errorInfo && this.state.errorInfo.componentStack}
            </pre>
            <button
              onClick={() => window.location.reload()}
              style={{
                marginTop: '16px',
                padding: '8px 24px',
                backgroundColor: '#3b82f6',
                color: 'white',
                border: 'none',
                borderRadius: '8px',
                cursor: 'pointer',
                fontWeight: 'bold'
              }}
            >
              Reload App
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function App() {
  return (
    <ErrorBoundary>
      <div style={{ minHeight: '100vh', backgroundColor: '#0f172a', color: '#f8fafc' }}>
        <Dashboard />
      </div>
    </ErrorBoundary>
  )
}

export default App
