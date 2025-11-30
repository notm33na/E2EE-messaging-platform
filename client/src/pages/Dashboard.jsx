import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import WebSocketTest from '../components/WebSocketTest';
import './Dashboard.css';

export function Dashboard() {
  const { user, logout, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  if (!isAuthenticated) {
    return null;
  }

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <h1>Dashboard</h1>
        <button onClick={handleLogout} className="logout-button">
          Logout
        </button>
      </div>

      <div className="dashboard-content">
        <div className="user-info-card">
          <h2>Welcome, {user?.email}!</h2>
          <div className="user-details">
            <p><strong>Email:</strong> {user?.email}</p>
            <p><strong>Account Created:</strong> {user?.createdAt ? new Date(user.createdAt).toLocaleDateString() : 'N/A'}</p>
            <p><strong>Last Login:</strong> {user?.lastLoginAt ? new Date(user.lastLoginAt).toLocaleDateString() : 'N/A'}</p>
            <p><strong>Status:</strong> <span className={user?.isActive ? 'status-active' : 'status-inactive'}>
              {user?.isActive ? 'Active' : 'Inactive'}
            </span></p>
          </div>
        </div>

        <div className="websocket-section">
          <WebSocketTest />
        </div>
      </div>
    </div>
  );
}

