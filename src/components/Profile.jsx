import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import axios from 'axios';

const API_URL = '/api';

const Profile = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [isEditing, setIsEditing] = useState(false);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [formData, setFormData] = useState({
    fullName: '',
    profileName: '',
    email: '',
    mobile: '',
    dateOfBirth: '',
    bio: '',
    location: '',
    favoriteGenre: '',
  });

  useEffect(() => {
    if (user) {
      fetchUserProfile();
    }
  }, [user]);

  const fetchUserProfile = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`${API_URL}/auth/verify`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const userData = response.data.user;
      setFormData({
        fullName: userData.fullName || '',
        profileName: userData.profileName || '',
        email: userData.email || '',
        mobile: userData.mobile || '',
        dateOfBirth: userData.dateOfBirth ? userData.dateOfBirth.split('T')[0] : '',
        bio: userData.bio || '',
        location: userData.location || '',
        favoriteGenre: userData.favoriteGenre || '',
      });
    } catch (error) {
      console.error('Error fetching profile:', error);
    }
  };

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');

    try {
      const token = localStorage.getItem('token');
      if (!token) {
        setMessage('Please login again');
        setLoading(false);
        return;
      }
      
      const response = await axios.put(
        `${API_URL}/auth/profile`,
        formData,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setMessage('Profile updated successfully!');
      setIsEditing(false);
      // Refresh user data after update
      fetchUserProfile();
    } catch (error) {
      console.error('Update error:', error);
      if (error.response) {
        setMessage(error.response.data?.message || 'Failed to update profile');
      } else if (error.request) {
        setMessage('Cannot connect to server. Please check if backend is running.');
      } else {
        setMessage('An error occurred. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  if (!user) {
    return <div className="loading-container"><div className="netflix-loader"></div></div>;
  }

  return (
    <div className="profile-page">
      <nav className="profile-navbar">
        <h1 className="logo" onClick={() => navigate('/browse')}>NETFLIX</h1>
      </nav>

      <div className="profile-container">
        <div className="profile-header">
          <div className="profile-avatar">
            <img 
              src={`https://ui-avatars.com/api/?name=${formData.profileName}&background=e50914&color=fff&size=150`}
              alt="Profile" 
            />
          </div>
          <h2>{formData.profileName}</h2>
          <p className="profile-email">{formData.email}</p>
        </div>

        {message && (
          <div className={`profile-message ${message.includes('success') ? 'success' : 'error'}`}>
            {message}
          </div>
        )}

        <div className="profile-content">
          {!isEditing ? (
            <div className="profile-view">
              <div className="profile-section">
                <h3>Profile Information</h3>
                <div className="info-grid">
                  <div className="info-item">
                    <label>Full Name</label>
                    <p>{formData.fullName}</p>
                  </div>
                  <div className="info-item">
                    <label>Profile Name</label>
                    <p>{formData.profileName}</p>
                  </div>
                  <div className="info-item">
                    <label>Email</label>
                    <p>{formData.email}</p>
                  </div>
                  <div className="info-item">
                    <label>Mobile</label>
                    <p>{formData.mobile}</p>
                  </div>
                  <div className="info-item">
                    <label>Date of Birth</label>
                    <p>{formData.dateOfBirth}</p>
                  </div>
                  <div className="info-item">
                    <label>Location</label>
                    <p>{formData.location || 'Not set'}</p>
                  </div>
                  <div className="info-item">
                    <label>Favorite Genre</label>
                    <p>{formData.favoriteGenre || 'Not set'}</p>
                  </div>
                </div>
                {formData.bio && (
                  <div className="bio-section">
                    <label>Bio</label>
                    <p>{formData.bio}</p>
                  </div>
                )}
              </div>
              <button className="edit-profile-btn" onClick={() => setIsEditing(true)}>
                Edit Profile
              </button>
            </div>
          ) : (
            <form className="profile-edit-form" onSubmit={handleSubmit}>
              <h3>Edit Profile</h3>
              <div className="form-grid">
                <div className="form-group">
                  <label>Full Name</label>
                  <input
                    type="text"
                    name="fullName"
                    value={formData.fullName}
                    onChange={handleChange}
                    required
                  />
                </div>
                <div className="form-group">
                  <label>Profile Name</label>
                  <input
                    type="text"
                    name="profileName"
                    value={formData.profileName}
                    onChange={handleChange}
                    required
                  />
                </div>
                <div className="form-group">
                  <label>Email</label>
                  <input
                    type="email"
                    name="email"
                    value={formData.email}
                    disabled
                  />
                </div>
                <div className="form-group">
                  <label>Mobile</label>
                  <input
                    type="tel"
                    name="mobile"
                    value={formData.mobile}
                    onChange={handleChange}
                    required
                  />
                </div>
                <div className="form-group">
                  <label>Date of Birth</label>
                  <input
                    type="date"
                    name="dateOfBirth"
                    value={formData.dateOfBirth}
                    onChange={handleChange}
                    required
                  />
                </div>
                <div className="form-group">
                  <label>Location</label>
                  <input
                    type="text"
                    name="location"
                    value={formData.location}
                    onChange={handleChange}
                    placeholder="City, Country"
                  />
                </div>
                <div className="form-group">
                  <label>Favorite Genre</label>
                  <select
                    name="favoriteGenre"
                    value={formData.favoriteGenre}
                    onChange={handleChange}
                  >
                    <option value="">Select Genre</option>
                    <option value="Action">Action</option>
                    <option value="Comedy">Comedy</option>
                    <option value="Drama">Drama</option>
                    <option value="Horror">Horror</option>
                    <option value="Sci-Fi">Sci-Fi</option>
                    <option value="Thriller">Thriller</option>
                    <option value="Romance">Romance</option>
                    <option value="Documentary">Documentary</option>
                  </select>
                </div>
              </div>
              <div className="form-group full-width">
                <label>Bio</label>
                <textarea
                  name="bio"
                  value={formData.bio}
                  onChange={handleChange}
                  rows="4"
                  placeholder="Tell us about yourself..."
                />
              </div>
              <div className="form-actions">
                <button type="submit" className="save-btn" disabled={loading}>
                  {loading ? 'Saving...' : 'Save Changes'}
                </button>
                <button type="button" className="cancel-btn" onClick={() => setIsEditing(false)}>
                  Cancel
                </button>
              </div>
            </form>
          )}
        </div>

        <div className="profile-actions">
          <button className="logout-btn" onClick={handleLogout}>
            Sign out of Netflix
          </button>
        </div>
      </div>
    </div>
  );
};

export default Profile;
