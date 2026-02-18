// Authentication utilities for frontend with Supabase
class Auth {
    constructor() {
        // Production URL only - Render backend
        this.API_BASE_URL = 'https://biu-legacycampus.onrender.com/api';
        this.currentUser = null;
        this.loadUserFromStorage();
    }

    // Load user from localStorage
    loadUserFromStorage() {
        const userStr = localStorage.getItem('user');
        if (userStr) {
            try {
                this.currentUser = JSON.parse(userStr);
            } catch (e) {
                console.error('Failed to parse user from storage:', e);
                this.clearAuth();
            }
        }
    }

    // Check if user is logged in (synchronous)
    isLoggedIn() {
        return !!localStorage.getItem('token');
    }

    // Login function with Supabase
    async login(email, password) {
        try {
            const response = await fetch(`${this.API_BASE_URL}/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email, password })
            });

            // Check if response is OK and has content
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
            }

            // Check if response has content
            const contentType = response.headers.get('content-type');
            if (!contentType || !contentType.includes('application/json')) {
                throw new Error('Server returned non-JSON response');
            }

            const data = await response.json();

            if (data.success) {
                // Save token and user data from Supabase
                localStorage.setItem('token', data.token);
                localStorage.setItem('user', JSON.stringify(data.user));
                localStorage.setItem('supabase_user_id', data.user.id); // Store Supabase user ID
                this.currentUser = data.user;
                
                return { 
                    success: true, 
                    message: data.message,
                    user: data.user,
                    token: data.token 
                };
            } else {
                return { 
                    success: false, 
                    message: data.message || 'Login failed' 
                };
            }
        } catch (error) {
            console.error('Login error:', error);
            return { 
                success: false, 
                message: error.message || 'Network error. Please try again.' 
            };
        }
    }

    // Check authentication and redirect if not logged in
    async requireAuth() {
        if (!this.isLoggedIn()) {
            this.redirectToLogin();
            return null;
        }

        try {
            const user = await this.checkAuth();
            if (!user) {
                this.redirectToLogin();
                return null;
            }
            return user;
        } catch (error) {
            console.error('Auth check error:', error);
            this.redirectToLogin();
            return null;
        }
    }

    // Check authentication with server validation (Supabase session check)
    async checkAuth() {
        const token = localStorage.getItem('token');
        
        if (!token) {
            return null;
        }

        try {
            const response = await fetch(`${this.API_BASE_URL}/auth/check`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (response.ok) {
                const data = await response.json();
                if (data.success) {
                    this.currentUser = data.user;
                    localStorage.setItem('user', JSON.stringify(data.user));
                    return this.currentUser;
                }
            }
            
            // If response is not ok, clear auth
            if (response.status === 401) {
                this.clearAuth();
            }
            return null;
            
        } catch (error) {
            console.warn('Auth check failed:', error);
            return null;
        }
    }

    // Get current user info
    getCurrentUser() {
        return this.currentUser;
    }

    // Get Supabase user ID
    getSupabaseUserId() {
        return localStorage.getItem('supabase_user_id');
    }

    // Get auth token
    getToken() {
        return localStorage.getItem('token');
    }

    // Logout (clear Supabase session)
    async logout() {
        try {
            const token = this.getToken();
            if (token) {
                // Attempt to notify server, but don't wait for response
                fetch(`${this.API_BASE_URL}/auth/logout`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                }).catch(err => console.warn('Logout notification failed:', err));
            }
        } catch (error) {
            console.error('Logout error:', error);
        }

        this.clearAuth();
        window.location.href = '/';
    }

    // Clear authentication data
    clearAuth() {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        localStorage.removeItem('email');
        localStorage.removeItem('name');
        localStorage.removeItem('role');
        localStorage.removeItem('department');
        localStorage.removeItem('supabase_user_id');
        this.currentUser = null;
    }

    // Redirect to login page
    redirectToLogin() {
        // Only redirect if we're not already on login page
        const currentPath = window.location.pathname;
        if (!currentPath.includes('login') && currentPath !== '/') {
            window.location.href = '/';
        }
    }

    // Add authorization headers to fetch requests
    getAuthHeaders() {
        const token = this.getToken();
        const headers = {
            'Content-Type': 'application/json'
        };
        
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        
        return headers;
    }

    // Wrapper for fetch with authentication
    async authFetch(url, options = {}) {
        const headers = this.getAuthHeaders();
        
        try {
            const response = await fetch(`${this.API_BASE_URL}${url}`, {
                ...options,
                headers: {
                    ...headers,
                    ...options.headers
                }
            });

            if (response.status === 401) {
                // Token expired or invalid
                this.clearAuth();
                window.location.href = '/';
                throw new Error('Session expired. Please login again.');
            }

            return response;
        } catch (error) {
            console.error('Auth fetch error:', error);
            throw error;
        }
    }

    // Check user role
    isAdmin() {
        return this.currentUser && this.currentUser.role === 'admin';
    }

    // Check user role
    isSecurity() {
        return this.currentUser && this.currentUser.role === 'security';
    }

    // Check if user is a student
    isStudent() {
        return this.currentUser && this.currentUser.role === 'student';
    }
}

// Create global auth instance
window.auth = new Auth();

// Initialize auth on page load for dashboard pages
document.addEventListener('DOMContentLoaded', async () => {
    // Don't check auth on login page
    if (window.location.pathname === '/' || 
        window.location.pathname.includes('login')) {
        
        // If already logged in on login page, redirect to dashboard
        if (auth.isLoggedIn()) {
            const user = await auth.checkAuth();
            if (user) {
                window.location.href = '/index.html';
            }
        }
        return;
    }

    // For all other pages, require authentication
    try {
        const user = await auth.requireAuth();
        if (user) {
            console.log('User authenticated:', user);
            
            // Update profile in sidebar
            const profileName = document.querySelector('.profile-name');
            const profileRole = document.querySelector('.profile-role');
            const userAvatar = document.querySelector('.user-avatar span');
            
            if (profileName) {
                profileName.textContent = user.name || user.email || 'User';
            }
            
            if (profileRole) {
                profileRole.textContent = user.department || user.role || 'Security Dept';
            }

            if (userAvatar) {
                userAvatar.textContent = (user.name || user.email || 'U').charAt(0).toUpperCase();
            }

            // Update logout button
            const logoutBtn = document.getElementById('logoutBtn');
            if (logoutBtn) {
                // Remove any existing event listeners
                const newLogoutBtn = logoutBtn.cloneNode(true);
                logoutBtn.parentNode.replaceChild(newLogoutBtn, logoutBtn);
                
                newLogoutBtn.addEventListener('click', async (e) => {
                    e.preventDefault();
                    if (confirm('Are you sure you want to logout?')) {
                        await auth.logout();
                    }
                });
            }
        }
    } catch (error) {
        console.error('Auth initialization error:', error);
    }
});

// Add global error handler for fetch failures
window.addEventListener('unhandledrejection', function(event) {
    if (event.reason && event.reason.message && 
        (event.reason.message.includes('Failed to fetch') || 
         event.reason.message.includes('Network error'))) {
        console.warn('Network error detected - server might be starting up');
        // Optionally show a user-friendly message
    }
});