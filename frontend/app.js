const API_BASE = 'http://localhost:8080/api';

// Utility functions
function showResult(elementId, data, isError = false) {
    const element = document.getElementById(elementId);
    element.textContent = JSON.stringify(data, null, 2);
    element.className = `result ${isError ? 'error' : 'success'}`;
}

function updateTokenDisplay(accessToken, refreshToken) {
    if (accessToken) {
        document.getElementById('currentAccessToken').textContent = accessToken;
        document.getElementById('checkToken').value = accessToken;
    }
    if (refreshToken) {
        document.getElementById('currentRefreshToken').textContent = refreshToken;
        document.getElementById('refreshToken').value = refreshToken;
    }
}

function copyAccessToken() {
    const token = document.getElementById('currentAccessToken').textContent;
    if (token !== 'No token yet') {
        navigator.clipboard.writeText(token);
        alert('Access token copied to clipboard!');
    }
}

function copyRefreshToken() {
    const token = document.getElementById('currentRefreshToken').textContent;
    if (token !== 'No token yet') {
        navigator.clipboard.writeText(token);
        alert('Refresh token copied to clipboard!');
    }
}

function clearTokens() {
    document.getElementById('currentAccessToken').textContent = 'No token yet';
    document.getElementById('currentRefreshToken').textContent = 'No token yet';
    document.getElementById('checkToken').value = '';
    document.getElementById('refreshToken').value = '';
}

// API Functions
async function firstLogin() {
    const email = document.getElementById('firstEmail').value;
    const tempPassword = document.getElementById('tempPassword').value;
    const newPassword = document.getElementById('newPassword').value;

    try {
        const response = await fetch(`${API_BASE}/first-login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                email: email,
                password: tempPassword,
                new_password: newPassword
            })
        });

        const data = await response.json();
        
        if (data.success) {
            showResult('firstLoginResult', data);
            updateTokenDisplay(data.token, data.refresh_token);
        } else {
            showResult('firstLoginResult', data, true);
        }
    } catch (error) {
        showResult('firstLoginResult', { error: error.message }, true);
    }
}

async function regularLogin() {
    const email = document.getElementById('regularEmail').value;
    const password = document.getElementById('regularPassword').value;

    try {
        const response = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                email: email,
                password: password
            })
        });

        const data = await response.json();
        
        if (data.success) {
            showResult('regularLoginResult', data);
            updateTokenDisplay(data.token, data.refresh_token);
        } else {
            showResult('regularLoginResult', data, true);
        }
    } catch (error) {
        showResult('regularLoginResult', { error: error.message }, true);
    }
}

async function checkAuth() {
    const token = document.getElementById('checkToken').value;

    if (!token) {
        showResult('checkAuthResult', { error: 'Please enter a token' }, true);
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/check-auth`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        const data = await response.json();
        
        if (data.success) {
            showResult('checkAuthResult', data);
        } else {
            showResult('checkAuthResult', data, true);
        }
    } catch (error) {
        showResult('checkAuthResult', { error: error.message }, true);
    }
}

async function refreshToken() {
    const refreshToken = document.getElementById('refreshToken').value;

    if (!refreshToken) {
        showResult('refreshTokenResult', { error: 'Please enter a refresh token' }, true);
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/refresh-token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                refresh_token: refreshToken
            })
        });

        const data = await response.json();
        
        if (data.success) {
            showResult('refreshTokenResult', data);
            updateTokenDisplay(data.token, data.refresh_token);
        } else {
            showResult('refreshTokenResult', data, true);
        }
    } catch (error) {
        showResult('refreshTokenResult', { error: error.message }, true);
    }
}

// Health check on load
async function checkHealth() {
    try {
        const response = await fetch(`${API_BASE}/health`);
        const data = await response.json();
        console.log('Health check:', data);
    } catch (error) {
        console.error('Health check failed:', error);
    }
}

// Initialize
checkHealth();