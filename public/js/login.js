// public/js/login.js
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    const loginError = document.getElementById('loginError');

    if (username === '' || password === '') {
        loginError.textContent = 'Username and password cannot be empty.';
        return;
    }

    try {
        const res = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await res.json();

        if (data.success) {
            // Redirect to protected dashboard route upon successful login
            window.location.href = '/';
        } else {
            loginError.textContent = 'Login failed: ' + data.message;
        }
    } catch (error) {
        console.error('Error during login:', error);
        loginError.textContent = 'An error occurred. Please try again.';
    }
});
