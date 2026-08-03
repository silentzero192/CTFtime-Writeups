document.getElementById('form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const res = await fetch('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            username: document.getElementById('username').value,
            password: document.getElementById('password').value,
        }),
    });
    const data = await res.json();
    if (res.status === 201) {
        window.location = '/login';
    } else {
        document.getElementById('error-message').textContent = data.message;
    }
});
