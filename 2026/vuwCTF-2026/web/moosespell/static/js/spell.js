document.getElementById('form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const res = await fetch('/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ spell_id: document.getElementById('spell_id').value }),
    });
    const data = await res.json();
    document.getElementById('error-message').textContent = data.message;
});
