document.getElementById('form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const res = await fetch('/spells', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            title: document.getElementById('title').value,
            incantation: document.getElementById('incantation').value,
        }),
    });
    const data = await res.json();
    if (res.status === 201) {
        window.location = '/spells/' + data.id;
    } else {
        document.getElementById('error-message').textContent = data.message;
    }
});
