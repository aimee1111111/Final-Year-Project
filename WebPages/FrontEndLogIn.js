const form = document.getElementById('login-form');
const errorBox = document.getElementById('error-message');

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  errorBox.textContent = '';
  errorBox.style.display = 'none';

  const data = {
    email: form.email.value.trim(),
    password: form.password.value
  };

  if (data.password.length < 8) {
    errorBox.textContent = 'Password must be at least 8 characters long.';
    errorBox.style.display = 'block';
    return;
  }

  try {
    const res = await fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });

    let result = {};
    try { result = await res.json(); } catch {}

    if (res.ok && result.success) {
      window.location.href = result.redirectUrl || '/Home.html';
    } else {
      errorBox.textContent = result.error || 'Login failed. Please check your email and password.';
      errorBox.style.display = 'block';
    }
  } catch (err) {
    errorBox.textContent = 'Network error. Please try again.';
    errorBox.style.display = 'block';
  }
});
