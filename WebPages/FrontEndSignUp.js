const form = document.getElementById('signupForm');
const errorBox = document.getElementById('error-message');

form.addEventListener('submit', async (e) => {
  e.preventDefault();

  if (errorBox) {
    errorBox.textContent = '';
    errorBox.style.display = 'none';
  }

  const data = {
    username: form.username.value.trim(),
    email: form.email.value.trim(),
    password: form.password.value
  };

  console.log('Submitting signup data:', { username: data.username, email: data.email });

  if (data.password.length < 8) {
    if (errorBox) {
      errorBox.textContent = 'Password must be at least 8 characters long.';
      errorBox.style.display = 'block';
    }
    return;
  }

  try {
    const res = await fetch('/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });

    console.log('Response status:', res.status);
    const result = await res.json();
    console.log('Response data:', result);

    const ok = res.ok && (result.success === true || result.status === 'success');

    if (ok) {
      console.log('Signup successful, saving user info and redirecting...');

      // ✅ Store user info in localStorage
      if (result.user_id) localStorage.setItem('user_id', result.user_id);
      if (result.username) localStorage.setItem('username', result.username);
      if (result.email) localStorage.setItem('email', result.email);

      // Redirect to Home or whatever page your API specifies
      window.location.href = result.redirectUrl || '/Home.html';
    } else {
      const errorMsg = result.error || result.message || 'Signup failed. Please try again.';
      console.error('Signup failed:', errorMsg);
      if (errorBox) {
        errorBox.textContent = errorMsg;
        errorBox.style.display = 'block';
      } else {
        alert(errorMsg);
      }
    }
  } catch (err) {
    console.error('Network error:', err);
    const errorMsg = 'Unable to connect to the server. Please check your internet connection and try again.';
    if (errorBox) {
      errorBox.textContent = errorMsg;
      errorBox.style.display = 'block';
    } else {
      alert(errorMsg);
    }
  }
});
