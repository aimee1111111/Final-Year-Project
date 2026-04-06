/*
  Sign-up form script

  This file handles user registration on the sign-up page.
  It collects the form data, does a simple password length check,
  sends the sign-up request to the backend, shows any errors on screen,
  and redirects the user if registration is successful.
*/

const form = document.getElementById('signupForm');
const errorBox = document.getElementById('error-message');

form.addEventListener('submit', async (e) => {
  e.preventDefault();

  // Clear any old error message before starting a new submission
  if (errorBox) {
    errorBox.textContent = '';
    errorBox.style.display = 'none';
  }

  // Collect the values entered by the user
  const data = {
    username: form.username.value.trim(),
    email: form.email.value.trim(),
    password: form.password.value
  };

  console.log('Submitting signup data:', { username: data.username, email: data.email });

  // Basic frontend validation before sending to the server
  if (data.password.length < 8) {
    if (errorBox) {
      errorBox.textContent = 'Password must be at least 8 characters long.';
      errorBox.style.display = 'block';
    }
    return;
  }

  try {
    // Send the sign-up request to the backend
    const res = await fetch('/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });

    console.log('Response status:', res.status);

    const result = await res.json();
    console.log('Response data:', result);

    // Treat the request as successful if the HTTP response is OK
    // and the backend returns a success flag or status
    const ok = res.ok && (result.success === true || result.status === 'success');

    if (ok) {
      console.log('Signup successful, saving user info and redirecting...');

      // Save returned user information in localStorage
      if (result.user_id) localStorage.setItem('user_id', result.user_id);
      if (result.username) localStorage.setItem('username', result.username);
      if (result.email) localStorage.setItem('email', result.email);

      // Redirect the user after successful sign-up
      window.location.href = result.redirectUrl || '/Home.html';
    } else {
      const errorMsg = result.error || result.message || 'Signup failed. Please try again.';
      console.error('Signup failed:', errorMsg);

      // Show the error inside the page if possible
      if (errorBox) {
        errorBox.textContent = errorMsg;
        errorBox.style.display = 'block';
      } else {
        alert(errorMsg);
      }
    }
  } catch (err) {
    console.error('Network error:', err);

    // Handle connection or server errors
    const errorMsg = 'Unable to connect to the server. Please check your internet connection and try again.';
    if (errorBox) {
      errorBox.textContent = errorMsg;
      errorBox.style.display = 'block';
    } else {
      alert(errorMsg);
    }
  }
});