//Password checker
const pw = document.querySelector('#pw');
const pwbar = document.querySelector('#pwbar');
const pwtips = document.querySelector('#pwtips');

function scorePassword(s) {
  if (!s) return 0;
  let score = 0;
   // Track frequency of each character to penalize repeats
  const letters = {};
  for (const ch of s) {
    letters[ch] = (letters[ch] || 0) + 1;
     // Each repeat of the same character contributes less than the previous
    score += 5.0 / letters[ch];
  }
  // Check presence of each character class
  const variations = [/[a-z]/, /[A-Z]/, /\d/, /[^\w]/];
  let variationCount = 0;
  variations.forEach((v) => (variationCount += v.test(s)));
   // Reward diversity of character classes (0–30 points)
  score += (variationCount - 1) * 10;
    // Length bonus for strong passphrases
  if (s.length >= 14) score += 10;
  if (/-|\s/.test(s)) score += 3; // passphrase hyphens/spaces
    // Clamp to 0–100 and return an integer
  return Math.min(100, Math.floor(score));
}
//Generate human-readable advice for improving the password.
function pwAdvice(s) {
  const tips = [];
    // Length and composition suggestions
  if (s.length < 14) tips.push('Use 14+ characters (passphrase works great).');
  if (!/[A-Z]/.test(s)) tips.push('Add an uppercase letter.');
  if (!/[a-z]/.test(s)) tips.push('Add a lowercase letter.');
  if (!/\d/.test(s)) tips.push('Add a number.');
  if (!/[^\w]/.test(s)) tips.push('Add a symbol.');
  if (/([a-zA-Z0-9])\1{2,}/.test(s)) tips.push('Avoid repeating characters.');
  if (/password|qwerty|12345|letmein|admin/i.test(s)) tips.push('Avoid common words.');
  return tips.length ? 'Tips: ' + tips.join(' ') : 'Nice! Consider a manager to store it safely.';
}

// Wire up live scoring only if all required elements exist on the page
if (pw && pwbar && pwtips) {
   // Update visual meter width (0–100%)
  pw.addEventListener('input', () => {
    const s = pw.value.trim();
    const n = scorePassword(s);
    pwbar.style.width = n + '%';
     // Show advice or default helper text
    pwtips.textContent = s ? pwAdvice(s) : 'Start typing to get tips…';
  });
}

// Quiz
const questions = [
  {
    q: 'If you suspect a device is infected with malware, what should you do first?',
    choices: [
      'Ignore it - it might go away.',
      'Send files to friends to test if they can open them',
      'Disconnect from the internet and run a full scan.',
    ],
    correct: 2,
    why: 'Disconnecting contains the threat — it stops data theft and blocks the malware from talking to its command-and-control server or spreading to others. Then a full antivirus scan can safely identify and remove it. Ignoring it or sharing files risks spreading the infection.',
  },
  {
    q: 'Best multi-factor authentication (MFA) option for important accounts:',
    choices: ['SMS codes', 'App-based or hardware security key', 'Email codes'],
    correct: 1,
    why: 'App-based TOTP or security keys resist SIM-swap and interception better than SMS or email.',
  },
  {
    q: 'Password strategy that’s safest:',
    choices: [
      'Use one long password everywhere so it’s easy to remember.',
      'Use a manager to create unique 14+ char passwords for every site.',
      'Write passwords on a sticky note under your keyboard.',
    ],
    correct: 1,
    why: 'Unique + long defeats credential stuffing; a manager helps you do this reliably.',
  },
  {
    q: 'Why is public Wi-Fi risky for sensitive tasks??',
    choices: ['It’s usually slow.', 
      'Others on the network could intercept your data.',
       'It uses too much battery. give a reason.'],
    correct: 1,
    why: 'Public Wi-Fi networks are often unsecured, meaning anyone nearby could spy on or intercept your data. Hackers can capture passwords, messages, or financial info if the connection isn’t encrypted - making it unsafe for sensitive logins or transactions.',
  },
  {
    q: 'A Word document asks you to enable macros to view content. You should…',
    choices: ['Enable macros; it’s probably safe.', 
      'Upload the file to a random “viewer” site.', 
      'Do not enable macros; verify the source or use a safe viewer.'],
    correct: 2,
    why: 'Malware often hides behind macro prompts. Avoid enabling them unless absolutely necessary and verified.',
  },
  {
    q: 'What should you check before entering details on a website',
    choices: ['That the website loads fast and has no ads.',
       'That the address bar shows “https://” and the correct domain name.', 
       'no need to check anything; just trust it.'],
    correct: 1,
    why: 'HTTPS encrypts your data so others can’t steal it, and checking the exact domain helps you avoid phishing sites that imitate real ones',
  },
  {
    q: 'Someone on the phone says they’re IT and need your password to “fix” your account.',
    choices: ['Share your password so they can help.', 
      'Ask for their name and call back using an official number.',
       'Email your password instead.'],
    correct: 1,
    why: 'Legitimate support will never ask for your password. Verify caller identity via official channels.',
  },
  {
    q: 'Your files are encrypted and a ransom note appears. First action?',
    choices: ['Turn off backups to keep them safe.',
       'Disconnect from the network and contact security/IT immediately.', 
       'Pay quickly to get your files back.'],
    correct: 1,
    why: 'Isolate affected machines, alert responders. Paying is risky and not guaranteed.',
  },
  {
    q: 'You clicked a suspicious link and entered your email + password. Best next step:',
    choices: ['Do nothing unless something breaks.',
       'Change the password immediately and enable MFA; watch for alerts.',
        'Delete the email and forget it.'],
    correct: 1,
    why: 'Assume compromise: change password, enable MFA, and monitor activity.',
  },
  {
    q: 'Best backup approach for home or study:',
    choices: ['One copy on the same laptop.',
       '3-2-1 rule: 3 copies, 2 media, 1 off-site/cloud.', 
       'Occasional manual copies when you remember.'],
    correct: 1,
    why: '3-2-1 improves resilience to hardware failure, theft, and ransomware.',
  },
];

// Cache references to key DOM elements for performance and readability
const qwrap = document.getElementById('qwrap');       // Container that will hold all quiz questions
const scorebar = document.getElementById('scorebar'); // The visual progress/score bar element
const scoreText = document.getElementById('scoreText'); // Text element showing "Score: X/10"
const submitBtn = document.getElementById('submitBtn'); // Button that grades the quiz
const resetBtn = document.getElementById('resetBtn');   // Button that resets the quiz

//Renders the quiz questions dynamically inside the #qwrap container.

function renderQuiz() {
  if (!qwrap) return; // Safety check in case the element doesn't exist

  qwrap.innerHTML = ''; // Clear any previous quiz render 

  // Loop over the global "questions" array and build each question block
  questions.forEach((item, idx) => {
    const root = document.createElement('div');
    root.className = 'q'; // Wrapper div for a single question

    // Unique heading ID used for ARIA accessibility 
    const headingId = `q${idx}`;

    // Build inner HTML for each question:
    // - Heading with question text
    // - Set of labeled radio inputs
    // - Hidden explanation block (revealed after grading)
    root.innerHTML = `
      <h4 id="${headingId}">${idx + 1}. ${item.q}</h4>
      <div class="choices" role="radiogroup" aria-labelledby="${headingId}">
        ${item.choices
          .map(
            (c, i) =>
              `<label class="choice">
                 <input type="radio" name="q${idx}" value="${i}" class="radio">
                 <span>${c}</span>
               </label>`
          )
          .join('')}
      </div>
      <div class="explain" style="display:none;">💡 ${item.why}</div>
    `;
    qwrap.appendChild(root); // Add the question block to the quiz container
  });
}

/**
 * Grades the quiz when the user clicks "Submit Answers".
 * - Checks which answers are selected
 * - Compares each to the correct answer in the `questions` array
 * - Highlights correct/incorrect answers visually
 * - Displays explanations and updates the score bar/text
 */
function grade() {
  if (!qwrap || !scorebar || !scoreText) return; // Exit if elements not found

  let correct = 0;
  const total = questions.length;

  // Loop through all rendered questions
  [...qwrap.querySelectorAll('.q')].forEach((node, qi) => {
    const picked = node.querySelector('input[type=radio]:checked'); // User’s selected choice
    const explain = node.querySelector('.explain'); // Hidden explanation div
    const options = [...node.querySelectorAll('.choice')]; // All choice labels for this question

    // Reset any previous highlighting
    options.forEach((o) => o.classList.remove('correct', 'wrong'));

    // If the user picked an answer:
    if (picked) {
      const val = Number(picked.value);
      if (val === questions[qi].correct) {
        // Correct answer
        correct++;
        options[val].classList.add('correct'); // Highlight the right one
      } else {
        // Incorrect answer
        options[val].classList.add('wrong'); // Highlight chosen wrong one
        options[questions[qi].correct].classList.add('correct'); // Also show the correct one
      }
      if (explain) explain.style.display = 'block'; // Show explanation
    } else {
      // No answer selected — still show explanation
      if (explain) explain.style.display = 'block';
    }
  });

  // Compute and display total score percentage
  const pct = Math.round((correct / total) * 100);
  scorebar.style.width = pct + '%';
  scoreText.textContent = `Score: ${correct}/${total} (${pct}%)`;

  // Smooth scroll down to the score area so user can see results
  const scoreEl = document.querySelector('.score-text');
  if (scoreEl) {
    const y = scoreEl.getBoundingClientRect().top + window.scrollY - 120;
    window.scrollTo({ top: y, behavior: 'smooth' });
  }
}

// Render all quiz questions on page load
renderQuiz();

// Handle quiz submission and grading
if (submitBtn) submitBtn.addEventListener('click', grade);

// Handle quiz reset (clears answers and score display)
if (resetBtn) {
  resetBtn.addEventListener('click', () => {
    renderQuiz(); // Rebuild questions from scratch
    if (scorebar) scorebar.style.width = '0%'; // Reset score bar
    if (scoreText) scoreText.textContent = 'Score: 0/10'; // Reset score text
  });
}