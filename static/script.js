// CrackLab JavaScript - Client‑side logic for Flask application

// -------------------- Sidebar Nav --------------------
document.addEventListener('DOMContentLoaded', function() {
    // Setup navigation after DOM is loaded
    document.querySelectorAll('.sidebar nav a').forEach(link => {
        link.addEventListener('click', e => {
            e.preventDefault();
            const target = link.dataset.module;
            document.querySelectorAll('.module').forEach(sec => {
                sec.classList.toggle('hidden', sec.id !== target);
            });
            if (target === 'dashboard') loadDashboard();
        });
    });
    
    // Show analyzer by default
    document.querySelectorAll('.module').forEach(sec => {
        sec.classList.toggle('hidden', sec.id !== 'analyzer');
    });
});

console.log('🔧 nav‑switch logic loaded');

// -------------------- Globals --------------------
let socket;
let currentPassword = '';
let attackRunning   = false;
let attackStartTime = 0;
let attackAttempts  = 0;
let statsInterval   = null;

// Constants
const MAX_PASSWORD_LENGTH    = 128;
const BRUTE_FORCE_MAX_LENGTH = 10;

// -------------------- Initialization --------------------
document.addEventListener('DOMContentLoaded', () => {
  initializeApp();
});

function initializeApp() {
  socket = io();                           // connect Socket.IO
  setupEventListeners();                   // bind UI buttons & inputs
  setupSocketListeners();                  // bind socket events
  setupGeneratorListeners();               // bind generator
  setupHashLabListeners();                 // bind hash lab
  updateStats();                           // zero‑out stats
  updateAttackButtons();                   // disable/enable
  showWelcomeInfo();                       // initial attackOutput text
  updateAlgorithmInfo();                   // initialize algorithm info
  console.log('🔧 CrackLab initialized');
}

// -------------------- Toasts --------------------
function showMessage(msg, type='info') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const el = document.createElement('div');
  el.className = `message message-${type}`;
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transform = 'translateX(100%)';
    setTimeout(() => el.remove(), 300);
  }, 4000);
}

// -------------------- Dashboard --------------------
function loadDashboard() {
  fetch('/api/dashboard')
    .then(r => r.json())
    .then(s => {
      document.getElementById('dashTotal').textContent   = s.totalAttempts;
      document.getElementById('dashSuccess').textContent = s.successfulCracks;
      document.getElementById('dashAvg').textContent     = s.averageTime + 's';
    })
    .catch(console.error);
}

// -------------------- Welcome Info --------------------
function showWelcomeInfo() {
  const out = document.getElementById('attackOutput');
  if (out) {
    out.textContent = `🔐 Welcome to CrackLab!
• Dictionary (50+ passwords)
• Brute force up to ${BRUTE_FORCE_MAX_LENGTH} chars
• Realistic speeds
• Strength + breach analysis

1. Enter a password above
2. Pick an attack method
3. Watch it crack (or resist)
⚠️ For learning only!`;
  }
}

// -------------------- Event Listeners --------------------
function setupEventListeners() {
  // Password input
  const passwordInput = document.getElementById('password');
  if (passwordInput) {
    passwordInput.addEventListener('input', e => {
      currentPassword = e.target.value;
      if (currentPassword.length > MAX_PASSWORD_LENGTH) {
        currentPassword = currentPassword.substring(0, MAX_PASSWORD_LENGTH);
        e.target.value = currentPassword;
        showMessage('Password limited to ' + MAX_PASSWORD_LENGTH + ' characters', 'info');
      }
      analyzePassword();
    });
  }

  // Toggle show/hide
  const toggleBtn = document.getElementById('togglePasswordBtn');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', togglePasswordVisibility);
  }

  // Attack buttons
  const dictBtn = document.getElementById('dictionaryAttackBtn');
  if (dictBtn) dictBtn.addEventListener('click', startDictionaryAttack);
  
  const bruteBtn = document.getElementById('bruteForceAttackBtn');
  if (bruteBtn) bruteBtn.addEventListener('click', startBruteForceAttack);
  
  const stopBtn = document.getElementById('stopAttackBtn');
  if (stopBtn) stopBtn.addEventListener('click', stopAttack);
  
  const clearBtn = document.getElementById('clearOutputBtn');
  if (clearBtn) clearBtn.addEventListener('click', clearOutput);
}

// -------------------- Socket Listeners --------------------
function setupSocketListeners() {
  socket.on('connect',    () => updateConnectionStatus(true));
  socket.on('disconnect', () => { updateConnectionStatus(false); finalizeAttack(); });
  socket.on('attack_progress', handleAttackProgress);
  socket.on('attack_success',  handleAttackSuccess);
  socket.on('attack_complete', handleAttackComplete);
  socket.on('attack_info',     d => appendToOutput(d.message + '\n'));
  socket.on('attack_stopped',  d => {
    appendToOutput(`\n⏹️ ${d.message}\n`);
    finalizeAttack();
  });
  socket.on('error', d => {
    showMessage(d.message, 'error');
    if (attackRunning) {
      finalizeAttack();
    }
  });
}

// -------------------- UI Helpers --------------------
function togglePasswordVisibility() {
  const inp = document.getElementById('password');
  const btn = document.getElementById('togglePasswordBtn');
  if (inp && btn) {
    inp.type = inp.type === 'password' ? 'text' : 'password';
    btn.textContent = inp.type === 'password' ? '👁️ Show' : '🙈 Hide';
  }
}

function updateConnectionStatus(connected) {
  let dot = document.getElementById('connection-status');
  if (!dot) {
    dot = document.createElement('div');
    dot.id = 'connection-status';
    dot.style.cssText = 'position:fixed;top:10px;left:10px;width:10px;height:10px;border-radius:50%';
    document.body.appendChild(dot);
  }
  dot.style.backgroundColor = connected ? '#4caf50' : '#f44336';
}

function formatLargeNumber(n) {
  if      (n < 1e3)  return n + '';
  else if (n < 1e6)  return (n/1e3).toFixed(1)+'K';
  else if (n < 1e9)  return (n/1e6).toFixed(1)+'M';
  else if (n < 1e12) return (n/1e9).toFixed(1)+'B';
  else if (n < 1e15) return (n/1e12).toFixed(1)+'T';
  else               return n.toExponential(2);
}

// -------------------- Analysis --------------------
async function analyzePassword() {
  if (!currentPassword) {
    resetAnalysis();
    return;
  }

  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: currentPassword })
    });
    
    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.error || 'Analysis failed');
    }
    
    const data = await res.json();

    // Update strength
    if (data.strength) {
      updateStrengthMeter(data.strength.score);
      updatePasswordInfo(data.strength);
      updateFeedback(data.strength.feedback);
    }
    
    // Update crack time
    if (data.estimated_crack_time) {
      document.getElementById('estimatedTime').textContent = data.estimated_crack_time;
    }

    // Update breach status
    if (data.breach_info) {
      updateBreachStatus(data.breach_info);
    }
    
  } catch (e) {
    console.error('Analysis error:', e);
    showMessage('Analysis error: ' + e.message, 'error');
  }
}

function resetAnalysis() {
  document.getElementById('strengthText').textContent = 'Enter a password to analyze';
  const f = document.getElementById('strengthFill');
  f.style.width   = '0%';
  f.className     = 'strength-fill';
  document.getElementById('breachStatus').style.display = 'none';
  document.getElementById('strengthFeedback').innerHTML  = '';
  document.getElementById('estimatedTime').textContent   = '-';
  
  // Clear password info if it exists
  const info = document.getElementById('passwordInfo');
  if (info) {
    info.innerHTML = '';
  }
}

function updateStrengthMeter(score = 0) {
  const levels = [
    {w:'25%', c:'strength-weak', t:'Very Weak'},
    {w:'50%', c:'strength-fair', t:'Weak'},
    {w:'75%', c:'strength-good', t:'Good'},
    {w:'100%', c:'strength-strong', t:'Strong'}
  ];
  const lvl = levels[Math.min(score, 3)];
  const fill = document.getElementById('strengthFill');
  fill.style.width = lvl.w;
  fill.className = `strength-fill ${lvl.c}`;
  document.getElementById('strengthText').textContent = `${lvl.t} (${score}/3)`;
}

function updatePasswordInfo(s = {}) {
  let info = document.getElementById('passwordInfo');
  if (!info) {
    info = document.createElement('div');
    info.id = 'passwordInfo';
    info.style.cssText = 'margin-top:8px;font-size:0.9em;color:#666';
    const strengthMeter = document.querySelector('.strength-meter');
    if (strengthMeter) {
      strengthMeter.appendChild(info);
    }
  }
  
  info.innerHTML = `
    <strong>Details:</strong><br>
    • Length: ${s.length || 0}<br>
    • Charset: ${s.charset_size || 0}<br>
    • Entropy: ${s.entropy || 0} bits<br>
    • Guesses: ${formatLargeNumber(s.guesses || 0)}
  `;
}

function updateFeedback(fb = {}) {
  const el = document.getElementById('strengthFeedback');
  let html = '';
  if (fb.warning) {
    html += `<div style="color:#d32f2f;font-weight:bold;margin:10px 0;">⚠️ ${fb.warning}</div>`;
  }
  if (fb.suggestions && fb.suggestions.length) {
    html += '<strong>Suggestions:</strong><ul>' + 
            fb.suggestions.map(s => `<li>${s}</li>`).join('') + 
            '</ul>';
  }
  el.innerHTML = html;
}

function updateBreachStatus(b = {}) {
  const box = document.getElementById('breachStatus');
  const txt = document.getElementById('breachText');
  if (box && txt) {
    box.style.display = 'block';
    if (b.found || b.count > 0) {
      box.className = 'breach-status breach-found';
      txt.textContent = b.message || `⚠️ Found in ${(b.count || 0).toLocaleString()} breaches`;
    } else {
      box.className = 'breach-status breach-safe';
      txt.textContent = b.message || '✅ Not found in known breaches';
    }
  }
}

// -------------------- Attack Simulation --------------------
function startDictionaryAttack() {
  startAttack('start_dictionary_attack', 'Dictionary');
}

function startBruteForceAttack() {
  if (currentPassword.length > BRUTE_FORCE_MAX_LENGTH) {
    return showMessage(`Max ${BRUTE_FORCE_MAX_LENGTH} chars for brute force`, 'error');
  }
  if (currentPassword.length > 8) {
    if (!confirm(`Warning: A ${currentPassword.length}-character password may take a very long time to crack. Continue?`)) {
      return;
    }
  }
  startAttack('start_brute_force_attack', 'Brute Force');
}

function startAttack(evt, name) {
  if (!currentPassword) return showMessage('Enter a password first!', 'error');
  if (attackRunning) return showMessage('Attack in progress', 'error');
  if (!socket.connected) return showMessage('Not connected', 'error');

  attackRunning = true;
  attackStartTime = Date.now();
  attackAttempts = 0;
  appendToOutput(`\n🔍 Starting ${name} attack...\n`);
  updateAttackButtons();
  updateStats();
  updateProgress(0);

  statsInterval = setInterval(updateStats, 100);
  socket.emit(evt, { password: currentPassword });
}

function stopAttack() {
  if (!attackRunning) return showMessage('No attack to stop', 'info');
  socket.emit('stop_attack');
  appendToOutput('\n⏹️ Stopping attack...\n');
}

function clearOutput() {
  const output = document.getElementById('attackOutput');
  if (output) {
    output.textContent = '';
  }
  document.getElementById('progressFill').style.width = '0%';
  if (!attackRunning) {
    attackAttempts = 0;
    updateStats();
  }
}

function finalizeAttack() {
  attackRunning = false;
  if (statsInterval) {
    clearInterval(statsInterval);
    statsInterval = null;
  }
  updateAttackButtons();
  updateStats();
  updateProgress(0);
}

// -------------------- Handlers --------------------
function handleAttackProgress(d) {
  attackAttempts = d.attempts;
  
  // Only show every 10th attempt to reduce spam
  if (d.attempts % 10 === 0 || d.attempts === 1) {
    appendToOutput(`[${d.attempts}] Trying "${d.attempt}"\n`);
  }
  
  if (d.total) {
    updateProgress(d.attempts / d.total);
  } else {
    // For brute force, estimate progress
    const elapsed = (Date.now() - attackStartTime) / 1000;
    const estimatedTotal = elapsed * 60;
    updateProgress(Math.min(elapsed / estimatedTotal, 0.95));
  }
  
  updateStats();
}

function handleAttackSuccess(d) {
  appendToOutput(`\n🎯 PASSWORD CRACKED!\n`);
  appendToOutput(`✅ Found: "${d.password}"\n`);
  appendToOutput(`⏱️ Time: ${d.time_elapsed.toFixed(2)} seconds\n`);
  appendToOutput(`🔢 Attempts: ${d.attempts.toLocaleString()}\n`);
  finalizeAttack();
  showMessage('Password cracked!', 'success');
}

function handleAttackComplete(d) {
  if (!d.found) {
    appendToOutput(`\n❌ Attack completed - Password not found\n`);
    appendToOutput(`🔢 Total attempts: ${d.attempts.toLocaleString()}\n`);
    appendToOutput(`⏱️ Time elapsed: ${d.time_elapsed.toFixed(2)} seconds\n`);
  }
  finalizeAttack();
  showMessage('Attack complete', 'info');
}

// -------------------- Stats & UI --------------------
function updateStats() {
  const elapsed = attackRunning ? (Date.now() - attackStartTime) / 1000 : 0;
  const speed = elapsed > 0 ? Math.round(attackAttempts / elapsed) : 0;
  
  document.getElementById('attemptsCount').textContent = attackAttempts.toLocaleString();
  document.getElementById('timeElapsed').textContent = elapsed.toFixed(1) + 's';
  document.getElementById('attackSpeed').textContent = speed.toLocaleString() + '/s';
  
  // Highlight active stats
  const statItems = document.querySelectorAll('.stat-item');
  statItems.forEach(item => {
    if (attackRunning) {
      item.classList.add('stat-active');
    } else {
      item.classList.remove('stat-active');
    }
  });
}

function updateAttackButtons() {
  const dictBtn = document.getElementById('dictionaryAttackBtn');
  const bruteBtn = document.getElementById('bruteForceAttackBtn');
  const stopBtn = document.getElementById('stopAttackBtn');
  
  if (dictBtn) dictBtn.disabled = attackRunning;
  if (bruteBtn) bruteBtn.disabled = attackRunning;
  if (stopBtn) stopBtn.disabled = !attackRunning;
}

function updateProgress(frac) {
  const fill = document.getElementById('progressFill');
  if (fill) {
    fill.style.width = `${Math.min(frac * 100, 100)}%`;
  }
}

function appendToOutput(txt) {
  const out = document.getElementById('attackOutput');
  if (out) {
    out.textContent += txt;
    out.scrollTop = out.scrollHeight;
    
    // Limit output size
    const lines = out.textContent.split('\n');
    if (lines.length > 1000) {
      out.textContent = '... (older output truncated) ...\n' + lines.slice(-900).join('\n');
    }
  }
}

// -------------------- Generator (unchanged) --------------------
function setupGeneratorListeners() {
  const per = document.getElementById('generatePersonalBtn');
  const copy = document.getElementById('copyPersonalBtn');
  
  if (per) {
    per.addEventListener('click', () => {
      const payload = {
        place: document.getElementById('cuePlace').value,
        pet: document.getElementById('cuePet').value,
        num: document.getElementById('cueNum').value,
        hobby: document.getElementById('cueHobby').value
      };
      fetch('/api/generate_personal', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })
      .then(r => r.json())
      .then(r => {
        if (r.error) throw new Error(r.error);
        document.getElementById('personalPassword').value = r.password;
        showMessage('Passphrase generated!', 'success');
      })
      .catch(e => showMessage(e.message, 'error'));
    });
  }
  
  if (copy) {
    copy.addEventListener('click', () => {
      const ip = document.getElementById('personalPassword');
      if (ip) {
        ip.select();
        document.execCommand('copy');
        showMessage('Copied!', 'success');
      }
    });
  }
}

// Page unload cleanup
window.addEventListener('beforeunload', () => {
  if (attackRunning && socket) {
    socket.emit('stop_attack');
  }
});

// Error handling for socket connection
if (socket) {
  socket.on('connect_error', (error) => {
    console.error('Connection error:', error);
    showMessage('Connection error. Please refresh the page.', 'error');
  });
}

// -------------------- Hash Laboratory Functions --------------------

function setupHashLabListeners() {
  const computeBtn = document.getElementById('computeHashBtn');
  const copyBtn = document.getElementById('copyHashBtn');
  const clearBtn = document.getElementById('clearHashBtn');
  const algorithmSelect = document.getElementById('hashAlgorithm');
  const compareInput = document.getElementById('compareHash');
  
  if (computeBtn) {
    computeBtn.addEventListener('click', computeHash);
  }
  
  if (copyBtn) {
    copyBtn.addEventListener('click', copyHashToClipboard);
  }
  
  if (clearBtn) {
    clearBtn.addEventListener('click', clearHashLab);
  }
  
  if (algorithmSelect) {
    algorithmSelect.addEventListener('change', updateAlgorithmInfo);
  }
  
  if (compareInput) {
    compareInput.addEventListener('input', compareHashes);
  }
}

async function computeHash() {
  const input = document.getElementById('hashInput');
  const algorithmSelect = document.getElementById('hashAlgorithm');
  const computeBtn = document.getElementById('computeHashBtn');
  
  if (!input || !algorithmSelect) return;
  
  const text = input.value;
  const algorithm = algorithmSelect.value;
  
  if (!text.trim()) {
    showMessage('Please enter text to hash', 'error');
    return;
  }
  
  // Show loading state
  computeBtn.disabled = true;
  computeBtn.textContent = '⏳ Computing...';
  
  try {
    const response = await fetch('/api/hash', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        password: text,
        algorithm: algorithm
      })
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Hash computation failed');
    }
    
    // Display results
    displayHashResult(data);
    showMessage('Hash computed successfully!', 'success');
    
  } catch (error) {
    console.error('Hash computation error:', error);
    showMessage('Error: ' + error.message, 'error');
  } finally {
    // Reset button state
    computeBtn.disabled = false;
    computeBtn.textContent = '⚡ Compute Hash';
  }
}

function displayHashResult(data) {
  const hashOutput = document.getElementById('hashOutput');
  const hashInfo = document.getElementById('hashInfo');
  const algorithmDisplay = document.getElementById('hashAlgorithmDisplay');
  const inputLength = document.getElementById('hashInputLength');
  const outputLength = document.getElementById('hashOutputLength');
  const copyBtn = document.getElementById('copyHashBtn');
  const hashComparison = document.getElementById('hashComparison');
  
  if (hashOutput) {
    hashOutput.value = data.hash;
  }
  
  if (hashInfo) {
    hashInfo.style.display = 'block';
  }
  
  if (algorithmDisplay) {
    algorithmDisplay.textContent = data.algorithm;
  }
  
  if (inputLength) {
    inputLength.textContent = data.input_length + ' characters';
  }
  
  if (outputLength) {
    outputLength.textContent = data.hash_length + ' characters';
  }
  
  if (copyBtn) {
    copyBtn.disabled = false;
  }
  
  if (hashComparison) {
    hashComparison.style.display = 'block';
  }
  
  // Clear any previous comparison
  const compareInput = document.getElementById('compareHash');
  if (compareInput) {
    compareInput.value = '';
  }
  clearComparisonResult();
}

function copyHashToClipboard() {
  const hashOutput = document.getElementById('hashOutput');
  
  if (hashOutput && hashOutput.value) {
    hashOutput.select();
    hashOutput.setSelectionRange(0, 99999); // For mobile devices
    
    try {
      document.execCommand('copy');
      showMessage('Hash copied to clipboard!', 'success');
    } catch (err) {
      // Fallback for modern browsers
      navigator.clipboard.writeText(hashOutput.value).then(() => {
        showMessage('Hash copied to clipboard!', 'success');
      }).catch(() => {
        showMessage('Failed to copy hash', 'error');
      });
    }
  } else {
    showMessage('No hash to copy', 'error');
  }
}

function clearHashLab() {
  const hashInput = document.getElementById('hashInput');
  const hashOutput = document.getElementById('hashOutput');
  const hashInfo = document.getElementById('hashInfo');
  const copyBtn = document.getElementById('copyHashBtn');
  const hashComparison = document.getElementById('hashComparison');
  const compareInput = document.getElementById('compareHash');
  
  if (hashInput) hashInput.value = '';
  if (hashOutput) hashOutput.value = '';
  if (hashInfo) hashInfo.style.display = 'none';
  if (copyBtn) copyBtn.disabled = true;
  if (hashComparison) hashComparison.style.display = 'none';
  if (compareInput) compareInput.value = '';
  
  clearComparisonResult();
  showMessage('Hash lab cleared', 'info');
}

function updateAlgorithmInfo() {
  const algorithmSelect = document.getElementById('hashAlgorithm');
  const algorithmInfos = document.querySelectorAll('.algorithm-info');
  
  if (!algorithmSelect) return;
  
  const selectedAlgorithm = algorithmSelect.value;
  
  // Hide all algorithm info sections
  algorithmInfos.forEach(info => {
    info.style.display = 'none';
    info.classList.remove('active');
  });
  
  // Show the selected algorithm info
  const selectedInfo = document.querySelector(`[data-algorithm="${selectedAlgorithm}"]`);
  if (selectedInfo) {
    selectedInfo.style.display = 'block';
    selectedInfo.classList.add('active');
  }
}

function compareHashes() {
  const compareInput = document.getElementById('compareHash');
  const hashOutput = document.getElementById('hashOutput');
  
  if (!compareInput || !hashOutput) return;
  
  const compareValue = compareInput.value.trim();
  const currentHash = hashOutput.value.trim();
  
  if (!compareValue || !currentHash) {
    clearComparisonResult();
    return;
  }
  
  const comparisonResult = document.getElementById('comparisonResult');
  if (!comparisonResult) return;
  
  const isMatch = compareValue.toLowerCase() === currentHash.toLowerCase();
  
  comparisonResult.className = `comparison-result ${isMatch ? 'comparison-match' : 'comparison-no-match'}`;
  comparisonResult.textContent = isMatch 
    ? '✅ Hashes match! The inputs are identical.'
    : '❌ Hashes do not match. The inputs are different.';
  
  comparisonResult.style.display = 'block';
}

function clearComparisonResult() {
  const comparisonResult = document.getElementById('comparisonResult');
  if (comparisonResult) {
    comparisonResult.style.display = 'none';
    comparisonResult.className = 'comparison-result';
    comparisonResult.textContent = '';
  }
}

// ==================== VAULT INTEGRATION ==================== 

// ==================== GLOBAL STATE ==================== 

const Vault = {
    // Crypto configuration
    crypto: {
        kdf: {
            algorithm: 'PBKDF2',
            hash: 'SHA-256',
            iterations: 100000,
            keyLength: 256
        },
        encryption: {
            algorithm: 'AES-GCM',
            keyLength: 256,
            ivLength: 12,
            tagLength: 16
        }
    },
    
    // Application state
    state: {
        isUnlocked: false,
        masterKey: null,
        credentials: [],
        currentSalt: null,
        editingCredential: null
    },
    
    // UI elements cache
    elements: {},
    
    // Configuration
    config: {
        storagePrefix: 'cracklab_vault_',
        maxCredentials: 100,
        passwordOptions: {
            length: 16,
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: true
        }
    }
};

// ==================== VAULT INITIALIZATION ==================== 

// Add vault initialization to DOMContentLoaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('🔐 CrackLab Vault initializing...');
    
    // Cache DOM elements
    cacheVaultElements();
    
    // Setup event listeners
    setupVaultEventListeners();
    
    // Initialize UI
    initializeVaultUI();
    
    console.log('✅ Vault ready!');
});

function cacheVaultElements() {
    Vault.elements = {
        // Master password screen
        masterPasswordScreen: document.getElementById('masterPasswordScreen'),
        unlockModeBtn: document.getElementById('unlockModeBtn'),
        createModeBtn: document.getElementById('createModeBtn'),
        masterPasswordForm: document.getElementById('masterPasswordForm'),
        vaultName: document.getElementById('vaultName'),
        vaultNameGroup: document.getElementById('vaultNameGroup'),
        masterPassword: document.getElementById('masterPassword'),
        confirmPasswordGroup: document.getElementById('confirmPasswordGroup'),
        confirmPassword: document.getElementById('confirmPassword'),
        toggleMasterPassword: document.getElementById('toggleMasterPassword'),
        toggleConfirmPassword: document.getElementById('toggleConfirmPassword'),
        strengthIndicator: document.getElementById('strengthIndicator'),
        strengthFill: document.getElementById('strengthFill'),
        strengthText: document.getElementById('strengthText'),
        strengthFeedback: document.getElementById('strengthFeedback'),
        masterSubmit: document.getElementById('masterSubmit'),
        
        // Main vault interface
        vaultInterface: document.getElementById('vaultInterface'),
        changePasswordBtn: document.getElementById('changePasswordBtn'),
        toggleCryptoBtn: document.getElementById('toggleCryptoBtn'),
        lockVaultBtn: document.getElementById('lockVaultBtn'),
        
        // Credential management
        addCredentialForm: document.getElementById('addCredentialForm'),
        siteName: document.getElementById('siteName'),
        username: document.getElementById('username'),
        password: document.getElementById('password'),
        generatePasswordBtn: document.getElementById('generatePasswordBtn'),
        togglePasswordBtn: document.getElementById('togglePasswordBtn'),
        cancelEditBtn: document.getElementById('cancelEditBtn'),
        searchCredentials: document.getElementById('searchCredentials'),
        credentialsList: document.getElementById('credentialsList'),
        
        // Crypto panel
        cryptoPanel: document.getElementById('cryptoPanel'),
        cryptoHelpToggle: document.getElementById('cryptoHelpToggle'),
        cryptoEducation: document.getElementById('cryptoEducation'),
        kdfIterations: document.getElementById('kdfIterations'),
        kdfSalt: document.getElementById('kdfSalt'),
        encIv: document.getElementById('encIv'),
        encTag: document.getElementById('encTag'),
        storageCount: document.getElementById('storageCount'),
        storageSize: document.getElementById('storageSize'),
        
        // Modals
        passwordGeneratorModal: document.getElementById('passwordGeneratorModal'),
        changeMasterPasswordModal: document.getElementById('changeMasterPasswordModal'),
        loadingOverlay: document.getElementById('loadingOverlay'),
        toastContainer: document.getElementById('toast-container')
    };
}

function setupVaultEventListeners() {
    const e = Vault.elements;
    
    // Master password mode switching
    if (e.unlockModeBtn) e.unlockModeBtn.addEventListener('click', () => setMasterPasswordMode('unlock'));
    if (e.createModeBtn) e.createModeBtn.addEventListener('click', () => setMasterPasswordMode('create'));
    
    // Master password form
    if (e.masterPasswordForm) e.masterPasswordForm.addEventListener('submit', handleMasterPasswordSubmit);
    if (e.masterPassword) e.masterPassword.addEventListener('input', updatePasswordStrength);
    if (e.toggleMasterPassword) e.toggleMasterPassword.addEventListener('click', () => toggleVaultPasswordVisibility('masterPassword'));
    if (e.toggleConfirmPassword) e.toggleConfirmPassword.addEventListener('click', () => toggleVaultPasswordVisibility('confirmPassword'));
    
    // Main vault controls
    if (e.changePasswordBtn) e.changePasswordBtn.addEventListener('click', openChangeMasterPasswordModal);
    if (e.toggleCryptoBtn) e.toggleCryptoBtn.addEventListener('click', toggleCryptoPanel);
    if (e.lockVaultBtn) e.lockVaultBtn.addEventListener('click', lockVault);
    
    // Credential management
    if (e.addCredentialForm) e.addCredentialForm.addEventListener('submit', handleAddCredential);
    if (e.generatePasswordBtn) e.generatePasswordBtn.addEventListener('click', openPasswordGenerator);
    if (e.togglePasswordBtn) e.togglePasswordBtn.addEventListener('click', () => toggleVaultPasswordVisibility('password'));
    if (e.cancelEditBtn) e.cancelEditBtn.addEventListener('click', cancelEdit);
    if (e.searchCredentials) e.searchCredentials.addEventListener('input', handleSearch);
    
    // Crypto panel
    if (e.cryptoHelpToggle) e.cryptoHelpToggle.addEventListener('click', toggleCryptoEducation);
    
    // Password generator modal
    setupPasswordGeneratorListeners();
    
    // Change master password modal
    setupChangeMasterPasswordListeners();
    
    // Keyboard shortcuts
    document.addEventListener('keydown', handleKeyboardShortcuts);
    
    // Window events
    window.addEventListener('beforeunload', handleBeforeUnload);
}

function initializeVaultUI() {
    // Check crypto availability and show warning if needed
    const cryptoWarning = document.getElementById('cryptoWarning');
    if (!window.crypto || !window.crypto.subtle) {
        if (cryptoWarning) {
            cryptoWarning.style.display = 'block';
        }
        // Disable vault creation/unlock buttons
        if (Vault.elements.masterSubmit) {
            Vault.elements.masterSubmit.disabled = true;
            Vault.elements.masterSubmit.textContent = '🔒 HTTPS Required';
        }
    }
    
    // Check if vault exists
    const hasVault = checkVaultExists();
    
    if (hasVault) {
        setMasterPasswordMode('unlock');
    } else {
        setMasterPasswordMode('create');
    }
    
    // Initialize password generator
    initializePasswordGenerator();
    
    // Only show master password screen if we're on the vault page
    const vaultModule = document.getElementById('vault');
    if (vaultModule && !vaultModule.classList.contains('hidden')) {
        showMasterPasswordScreen();
    }
}

// ==================== MASTER PASSWORD MANAGEMENT ==================== 

function setMasterPasswordMode(mode) {
    const e = Vault.elements;
    
    if (!e.unlockModeBtn || !e.createModeBtn) return;
    
    // Update mode buttons
    e.unlockModeBtn.classList.toggle('active', mode === 'unlock');
    e.createModeBtn.classList.toggle('active', mode === 'create');
    
    // Show/hide vault name field
    if (e.vaultNameGroup) e.vaultNameGroup.style.display = mode === 'create' ? 'block' : 'none';
    
    // Show/hide confirm password
    if (e.confirmPasswordGroup) e.confirmPasswordGroup.style.display = mode === 'create' ? 'block' : 'none';
    
    // Show/hide strength indicator
    if (e.strengthIndicator) e.strengthIndicator.style.display = mode === 'create' ? 'block' : 'none';
    
    // Update submit button
    if (e.masterSubmit) e.masterSubmit.textContent = mode === 'unlock' ? '🔓 Unlock Vault' : '🆕 Create Vault';
    
    // Update form validation
    if (e.confirmPassword) e.confirmPassword.required = mode === 'create';
    
    // Clear form
    if (e.masterPasswordForm) e.masterPasswordForm.reset();
    if (e.vaultName && mode === 'create') e.vaultName.value = 'My Vault';
    if (e.masterPassword) e.masterPassword.focus();
}

async function handleMasterPasswordSubmit(e) {
    e.preventDefault();
    
    const mode = Vault.elements.createModeBtn.classList.contains('active') ? 'create' : 'unlock';
    const masterPassword = Vault.elements.masterPassword.value;
    const confirmPassword = Vault.elements.confirmPassword.value;
    
    // Validation
    if (!masterPassword) {
        showVaultToast('Please enter a master password', 'error');
        return;
    }
    
    if (mode === 'create') {
        if (masterPassword !== confirmPassword) {
            showVaultToast('Passwords do not match', 'error');
            return;
        }
        
        if (masterPassword.length < 8) {
            showVaultToast('Master password must be at least 8 characters', 'error');
            return;
        }
    }
    
    showLoading(true, mode === 'create' ? 'Creating vault...' : 'Unlocking vault...');
    
    try {
        if (mode === 'create') {
            await createVault(masterPassword);
        } else {
            await unlockVault(masterPassword);
        }
    } catch (error) {
        console.error('Master password error:', error);
        showVaultToast(error.message, 'error');
    } finally {
        showLoading(false);
    }
}

async function createVault(masterPassword) {
    // Check crypto availability first
    checkCryptoAvailable();
    
    // Get vault name
    const vaultNameInput = document.getElementById('vaultName');
    const vaultName = vaultNameInput ? vaultNameInput.value.trim() : 'My Vault';
    
    // Generate random salt
    const salt = window.crypto.getRandomValues(new Uint8Array(32));
    
    // Derive master key
    const masterKey = await deriveMasterKey(masterPassword, salt);
    
    // Create vault metadata
    const vaultMetadata = {
        name: vaultName,
        createdAt: new Date().toISOString(),
        version: '1.0'
    };
    
    // Initialize empty credentials array
    const credentials = [];
    
    // Save vault metadata
    localStorage.setItem(Vault.config.storagePrefix + 'metadata', JSON.stringify(vaultMetadata));
    
    // Encrypt and save vault
    await saveVault(credentials, masterKey, salt);
    
    // Update state
    Vault.state.isUnlocked = true;
    Vault.state.masterKey = masterKey;
    Vault.state.credentials = credentials;
    Vault.state.currentSalt = salt;
    Vault.state.vaultName = vaultName;
    
    showVaultToast(`Vault "${vaultName}" created successfully!`, 'success');
    showVaultInterface();
}

async function unlockVault(masterPassword) {
    // Check crypto availability first
    checkCryptoAvailable();
    
    // Load salt from storage
    const salt = loadSalt();
    if (!salt) {
        throw new Error('Vault not found. Please create a new vault.');
    }
    
    // Load vault metadata
    const metadataJson = localStorage.getItem(Vault.config.storagePrefix + 'metadata');
    const metadata = metadataJson ? JSON.parse(metadataJson) : { name: 'My Vault' };
    
    // Derive master key
    const masterKey = await deriveMasterKey(masterPassword, salt);
    
    // Load and decrypt vault data
    const credentials = await loadVault(masterKey);
    
    // Update state
    Vault.state.isUnlocked = true;
    Vault.state.masterKey = masterKey;
    Vault.state.credentials = credentials;
    Vault.state.currentSalt = salt;
    Vault.state.vaultName = metadata.name || 'My Vault';
    
    showVaultToast(`Vault "${Vault.state.vaultName}" unlocked successfully!`, 'success');
    showVaultInterface();
}

function updatePasswordStrength() {
    const password = Vault.elements.masterPassword.value;
    const mode = Vault.elements.createModeBtn.classList.contains('active') ? 'create' : 'unlock';
    
    // Only show strength indicator in create mode
    if (mode !== 'create') return;
    
    const strength = analyzeVaultPasswordStrength(password);
    
    // Make sure elements exist before updating
    if (Vault.elements.strengthFill) {
        const fillWidth = (strength.score / 4) * 100;
        Vault.elements.strengthFill.style.width = fillWidth + '%';
        Vault.elements.strengthFill.className = `strength-fill strength-${strength.level}`;
    }
    
    if (Vault.elements.strengthText) {
        Vault.elements.strengthText.textContent = `${strength.levelText} (${strength.score}/4)`;
    }
    
    if (Vault.elements.strengthFeedback) {
        if (strength.feedback.length > 0) {
            Vault.elements.strengthFeedback.innerHTML = 
                '<strong>Suggestions:</strong><br>' + strength.feedback.join('<br>');
        } else {
            Vault.elements.strengthFeedback.textContent = 'Strong password!';
        }
    }
}

function analyzeVaultPasswordStrength(password) {
    let score = 0;
    const feedback = [];
    
    // Length check
    if (password.length >= 8) score++;
    else feedback.push('Use at least 8 characters');
    
    if (password.length >= 12) score++;
    
    // Character variety
    if (/[a-z]/.test(password)) score++;
    else feedback.push('Add lowercase letters');
    
    if (/[A-Z]/.test(password)) score++;
    else feedback.push('Add uppercase letters');
    
    if (/[0-9]/.test(password)) score++;
    else feedback.push('Add numbers');
    
    if (/[^a-zA-Z0-9]/.test(password)) score++;
    else feedback.push('Add symbols');
    
    // Common patterns check
    const commonPatterns = ['password', '123456', 'qwerty', 'abc123'];
    if (commonPatterns.some(pattern => password.toLowerCase().includes(pattern))) {
        score = Math.max(0, score - 2);
        feedback.push('Avoid common patterns');
    }
    
    const levels = ['weak', 'weak', 'fair', 'good', 'strong'];
    const levelTexts = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
    
    return {
        score: Math.min(score, 4),
        level: levels[Math.min(score, 4)],
        levelText: levelTexts[Math.min(score, 4)],
        feedback
    };
}

// ==================== CRYPTOGRAPHY ==================== 

// Check if crypto is available
function checkCryptoAvailable() {
    if (!window.crypto || !window.crypto.subtle) {
        throw new Error('Web Crypto API not available. Please use HTTPS or localhost.');
    }
}

async function deriveMasterKey(password, salt) {
    // Check crypto availability
    checkCryptoAvailable();
    
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    
    try {
        // Import password as key material
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );
        
        // Derive key using PBKDF2
        const masterKey = await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: Vault.crypto.kdf.iterations,
                hash: Vault.crypto.kdf.hash
            },
            keyMaterial,
            {
                name: 'AES-GCM',
                length: Vault.crypto.encryption.keyLength
            },
            false,
            ['encrypt', 'decrypt']
        );
        
        return masterKey;
    } catch (error) {
        console.error('Crypto error:', error);
        throw new Error('Encryption failed. Please ensure you are using HTTPS or localhost.');
    }
}

async function encryptData(data, key) {
    checkCryptoAvailable();
    
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(JSON.stringify(data));
    
    // Generate random IV
    const iv = window.crypto.getRandomValues(new Uint8Array(Vault.crypto.encryption.ivLength));
    
    // Encrypt data
    const encryptedBuffer = await window.crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv
        },
        key,
        dataBuffer
    );
    
    // Extract ciphertext and auth tag
    const ciphertext = new Uint8Array(encryptedBuffer);
    
    return {
        ciphertext,
        iv,
        tag: ciphertext.slice(-Vault.crypto.encryption.tagLength)
    };
}

async function decryptData(encryptedData, key) {
    checkCryptoAvailable();
    
    try {
        // Reconstruct the encrypted buffer (ciphertext + tag)
        const encryptedBuffer = encryptedData.ciphertext;
        
        // Decrypt data
        const decryptedBuffer = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: encryptedData.iv
            },
            key,
            encryptedBuffer
        );
        
        // Decode and parse JSON
        const decoder = new TextDecoder();
        const jsonString = decoder.decode(decryptedBuffer);
        return JSON.parse(jsonString);
        
    } catch (error) {
        throw new Error('Failed to decrypt vault data. Wrong master password?');
    }
}

// ==================== STORAGE MANAGEMENT ==================== 

function checkVaultExists() {
    return localStorage.getItem(Vault.config.storagePrefix + 'salt') !== null;
}

function loadSalt() {
    const saltBase64 = localStorage.getItem(Vault.config.storagePrefix + 'salt');
    if (!saltBase64) return null;
    
    return Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));
}

function saveSalt(salt) {
    const saltBase64 = btoa(String.fromCharCode(...salt));
    localStorage.setItem(Vault.config.storagePrefix + 'salt', saltBase64);
}

async function saveVault(credentials, masterKey, salt) {
    // Encrypt credentials
    const encryptedData = await encryptData(credentials, masterKey);
    
    // Convert to base64 for storage
    const ciphertextBase64 = btoa(String.fromCharCode(...encryptedData.ciphertext));
    const ivBase64 = btoa(String.fromCharCode(...encryptedData.iv));
    
    const vaultData = {
        ciphertext: ciphertextBase64,
        iv: ivBase64
    };
    
    // Save to localStorage
    localStorage.setItem(Vault.config.storagePrefix + 'data', JSON.stringify(vaultData));
    saveSalt(salt);
    
    // Update crypto display
    updateCryptoDisplay(encryptedData);
}

async function loadVault(masterKey) {
    const vaultDataJson = localStorage.getItem(Vault.config.storagePrefix + 'data');
    if (!vaultDataJson) {
        throw new Error('No vault data found');
    }
    
    const vaultData = JSON.parse(vaultDataJson);
    
    // Convert from base64
    const ciphertext = Uint8Array.from(atob(vaultData.ciphertext), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(vaultData.iv), c => c.charCodeAt(0));
    
    const encryptedData = { ciphertext, iv };
    
    // Decrypt and return credentials
    const credentials = await decryptData(encryptedData, masterKey);
    
    // Update crypto display
    updateCryptoDisplay(encryptedData);
    
    return credentials;
}

// ==================== CREDENTIAL MANAGEMENT ==================== 

async function handleAddCredential(e) {
    e.preventDefault();
    
    const siteName = Vault.elements.siteName.value.trim();
    const username = Vault.elements.username.value.trim();
    const password = Vault.elements.password.value;
    
    if (!siteName || !username || !password) {
        showVaultToast('Please fill in all fields', 'error');
        return;
    }
    
    if (Vault.state.credentials.length >= Vault.config.maxCredentials) {
        showVaultToast(`Maximum ${Vault.config.maxCredentials} credentials allowed`, 'error');
        return;
    }
    
    showLoading(true, 'Saving credential...');
    
    try {
        const credential = {
            id: generateId(),
            siteName,
            username,
            password,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        
        if (Vault.state.editingCredential) {
            // Update existing credential
            const index = Vault.state.credentials.findIndex(c => c.id === Vault.state.editingCredential.id);
            if (index !== -1) {
                credential.id = Vault.state.editingCredential.id;
                credential.createdAt = Vault.state.editingCredential.createdAt;
                Vault.state.credentials[index] = credential;
                showVaultToast('Credential updated successfully!', 'success');
            }
        } else {
            // Add new credential
            Vault.state.credentials.push(credential);
            showVaultToast('Credential saved successfully!', 'success');
        }
        
        // Save to storage
        await saveVault(Vault.state.credentials, Vault.state.masterKey, Vault.state.currentSalt);
        
        // Update UI
        renderCredentialsList();
        clearCredentialForm();
        
    } catch (error) {
        console.error('Save credential error:', error);
        showVaultToast('Failed to save credential', 'error');
    } finally {
        showLoading(false);
    }
}

function editCredential(id) {
    const credential = Vault.state.credentials.find(c => c.id === id);
    if (!credential) return;
    
    // Populate form
    Vault.elements.siteName.value = credential.siteName;
    Vault.elements.username.value = credential.username;
    Vault.elements.password.value = credential.password;
    
    // Update UI state
    Vault.state.editingCredential = credential;
    Vault.elements.cancelEditBtn.style.display = 'inline-flex';
    
    // Scroll to form
    Vault.elements.addCredentialForm.scrollIntoView({ behavior: 'smooth' });
    Vault.elements.siteName.focus();
}

function cancelEdit() {
    Vault.state.editingCredential = null;
    Vault.elements.cancelEditBtn.style.display = 'none';
    clearCredentialForm();
}

async function deleteCredential(id) {
    if (!confirm('Are you sure you want to delete this credential?')) {
        return;
    }
    
    showLoading(true, 'Deleting credential...');
    
    try {
        // Remove from array
        Vault.state.credentials = Vault.state.credentials.filter(c => c.id !== id);
        
        // Save to storage
        await saveVault(Vault.state.credentials, Vault.state.masterKey, Vault.state.currentSalt);
        
        // Update UI
        renderCredentialsList();
        showVaultToast('Credential deleted successfully!', 'success');
        
        // Clear edit state if we're editing this credential
        if (Vault.state.editingCredential && Vault.state.editingCredential.id === id) {
            cancelEdit();
        }
        
    } catch (error) {
        console.error('Delete credential error:', error);
        showVaultToast('Failed to delete credential', 'error');
    } finally {
        showLoading(false);
    }
}

function clearCredentialForm() {
    Vault.elements.addCredentialForm.reset();
    Vault.elements.password.type = 'password';
    Vault.elements.togglePasswordBtn.textContent = '👁️';
}

function handleSearch() {
    const query = Vault.elements.searchCredentials.value.toLowerCase();
    const filteredCredentials = Vault.state.credentials.filter(credential =>
        credential.siteName.toLowerCase().includes(query) ||
        credential.username.toLowerCase().includes(query)
    );
    renderCredentialsList(filteredCredentials);
}

function renderCredentialsList(credentials = null) {
    const credentialsToRender = credentials || Vault.state.credentials;
    const container = Vault.elements.credentialsList;
    
    if (!container) return;
    
    if (credentialsToRender.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">🔒</div>
                <h3>${credentials ? 'No matching credentials' : 'No credentials saved yet'}</h3>
                <p>${credentials ? 'Try a different search term' : 'Add your first credential using the form above'}</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = credentialsToRender.map(credential => `
        <div class="credential-item" data-id="${credential.id}">
            <div class="credential-header">
                <div class="credential-title">${escapeHtml(credential.siteName)}</div>
                <div class="credential-actions">
                    <button class="btn btn-small btn-secondary" onclick="editCredential('${credential.id}')" title="Edit">
                        ✏️ Edit
                    </button>
                    <button class="btn btn-small btn-danger" onclick="deleteCredential('${credential.id}')" title="Delete">
                        🗑️ Delete
                    </button>
                </div>
            </div>
            <div class="credential-details">
                <div class="credential-field">
                    <div class="field-label">Username</div>
                    <div class="field-value">${escapeHtml(credential.username)}</div>
                </div>
                <div class="credential-field">
                    <div class="field-label">Password</div>
                    <div class="password-field">
                        <div class="field-value password-value">
                            <span class="password-masked" data-id="${credential.id}">••••••••</span>
                            <span class="password-revealed" data-id="${credential.id}" style="display: none;">${escapeHtml(credential.password)}</span>
                        </div>
                        <button class="btn btn-small btn-icon" onclick="toggleCredentialPassword('${credential.id}')" title="Reveal/Hide">
                            👁️
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `).join('');
}

function toggleCredentialPassword(id) {
    const masked = document.querySelector(`.password-masked[data-id="${id}"]`);
    const revealed = document.querySelector(`.password-revealed[data-id="${id}"]`);
    
    if (masked && revealed) {
        const isRevealed = revealed.style.display !== 'none';
        masked.style.display = isRevealed ? 'block' : 'none';
        revealed.style.display = isRevealed ? 'none' : 'block';
    }
}

// ==================== PASSWORD GENERATION ==================== 

function initializePasswordGenerator() {
    const lengthSlider = document.getElementById('passwordLength');
    const lengthValue = document.getElementById('lengthValue');
    
    if (lengthSlider && lengthValue) {
        lengthSlider.addEventListener('input', () => {
            lengthValue.textContent = lengthSlider.value;
            generateNewPassword();
        });
        
        // Initial generation
        generateNewPassword();
    }
}

function setupPasswordGeneratorListeners() {
    const modal = Vault.elements.passwordGeneratorModal;
    const closeBtn = document.getElementById('closeGeneratorModal');
    const useBtn = document.getElementById('useGeneratedPasswordBtn');
    const cancelBtn = document.getElementById('cancelGeneratorBtn');
    const regenerateBtn = document.getElementById('regenerateBtn');
    
    // Modal controls
    closeBtn?.addEventListener('click', closePasswordGenerator);
    cancelBtn?.addEventListener('click', closePasswordGenerator);
    useBtn?.addEventListener('click', useGeneratedPassword);
    regenerateBtn?.addEventListener('click', generateNewPassword);
    
    // Click outside to close
    modal?.addEventListener('click', (e) => {
        if (e.target === modal) closePasswordGenerator();
    });
    
    // Option changes trigger regeneration
    ['includeUppercase', 'includeLowercase', 'includeNumbers', 'includeSymbols'].forEach(id => {
        const element = document.getElementById(id);
        element?.addEventListener('change', generateNewPassword);
    });
}

function openPasswordGenerator() {
    generateNewPassword();
    if (Vault.elements.passwordGeneratorModal) {
        Vault.elements.passwordGeneratorModal.style.display = 'flex';
    }
}

function closePasswordGenerator() {
    if (Vault.elements.passwordGeneratorModal) {
        Vault.elements.passwordGeneratorModal.style.display = 'none';
    }
}

function generateNewPassword() {
    const length = parseInt(document.getElementById('passwordLength')?.value || '16');
    const options = {
        uppercase: document.getElementById('includeUppercase')?.checked || false,
        lowercase: document.getElementById('includeLowercase')?.checked || false,
        numbers: document.getElementById('includeNumbers')?.checked || false,
        symbols: document.getElementById('includeSymbols')?.checked || false
    };
    
    const password = generateSecurePassword(length, options);
    const output = document.getElementById('generatedPassword');
    if (output) {
        output.value = password;
    }
}

function generateSecurePassword(length, options) {
    let charset = '';
    
    if (options.uppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (options.lowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (options.numbers) charset += '0123456789';
    if (options.symbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    if (!charset) {
        return 'Please select at least one character type';
    }
    
    // Check if crypto is available
    if (!window.crypto || !window.crypto.getRandomValues) {
        // Fallback to Math.random (less secure but works everywhere)
        let password = '';
        for (let i = 0; i < length; i++) {
            password += charset[Math.floor(Math.random() * charset.length)];
        }
        return password;
    }
    
    const array = new Uint8Array(length);
    window.crypto.getRandomValues(array);
    
    return Array.from(array, byte => charset[byte % charset.length]).join('');
}

function useGeneratedPassword() {
    const generatedPassword = document.getElementById('generatedPassword')?.value;
    if (generatedPassword && Vault.elements.password) {
        Vault.elements.password.value = generatedPassword;
        closePasswordGenerator();
        showVaultToast('Password applied!', 'success');
    }
}

// ==================== MASTER PASSWORD CHANGE ==================== 

function setupChangeMasterPasswordListeners() {
    const modal = Vault.elements.changeMasterPasswordModal;
    const closeBtn = document.getElementById('closeMasterPasswordModal');
    const confirmBtn = document.getElementById('confirmChangePasswordBtn');
    const cancelBtn = document.getElementById('cancelChangePasswordBtn');
    
    closeBtn?.addEventListener('click', closeMasterPasswordModal);
    cancelBtn?.addEventListener('click', closeMasterPasswordModal);
    confirmBtn?.addEventListener('click', changeMasterPassword);
    
    // Click outside to close
    modal?.addEventListener('click', (e) => {
        if (e.target === modal) closeMasterPasswordModal();
    });
}

function openChangeMasterPasswordModal() {
    if (Vault.elements.changeMasterPasswordModal) {
        Vault.elements.changeMasterPasswordModal.style.display = 'flex';
        document.getElementById('currentMasterPassword')?.focus();
    }
}

function closeMasterPasswordModal() {
    if (Vault.elements.changeMasterPasswordModal) {
        Vault.elements.changeMasterPasswordModal.style.display = 'none';
        document.getElementById('changeMasterPasswordForm')?.reset();
    }
}

async function changeMasterPassword() {
    const currentPassword = document.getElementById('currentMasterPassword')?.value;
    const newPassword = document.getElementById('newMasterPassword')?.value;
    const confirmPassword = document.getElementById('confirmNewMasterPassword')?.value;
    
    if (!currentPassword || !newPassword || !confirmPassword) {
        showVaultToast('Please fill in all fields', 'error');
        return;
    }
    
    if (newPassword !== confirmPassword) {
        showVaultToast('New passwords do not match', 'error');
        return;
    }
    
    if (newPassword.length < 8) {
        showVaultToast('New password must be at least 8 characters', 'error');
        return;
    }
    
    showLoading(true, 'Changing master password...');
    
    try {
        // Verify current password by trying to decrypt
        const currentMasterKey = await deriveMasterKey(currentPassword, Vault.state.currentSalt);
        await decryptData({
            ciphertext: Uint8Array.from(atob(JSON.parse(localStorage.getItem(Vault.config.storagePrefix + 'data')).ciphertext), c => c.charCodeAt(0)),
            iv: Uint8Array.from(atob(JSON.parse(localStorage.getItem(Vault.config.storagePrefix + 'data')).iv), c => c.charCodeAt(0))
        }, currentMasterKey);
        
        // Generate new salt and derive new key
        const newSalt = crypto.getRandomValues(new Uint8Array(32));
        const newMasterKey = await deriveMasterKey(newPassword, newSalt);
        
        // Re-encrypt with new key
        await saveVault(Vault.state.credentials, newMasterKey, newSalt);
        
        // Update state
        Vault.state.masterKey = newMasterKey;
        Vault.state.currentSalt = newSalt;
        
        closeMasterPasswordModal();
        showVaultToast('Master password changed successfully!', 'success');
        
    } catch (error) {
        console.error('Change password error:', error);
        showVaultToast('Current password is incorrect', 'error');
    } finally {
        showLoading(false);
    }
}

// ==================== UI MANAGEMENT ==================== 

function showMasterPasswordScreen() {
    if (Vault.elements.masterPasswordScreen && Vault.elements.vaultInterface) {
        Vault.elements.masterPasswordScreen.style.display = 'flex';
        Vault.elements.vaultInterface.style.display = 'none';
        if (Vault.elements.masterPassword) Vault.elements.masterPassword.focus();
    }
}

function showVaultInterface() {
    if (Vault.elements.masterPasswordScreen && Vault.elements.vaultInterface) {
        Vault.elements.masterPasswordScreen.style.display = 'none';
        Vault.elements.vaultInterface.style.display = 'flex';
        
        // Update vault name display
        const vaultDisplayName = document.getElementById('vaultDisplayName');
        if (vaultDisplayName && Vault.state.vaultName) {
            vaultDisplayName.textContent = Vault.state.vaultName;
        }
        
        renderCredentialsList();
        updateStorageStats();
        updateCryptoDisplay();
    }
}

function lockVault() {
    if (!confirm('Are you sure you want to lock the vault? You will need to enter your master password again.')) {
        return;
    }
    
    // Clear sensitive state
    Vault.state.isUnlocked = false;
    Vault.state.masterKey = null;
    Vault.state.credentials = [];
    Vault.state.editingCredential = null;
    
    // Clear forms
    clearCredentialForm();
    if (Vault.elements.masterPasswordForm) Vault.elements.masterPasswordForm.reset();
    if (Vault.elements.searchCredentials) Vault.elements.searchCredentials.value = '';
    
    // Show master password screen
    showMasterPasswordScreen();
    
    showVaultToast('Vault locked successfully', 'success');
}

function toggleVaultPasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    const button = inputId === 'masterPassword' ? Vault.elements.toggleMasterPassword :
                   inputId === 'confirmPassword' ? Vault.elements.toggleConfirmPassword :
                   Vault.elements.togglePasswordBtn;
    
    if (input && button) {
        const isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';
        button.textContent = isPassword ? '🙈' : '👁️';
    }
}

function toggleCryptoPanel() {
    const panel = Vault.elements.cryptoPanel;
    if (!panel) return;
    
    const isHidden = panel.classList.contains('hidden');
    
    if (window.innerWidth <= 968) {
        // On mobile, show as overlay
        panel.classList.toggle('show-mobile');
    } else {
        // On desktop, slide in/out
        panel.classList.toggle('hidden');
    }
    
    if (Vault.elements.toggleCryptoBtn) {
        Vault.elements.toggleCryptoBtn.textContent = isHidden ? '📊 Hide Crypto' : '📊 Show Crypto';
    }
}

function toggleCryptoEducation() {
    const education = Vault.elements.cryptoEducation;
    if (!education) return;
    
    const isVisible = education.style.display !== 'none';
    
    education.style.display = isVisible ? 'none' : 'block';
    if (Vault.elements.cryptoHelpToggle) {
        Vault.elements.cryptoHelpToggle.setAttribute('aria-expanded', !isVisible);
    }
}

function updateCryptoDisplay(encryptedData = null) {
    // Update KDF info
    if (Vault.elements.kdfIterations) {
        Vault.elements.kdfIterations.textContent = Vault.crypto.kdf.iterations.toLocaleString();
    }
    
    if (Vault.state.currentSalt && Vault.elements.kdfSalt) {
        const saltHex = Array.from(Vault.state.currentSalt.slice(0, 8))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
        Vault.elements.kdfSalt.textContent = saltHex + '...';
    }
    
    // Update encryption info
    if (encryptedData) {
        if (Vault.elements.encIv) {
            const ivHex = Array.from(encryptedData.iv)
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
            Vault.elements.encIv.textContent = ivHex;
        }
        
        if (encryptedData.tag && Vault.elements.encTag) {
            const tagHex = Array.from(encryptedData.tag.slice(0, 8))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
            Vault.elements.encTag.textContent = tagHex + '...';
        }
    }
    
    updateStorageStats();
}

function updateStorageStats() {
    if (Vault.elements.storageCount) {
        Vault.elements.storageCount.textContent = Vault.state.credentials.length;
    }
    
    const vaultData = localStorage.getItem(Vault.config.storagePrefix + 'data');
    if (vaultData && Vault.elements.storageSize) {
        const size = new Blob([vaultData]).size;
        Vault.elements.storageSize.textContent = formatBytes(size);
    }
}

// ==================== UTILITY FUNCTIONS ==================== 

function showLoading(show, text = 'Processing...') {
    if (Vault.elements.loadingOverlay) {
        Vault.elements.loadingOverlay.style.display = show ? 'flex' : 'none';
        const loadingText = document.getElementById('loadingText');
        if (loadingText) {
            loadingText.textContent = text;
        }
    }
}

function showVaultToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    
    if (Vault.elements.toastContainer) {
        Vault.elements.toastContainer.appendChild(toast);
        
        // Trigger animation
        setTimeout(() => toast.classList.add('show'), 10);
        
        // Remove after delay
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    } else {
        // Fallback to regular showMessage if toast container doesn't exist
        showMessage(message, type);
    }
}

function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 bytes';
    const k = 1024;
    const sizes = ['bytes', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function handleKeyboardShortcuts(e) {
    // Escape: Lock vault or close modals
    if (e.key === 'Escape') {
        if (Vault.elements.passwordGeneratorModal && Vault.elements.passwordGeneratorModal.style.display === 'flex') {
            closePasswordGenerator();
        } else if (Vault.elements.changeMasterPasswordModal && Vault.elements.changeMasterPasswordModal.style.display === 'flex') {
            closeMasterPasswordModal();
        } else if (Vault.state.isUnlocked) {
            lockVault();
        }
    }
    
    // Enter: Submit forms
    if (e.key === 'Enter' && !Vault.state.isUnlocked) {
        if (document.activeElement === Vault.elements.masterPassword || 
            document.activeElement === Vault.elements.confirmPassword) {
            Vault.elements.masterPasswordForm.dispatchEvent(new Event('submit'));
        }
    }
    
    // Ctrl+S: Save credential
    if (e.ctrlKey && e.key === 's' && Vault.state.isUnlocked) {
        e.preventDefault();
        if (Vault.elements.addCredentialForm) {
            Vault.elements.addCredentialForm.dispatchEvent(new Event('submit'));
        }
    }
}

function handleBeforeUnload(e) {
    if (Vault.state.isUnlocked) {
        e.preventDefault();
        e.returnValue = 'You have an unlocked vault. Are you sure you want to leave?';
    }
}

// ==================== GLOBAL FUNCTIONS (for HTML onclick) ==================== 

// Make functions available globally for onclick handlers
window.editCredential = editCredential;
window.deleteCredential = deleteCredential;
window.toggleCredentialPassword = toggleCredentialPassword;
window.initializeVaultUI = initializeVaultUI;

// ==================== ERROR HANDLING ==================== 

window.addEventListener('error', (e) => {
    console.error('CrackLab Error:', e.error);
    showMessage('An unexpected error occurred', 'error');
});

window.addEventListener('unhandledrejection', (e) => {
    console.error('CrackLab Promise Rejection:', e.reason);
    showMessage('A processing error occurred', 'error');
});

// Export for debugging
window.Vault = Vault;


