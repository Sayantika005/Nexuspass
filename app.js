/* ==========================================================================
   NexusPass JavaScript - Generator Logic, Analytics, & UI Controller
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
  // --- UI Elements ---
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');
  
  // Single Generator DOM Elements
  const passwordOutput = document.getElementById('password-output');
  const regenerateBtn = document.getElementById('regenerate-btn');
  const copyBtn = document.getElementById('copy-btn');
  const copyIcon = document.getElementById('copy-icon');
  const strengthBar = document.getElementById('strength-bar');
  const strengthBadge = document.getElementById('strength-badge');
  const generateTrigger = document.getElementById('generate-trigger');
  
  // Form Controls
  const lengthSlider = document.getElementById('length-slider');
  const lengthNumber = document.getElementById('length-number');
  const includeUpper = document.getElementById('include-upper');
  const includeLower = document.getElementById('include-lower');
  const includeNumbers = document.getElementById('include-numbers');
  const includeSymbols = document.getElementById('include-symbols');
  
  // Advanced Accordion DOM Elements
  const accordionToggle = document.getElementById('accordion-toggle');
  const accordionBody = document.getElementById('accordion-body');
  const accordion = accordionToggle.closest('.accordion');
  const excludeSimilar = document.getElementById('exclude-similar');
  const readablePass = document.getElementById('readable-pass');
  const customSymbolsInput = document.getElementById('custom-symbols');
  const excludeCharsInput = document.getElementById('exclude-chars');
  const autoCopyCheckbox = document.getElementById('auto-copy');
  
  // Bulk Generator DOM Elements
  const bulkQtySlider = document.getElementById('bulk-qty-slider');
  const bulkQtyNumber = document.getElementById('bulk-qty-number');
  const bulkGenerateTrigger = document.getElementById('bulk-generate-trigger');
  const bulkExports = document.getElementById('bulk-exports');
  const bulkCopyAll = document.getElementById('bulk-copy-all');
  const bulkDownloadTxt = document.getElementById('bulk-download-txt');
  const bulkOutputWrapper = document.getElementById('bulk-output-wrapper');
  const bulkCountBadge = document.getElementById('bulk-count-badge');
  const bulkListContainer = document.getElementById('bulk-list-container');

  // Security Audit DOM Elements
  const entropyVal = document.getElementById('entropy-val');
  const entropyProgress = document.getElementById('entropy-progress');
  const crackOnline = document.getElementById('crack-online');
  const crackGpu = document.getElementById('crack-gpu');
  const crackSuper = document.getElementById('crack-super');
  
  // Checklist Elements
  const chkLength = document.getElementById('chk-length');
  const chkCasing = document.getElementById('chk-casing');
  const chkNumbers = document.getElementById('chk-numbers');
  const chkSymbols = document.getElementById('chk-symbols');
  const chkEntropy = document.getElementById('chk-entropy');
  
  // History DOM Elements
  const historyVisibilityBtn = document.getElementById('history-visibility-btn');
  const historyEyeIcon = document.getElementById('history-eye-icon');
  const clearHistoryBtn = document.getElementById('clear-history-btn');
  const historyEmpty = document.getElementById('history-empty');
  const historyList = document.getElementById('history-list');
  
  // Toast
  const toast = document.getElementById('toast');
  const toastMessage = document.getElementById('toast-message');

  // --- State Variables ---
  let generatedPassword = '';
  let bulkPasswords = [];
  let passwordHistory = JSON.parse(localStorage.getItem('nexuspass_history')) || [];
  let isHistoryMasked = true; // Security first: history masked by default

  // Initialize Lucide Icons
  lucide.createIcons();

  // --- Tab Switching Logic ---
  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      
      tabButtons.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));
      
      btn.classList.add('active');
      document.getElementById(targetTab).classList.add('active');
    });
  });

  // --- Accordion Logic ---
  accordionToggle.addEventListener('click', () => {
    const isOpen = accordion.classList.contains('open');
    if (isOpen) {
      accordion.classList.remove('open');
      accordionBody.style.maxHeight = null;
    } else {
      accordion.classList.add('open');
      accordionBody.style.maxHeight = accordionBody.scrollHeight + "px";
    }
  });

  // --- Synchronize Range Sliders & Numeric Inputs ---
  function syncInputs(slider, number, updateCallback) {
    slider.addEventListener('input', (e) => {
      number.value = e.target.value;
      if (updateCallback) updateCallback();
    });
    number.addEventListener('input', (e) => {
      let val = parseInt(e.target.value);
      const min = parseInt(number.min);
      const max = parseInt(number.max);
      if (isNaN(val)) val = min;
      if (val < min) val = min;
      if (val > max) val = max;
      
      slider.value = val;
      e.target.value = val;
      if (updateCallback) updateCallback();
    });
  }

  syncInputs(lengthSlider, lengthNumber, () => {
    // Live update analysis if a password exists
    if (generatedPassword) {
      generatePassword();
    }
  });
  
  syncInputs(bulkQtySlider, bulkQtyNumber);

  // --- Cryptographically Secure Random Number Generator ---
  // Returns a random integer: 0 <= r < max
  function secureRandomInt(max) {
    if (max <= 0) return 0;
    const array = new Uint32Array(1);
    const maxRange = Math.floor(4294967296 / max) * max;
    let val;
    do {
      window.crypto.getRandomValues(array);
      val = array[0];
    } while (val >= maxRange);
    return val % max;
  }

  // --- Password Generation Algorithm ---
  function generatePassword() {
    const length = parseInt(lengthSlider.value);
    
    // Check parameters
    const useUpper = includeUpper.checked;
    const useLower = includeLower.checked;
    const useNumbers = includeNumbers.checked;
    const useSymbols = includeSymbols.checked;
    const avoidSimilar = excludeSimilar.checked;
    const makeReadable = readablePass.checked;
    const customSymbols = customSymbolsInput.value;
    const excludeChars = excludeCharsInput.value;

    // Fail-safe: If nothing is selected, force lowercase
    if (!useUpper && !useLower && !useNumbers && !useSymbols) {
      includeLower.checked = true;
      showToast('At least one character pool must be selected. Enabled Lowercase.', true);
      return generatePassword();
    }

    let password = '';

    if (makeReadable) {
      // Pronounceable password logic
      password = generateReadable(length, useUpper, useLower, useNumbers, useSymbols, customSymbols, excludeChars);
    } else {
      // Standard random password logic
      let charset = '';
      let guaranteed = [];

      // Base Charsets
      const upperSet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      const lowerSet = 'abcdefghijklmnopqrstuvwxyz';
      const numSet = '0123456789';
      
      let finalUpper = upperSet;
      let finalLower = lowerSet;
      let finalNum = numSet;
      let finalSym = customSymbols || '!@#$%^&*()_+-=[]{}|;:,.<>?';

      // Similar characters to filter out
      const similarChars = 'iI1lLo0O';

      const filterString = (str, charsToFilter) => {
        let result = '';
        for (let char of str) {
          if (!charsToFilter.includes(char)) {
            result += char;
          }
        }
        return result;
      };

      // Filter similar characters
      if (avoidSimilar) {
        finalUpper = filterString(finalUpper, similarChars);
        finalLower = filterString(finalLower, similarChars);
        finalNum = filterString(finalNum, similarChars);
        finalSym = filterString(finalSym, similarChars);
      }

      // Filter custom excluded characters
      if (excludeChars) {
        finalUpper = filterString(finalUpper, excludeChars);
        finalLower = filterString(finalLower, excludeChars);
        finalNum = filterString(finalNum, excludeChars);
        finalSym = filterString(finalSym, excludeChars);
      }

      // Build character set pool and add one guaranteed character for each checked pool
      if (useUpper && finalUpper.length > 0) {
        charset += finalUpper;
        guaranteed.push(finalUpper[secureRandomInt(finalUpper.length)]);
      }
      if (useLower && finalLower.length > 0) {
        charset += finalLower;
        guaranteed.push(finalLower[secureRandomInt(finalLower.length)]);
      }
      if (useNumbers && finalNum.length > 0) {
        charset += finalNum;
        guaranteed.push(finalNum[secureRandomInt(finalNum.length)]);
      }
      if (useSymbols && finalSym.length > 0) {
        charset += finalSym;
        guaranteed.push(finalSym[secureRandomInt(finalSym.length)]);
      }

      // If after filtering we have no characters left in the enabled sets
      if (charset.length === 0) {
        showToast('Configuration yielded an empty character set. Relax exclusions.', true);
        return;
      }

      // Generate the password body
      const remainingLength = length - guaranteed.length;
      for (let i = 0; i < remainingLength; i++) {
        password += charset[secureRandomInt(charset.length)];
      }

      // Insert guaranteed characters at random locations
      let passArr = password.split('');
      for (let char of guaranteed) {
        const insertIndex = secureRandomInt(passArr.length + 1);
        passArr.splice(insertIndex, 0, char);
      }
      password = passArr.join('');
    }

    // Set output text
    generatedPassword = password;
    passwordOutput.textContent = password;
    passwordOutput.classList.remove('placeholder');

    // Run audit
    runSecurityAudit(password);

    // Save to history (if single pane is active)
    const isSingleActive = document.getElementById('single-pane').classList.contains('active');
    if (isSingleActive) {
      addToHistory(password);
      
      // Auto-copy if checked
      if (autoCopyCheckbox.checked) {
        copyToClipboard(password, false);
      }
    }
  }

  // --- Pronounceable (Readable) Generator Logic ---
  function generateReadable(length, upper, lower, numbers, symbols, customSyms, exclude) {
    const vowels = 'aeiou';
    const consonants = 'bcdfghjklmnpqrstvwxyz';
    const numSet = '0123456789';
    const symSet = customSyms || '!@#$%^&*()_+-=[]{}|;:,.<>?';

    const similarChars = 'iI1lLo0O';

    const filterString = (str, charsToFilter) => {
      let result = '';
      for (let char of str) {
        if (!charsToFilter.includes(char)) {
          result += char;
        }
      }
      return result;
    };

    let finalVowels = vowels;
    let finalConsonants = consonants;
    let finalNums = numSet;
    let finalSyms = symSet;

    if (excludeSimilar) {
      finalVowels = filterString(finalVowels, similarChars);
      finalConsonants = filterString(finalConsonants, similarChars);
      finalNums = filterString(finalNums, similarChars);
      finalSyms = filterString(finalSyms, similarChars);
    }

    if (exclude) {
      finalVowels = filterString(finalVowels, exclude);
      finalConsonants = filterString(finalConsonants, exclude);
      finalNums = filterString(finalNums, exclude);
      finalSyms = filterString(finalSyms, exclude);
    }

    // Fail-safes if filters wiped out pools
    if (finalVowels.length === 0) finalVowels = vowels;
    if (finalConsonants.length === 0) finalConsonants = consonants;

    let result = '';
    let isVowel = secureRandomInt(2) === 0;

    // Alternate vowels and consonants
    for (let i = 0; i < length; i++) {
      let char = '';
      if (isVowel) {
        char = finalVowels[secureRandomInt(finalVowels.length)];
      } else {
        char = finalConsonants[secureRandomInt(finalConsonants.length)];
      }

      // Handle capitalization
      if (upper && lower) {
        // Syllable start capitalisation (every 3rd char randomly)
        if (i % 3 === 0 && secureRandomInt(2) === 0) {
          char = char.toUpperCase();
        }
      } else if (upper) {
        char = char.toUpperCase();
      }

      result += char;
      isVowel = !isVowel;
    }

    // Blend numbers and symbols into the middle or end if required
    let arr = result.split('');
    
    if (numbers && finalNums.length > 0 && length > 3) {
      const count = Math.max(1, Math.floor(length / 6));
      for (let k = 0; k < count; k++) {
        const idx = 1 + secureRandomInt(length - 2); // Avoid first/last to preserve structure
        arr[idx] = finalNums[secureRandomInt(finalNums.length)];
      }
    }

    if (symbols && finalSyms.length > 0 && length > 3) {
      const count = Math.max(1, Math.floor(length / 6));
      for (let k = 0; k < count; k++) {
        const idx = 1 + secureRandomInt(length - 2);
        arr[idx] = finalSyms[secureRandomInt(finalSyms.length)];
      }
    }

    return arr.join('');
  }

  // --- Security Audit: Entropy & Crack Time Calculations ---
  function runSecurityAudit(password) {
    const len = password.length;
    if (len === 0) return;

    // 1. Determine Character Pool Size (R)
    let poolSize = 0;
    
    // Check what is present in the actual password, or use selected settings.
    // Standard secure entropy checks use the actual character set used for generation.
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    
    // Count symbols in password by excluding alphanumeric
    const hasSymbol = /[^a-zA-Z0-9]/.test(password);

    if (hasLower) poolSize += 26;
    if (hasUpper) poolSize += 26;
    if (hasNumber) poolSize += 10;
    
    if (hasSymbol) {
      // Find count of unique symbols or default to selected symbols pool size
      const customSymbols = customSymbolsInput.value || '!@#$%^&*()_+-=[]{}|;:,.<>?';
      poolSize += customSymbols.length;
    }

    // Apply corrections for similarity exclusions
    if (excludeSimilar.checked) {
      // Subtract similar characters present in the enabled pools
      const similarCount = 8; // i,I,1,l,L,o,0,O
      poolSize = Math.max(1, poolSize - similarCount);
    }

    // Ensure pool size is at least 1
    poolSize = Math.max(1, poolSize);

    // 2. Calculate Entropy (Bits) = L * log2(R)
    const entropy = Math.round(len * Math.log2(poolSize));
    entropyVal.textContent = entropy;

    // Update circular SVG chart
    // Circumference = 2 * PI * r = 2 * 3.1415 * 15.9155 = 100
    // We map entropy 0-128 bits to 0-100% stroke dasharray
    const dashValue = Math.min(100, Math.round((entropy / 120) * 100));
    entropyProgress.setAttribute('stroke-dasharray', `${dashValue}, 100`);

    // 3. Assess strength rating and update bar/badges
    let rating = 'weak';
    let strengthColorClass = 'weak';
    
    if (entropy >= 80 && len >= 14) {
      rating = 'Secure';
      strengthColorClass = 'secure';
    } else if (entropy >= 60 && len >= 12) {
      rating = 'Strong';
      strengthColorClass = 'strong';
    } else if (entropy >= 36 && len >= 8) {
      rating = 'Fair';
      strengthColorClass = 'fair';
    } else {
      rating = 'Weak';
      strengthColorClass = 'weak';
    }

    // Update circular chart class
    entropyProgress.className.baseVal = `circle ${strengthColorClass}`;

    // Update strength badge
    strengthBadge.textContent = rating;
    strengthBadge.className = `strength-badge ${strengthColorClass}`;

    // Update strength progress bar
    strengthBar.className = `strength-bar ${strengthColorClass}`;
    
    // Scale strength bar percentage (Weak 25%, Fair 50%, Strong 75%, Secure 100%)
    let pct = 0;
    if (rating === 'Weak') pct = 25;
    else if (rating === 'Fair') pct = 50;
    else if (rating === 'Strong') pct = 75;
    else if (rating === 'Secure') pct = 100;
    
    strengthBar.style.width = `${pct}%`;

    // 4. Brute force crack-time estimation
    // Combinations (C) = R^L = 2^entropy
    const combinations = Math.pow(2, entropy);

    // Speed metrics
    const speedOnline = 1e3; // 1,000 guesses/sec (Network capped)
    const speedGpu = 1e11;   // 100 Billion guesses/sec (High-end consumer GPU rig)
    const speedSuper = 1e14; // 100 Trillion guesses/sec (Government / botnet scale)

    crackOnline.textContent = formatCrackTime(combinations / speedOnline);
    crackGpu.textContent = formatCrackTime(combinations / speedGpu);
    crackSuper.textContent = formatCrackTime(combinations / speedSuper);

    // 5. Checklist Audits
    updateChecklistItem(chkLength, len >= 12);
    updateChecklistItem(chkCasing, hasUpper && hasLower);
    updateChecklistItem(chkNumbers, hasNumber);
    updateChecklistItem(chkSymbols, hasSymbol);
    updateChecklistItem(chkEntropy, entropy > 60);
  }

  function updateChecklistItem(element, passed) {
    if (passed) {
      element.classList.add('passed');
      element.querySelector('i').setAttribute('data-lucide', 'check-circle-2');
    } else {
      element.classList.remove('passed');
      element.querySelector('i').setAttribute('data-lucide', 'circle');
    }
    lucide.createIcons({
      attrs: { class: 'check-icon' },
      nameAttr: 'data-lucide'
    });
  }

  function formatCrackTime(seconds) {
    if (seconds === Infinity || seconds > 3.154e22) return 'Trillions of years';
    
    const minutes = seconds / 60;
    const hours = minutes / 60;
    const days = hours / 24;
    const years = days / 365.25;

    if (seconds < 1) return 'Instantly';
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    if (minutes < 60) return `${Math.round(minutes)} minutes`;
    if (hours < 24) return `${Math.round(hours)} hours`;
    if (days < 365) return `${Math.round(days)} days`;
    
    if (years < 1000) return `${Math.round(years)} years`;
    if (years < 1e6) return `${Math.round(years / 1000)} thousand years`;
    if (years < 1e9) return `${Math.round(years / 1e6)} million years`;
    
    return `${Math.round(years / 1e9)} billion years`;
  }

  // --- Copy to Clipboard Controller ---
  function copyToClipboard(text, triggerToast = true) {
    if (!text) return;
    
    navigator.clipboard.writeText(text).then(() => {
      if (triggerToast) {
        showToast('Copied password to clipboard!');
      }
      
      // Visual flash on output wrapper
      const displayWrapper = document.querySelector('.password-display-wrapper');
      displayWrapper.classList.add('copied-flash');
      setTimeout(() => displayWrapper.classList.remove('copied-flash'), 400);

      // Momentarily change copy button icon
      if (triggerToast) {
        copyIcon.setAttribute('data-lucide', 'check');
        copyBtn.style.color = '#34d399';
        lucide.createIcons();
        
        setTimeout(() => {
          copyIcon.setAttribute('data-lucide', 'copy');
          copyBtn.style.color = '';
          lucide.createIcons();
        }, 1500);
      }
    }).catch(err => {
      console.error('Could not copy text: ', err);
      showToast('Failed to copy to clipboard', true);
    });
  }

  // --- Toast Manager ---
  let toastTimeout;
  function showToast(message, isError = false) {
    clearTimeout(toastTimeout);
    
    toastMessage.textContent = message;
    
    const icon = toast.querySelector('.toast-icon');
    if (isError) {
      toast.style.borderColor = 'rgba(239, 68, 68, 0.4)';
      toast.style.boxShadow = '0 10px 30px rgba(0,0,0,0.5), 0 0 15px var(--color-weak-glow)';
      icon.setAttribute('data-lucide', 'alert-triangle');
      icon.style.color = 'var(--color-weak)';
    } else {
      toast.style.borderColor = '';
      toast.style.boxShadow = '';
      icon.setAttribute('data-lucide', 'check-circle');
      icon.style.color = '';
    }
    
    lucide.createIcons();
    toast.classList.add('show');
    
    toastTimeout = setTimeout(() => {
      toast.classList.remove('show');
    }, 2500);
  }

  // --- Password History Controllers ---
  function addToHistory(password) {
    // Avoid duplicate insertions back-to-back
    if (passwordHistory.length > 0 && passwordHistory[0].password === password) return;

    const historyItem = {
      id: Date.now() + Math.random().toString(36).substr(2, 9),
      password: password,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    passwordHistory.unshift(historyItem);
    
    // Limit log size to 10 entries
    if (passwordHistory.length > 10) {
      passwordHistory.pop();
    }

    localStorage.setItem('nexuspass_history', JSON.stringify(passwordHistory));
    renderHistory();
  }

  function renderHistory() {
    if (passwordHistory.length === 0) {
      historyEmpty.classList.remove('hidden');
      historyList.classList.add('hidden');
      return;
    }

    historyEmpty.classList.add('hidden');
    historyList.classList.remove('hidden');

    historyList.innerHTML = '';

    passwordHistory.forEach(item => {
      const li = document.createElement('li');
      li.className = 'history-item';
      
      const pwdSpan = document.createElement('span');
      pwdSpan.className = `history-pwd ${isHistoryMasked ? 'masked' : ''}`;
      pwdSpan.textContent = isHistoryMasked ? '••••••••••••••••' : item.password;
      // Allow double-click to reveal single password in history
      pwdSpan.title = isHistoryMasked ? 'Double-click to temporarily reveal' : 'Double-click to mask';
      
      pwdSpan.addEventListener('dblclick', () => {
        if (pwdSpan.classList.contains('masked')) {
          pwdSpan.classList.remove('masked');
          pwdSpan.textContent = item.password;
        } else {
          pwdSpan.classList.add('masked');
          pwdSpan.textContent = '••••••••••••••••';
        }
      });

      const actionsDiv = document.createElement('div');
      actionsDiv.className = 'history-item-actions';

      const copyBtn = document.createElement('button');
      copyBtn.className = 'history-btn history-btn-copy';
      copyBtn.title = 'Copy password';
      copyBtn.innerHTML = '<i data-lucide="copy"></i>';
      copyBtn.addEventListener('click', () => copyToClipboard(item.password));

      const deleteBtn = document.createElement('button');
      deleteBtn.className = 'history-btn history-btn-delete';
      deleteBtn.title = 'Remove from log';
      deleteBtn.innerHTML = '<i data-lucide="x"></i>';
      deleteBtn.addEventListener('click', () => deleteHistoryItem(item.id));

      actionsDiv.appendChild(copyBtn);
      actionsDiv.appendChild(deleteBtn);
      
      li.appendChild(pwdSpan);
      li.appendChild(actionsDiv);
      
      historyList.appendChild(li);
    });

    lucide.createIcons();
  }

  function deleteHistoryItem(id) {
    passwordHistory = passwordHistory.filter(item => item.id !== id);
    localStorage.setItem('nexuspass_history', JSON.stringify(passwordHistory));
    renderHistory();
    showToast('Item removed from history');
  }

  // --- Toggle History Masking ---
  historyVisibilityBtn.addEventListener('click', () => {
    isHistoryMasked = !isHistoryMasked;
    
    if (isHistoryMasked) {
      historyEyeIcon.setAttribute('data-lucide', 'eye-off');
      historyVisibilityBtn.title = 'Reveal History';
      showToast('Password history masked');
    } else {
      historyEyeIcon.setAttribute('data-lucide', 'eye');
      historyVisibilityBtn.title = 'Mask History';
      showToast('Password history revealed', false);
    }
    
    lucide.createIcons();
    renderHistory();
  });

  // --- Clear Entire History Log ---
  clearHistoryBtn.addEventListener('click', () => {
    if (passwordHistory.length === 0) return;
    
    if (confirm('Are you sure you want to clear the entire password history log?')) {
      passwordHistory = [];
      localStorage.removeItem('nexuspass_history');
      renderHistory();
      showToast('Password history cleared');
    }
  });

  // --- Bulk Generator Controllers ---
  function generateBulk() {
    const qty = parseInt(bulkQtySlider.value);
    const length = parseInt(lengthSlider.value);
    
    // Check parameters
    const useUpper = includeUpper.checked;
    const useLower = includeLower.checked;
    const useNumbers = includeNumbers.checked;
    const useSymbols = includeSymbols.checked;
    const avoidSimilar = excludeSimilar.checked;
    const makeReadable = readablePass.checked;
    const customSymbols = customSymbolsInput.value;
    const excludeChars = excludeCharsInput.value;

    if (!useUpper && !useLower && !useNumbers && !useSymbols) {
      includeLower.checked = true;
      showToast('At least one character pool must be selected. Enabled Lowercase.', true);
      return generateBulk();
    }

    bulkPasswords = [];
    bulkListContainer.innerHTML = '';

    for (let i = 0; i < qty; i++) {
      let pwd = '';
      if (makeReadable) {
        pwd = generateReadable(length, useUpper, useLower, useNumbers, useSymbols, customSymbols, excludeChars);
      } else {
        // Standard random generation (same core code as single for bulk items)
        let charset = '';
        let guaranteed = [];
        
        const upperSet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const lowerSet = 'abcdefghijklmnopqrstuvwxyz';
        const numSet = '0123456789';
        
        let finalUpper = upperSet;
        let finalLower = lowerSet;
        let finalNum = numSet;
        let finalSym = customSymbols || '!@#$%^&*()_+-=[]{}|;:,.<>?';

        const similarChars = 'iI1lLo0O';
        const filterString = (str, charsToFilter) => {
          let result = '';
          for (let char of str) {
            if (!charsToFilter.includes(char)) result += char;
          }
          return result;
        };

        if (avoidSimilar) {
          finalUpper = filterString(finalUpper, similarChars);
          finalLower = filterString(finalLower, similarChars);
          finalNum = filterString(finalNum, similarChars);
          finalSym = filterString(finalSym, similarChars);
        }

        if (excludeChars) {
          finalUpper = filterString(finalUpper, excludeChars);
          finalLower = filterString(finalLower, excludeChars);
          finalNum = filterString(finalNum, excludeChars);
          finalSym = filterString(finalSym, excludeChars);
        }

        if (useUpper && finalUpper.length > 0) {
          charset += finalUpper;
          guaranteed.push(finalUpper[secureRandomInt(finalUpper.length)]);
        }
        if (useLower && finalLower.length > 0) {
          charset += finalLower;
          guaranteed.push(finalLower[secureRandomInt(finalLower.length)]);
        }
        if (useNumbers && finalNum.length > 0) {
          charset += finalNum;
          guaranteed.push(finalNum[secureRandomInt(finalNum.length)]);
        }
        if (useSymbols && finalSym.length > 0) {
          charset += finalSym;
          guaranteed.push(finalSym[secureRandomInt(finalSym.length)]);
        }

        if (charset.length > 0) {
          const remainingLength = length - guaranteed.length;
          for (let j = 0; j < remainingLength; j++) {
            pwd += charset[secureRandomInt(charset.length)];
          }

          let passArr = pwd.split('');
          for (let char of guaranteed) {
            const insertIndex = secureRandomInt(passArr.length + 1);
            passArr.splice(insertIndex, 0, char);
          }
          pwd = passArr.join('');
        }
      }
      
      if (pwd) {
        bulkPasswords.push(pwd);
      }
    }

    renderBulkList();
  }

  function renderBulkList() {
    bulkListContainer.innerHTML = '';
    
    if (bulkPasswords.length === 0) {
      bulkOutputWrapper.classList.add('hidden');
      bulkExports.classList.add('hidden');
      return;
    }

    bulkCountBadge.textContent = `${bulkPasswords.length} Keys`;
    
    bulkPasswords.forEach((pwd, index) => {
      const item = document.createElement('div');
      item.className = 'bulk-item';
      
      const valSpan = document.createElement('span');
      valSpan.className = 'pwd';
      valSpan.textContent = pwd;
      
      const copyBtn = document.createElement('button');
      copyBtn.className = 'bulk-copy-btn';
      copyBtn.title = 'Copy this key';
      copyBtn.innerHTML = '<i data-lucide="copy"></i>';
      copyBtn.addEventListener('click', () => copyToClipboard(pwd));

      item.appendChild(valSpan);
      item.appendChild(copyBtn);
      bulkListContainer.appendChild(item);
    });

    bulkOutputWrapper.classList.remove('hidden');
    bulkExports.classList.remove('hidden');
    
    lucide.createIcons();
    showToast(`Bulk generated ${bulkPasswords.length} passwords!`);
  }

  // --- Bulk Export Bindings ---
  bulkCopyAll.addEventListener('click', () => {
    if (bulkPasswords.length === 0) return;
    const combined = bulkPasswords.join('\n');
    copyToClipboard(combined);
    showToast('Copied all bulk passwords to clipboard!');
  });

  bulkDownloadTxt.addEventListener('click', () => {
    if (bulkPasswords.length === 0) return;
    const content = bulkPasswords.join('\r\n');
    downloadFile(content, 'nexuspass_export.txt', 'text/plain');
  });

  function downloadFile(content, fileName, contentType) {
    const a = document.createElement('a');
    const file = new Blob([content], { type: contentType });
    a.href = URL.createObjectURL(file);
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  // --- Button Action & General Click Listeners ---
  generateTrigger.addEventListener('click', generatePassword);
  
  regenerateBtn.addEventListener('click', () => {
    regenerateBtn.classList.add('spinning');
    generatePassword();
    setTimeout(() => {
      regenerateBtn.classList.remove('spinning');
    }, 600);
  });

  copyBtn.addEventListener('click', () => {
    if (generatedPassword) {
      copyToClipboard(generatedPassword);
    }
  });

  bulkGenerateTrigger.addEventListener('click', generateBulk);

  // --- Initial Generator Run ---
  generatePassword(); // Autogenerate a starting secure password
  renderHistory();    // Draw historical passwords on load
});
