// --- Utility Functions ---
const debounce = (func, delay) => {
    let timeout;
    return function(...args) {
        const context = this;
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(context, args), delay);
    };
};

function showMessage(message, type = 'success', triggerElement) {
    const popup = document.createElement('div');
    popup.textContent = message;
    popup.className = `popup-message ${type}`;

    const rect = triggerElement.getBoundingClientRect();
    popup.style.top = `${rect.top}px`;
    popup.style.left = `${rect.left + rect.width / 2}px`;
    
    document.body.appendChild(popup);

    setTimeout(() => {
        popup.remove();
    }, 2000);
}

// --- Core Logic: Password Analysis ---
function calculateEntropy(password) {
    if (password.length === 0) return 0;
    let charsetSize = 0;
    if (/[a-z]/.test(password)) charsetSize += 26;
    if (/[A-Z]/.test(password)) charsetSize += 26;
    if (/\d/.test(password)) charsetSize += 10;
    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(password)) charsetSize += 94; // Using a standard large set
    if (charsetSize === 0) return 0;
    return password.length * (Math.log(charsetSize) / Math.log(2));
}

function analyzePasswordStrength(password) {
    let score = 0;
    const feedback = { length: false, uppercase: false, lowercase: false, number: false, special: false, repetition: true };
    let charCounts = { upper: 0, lower: 0, numbers: 0, special: 0 };

    for (const char of password) {
        if (/[A-Z]/.test(char)) charCounts.upper++;
        else if (/[a-z]/.test(char)) charCounts.lower++;
        else if (/\d/.test(char)) charCounts.numbers++;
        else charCounts.special++;
    }

    if (password.length >= 8) score++;
    if (password.length >= 12) { score++; feedback.length = true; }
    if (password.length >= 16) score++;
    if (charCounts.upper > 0) { score++; feedback.uppercase = true; }
    if (charCounts.lower > 0) { score++; feedback.lowercase = true; }
    if (charCounts.numbers > 0) { score++; feedback.number = true; }
    if (charCounts.special > 0) { score++; feedback.special = true; }
    if (/(.)\1\1/.test(password) || /(abc|123|qwe|asd)/i.test(password)) {
        score--;
        feedback.repetition = false;
    }

    score = Math.max(0, score);
    updateStrengthUI(score, password.length);
    updateFeedbackTips(feedback);
    updateCharCounts(charCounts);
    updateEntropy(password);
    updateTimeToCrack(password);
}

// --- Core Logic: Password Generation (SECURED) ---
function secureRandom(max) {
    const randomValues = new Uint32Array(1);
    window.crypto.getRandomValues(randomValues);
    return randomValues[0] % max;
}

function shuffleArray(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = secureRandom(i + 1);
        [array[i], array[j]] = [array[j], array[i]];
    }
}

function generatePasswordFunc(length, options) {
    const charSets = {
        upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        lower: 'abcdefghijklmnopqrstuvwxyz',
        num: '0123456789',
        spec: "!@#$%^&*()_+-=[]{}|;':\",./<>?~`"
    };

    let charPool = '';
    let guaranteedChars = [];
    
    for (const key in options) {
        if (options[key]) {
            const charSet = charSets[key];
            charPool += charSet;
            guaranteedChars.push(charSet[secureRandom(charSet.length)]);
        }
    }

    if (charPool === '') {
        throw new Error('Please select at least one character type.');
    }

    let passwordArray = [...guaranteedChars];
    const remainingLength = length - passwordArray.length;

    for (let i = 0; i < remainingLength; i++) {
        passwordArray.push(charPool[secureRandom(charPool.length)]);
    }

    shuffleArray(passwordArray);
    return passwordArray.join('');
}

// --- UI Update Functions ---
function updateStrengthUI(score, length) {
    const strengthBar = document.getElementById('strengthBar');
    const strengthText = document.getElementById('strengthText');
    if (!strengthBar || !strengthText) return;

    strengthText.classList.remove('yellow-text');
    let width = 0, colorClass = '', text = 'Start typing...';
    
    if (length > 0) {
        if (score <= 2) { width = 25; colorClass = 'bg-red-500'; text = 'Very Weak'; }
        else if (score <= 3) { width = 50; colorClass = 'bg-orange-500'; text = 'Weak'; }
        else if (score <= 4) { width = 75; colorClass = 'bg-yellow-500'; text = 'Moderate'; }
        else { width = 100; colorClass = 'bg-green-500'; text = 'Strong!'; }
    }
    
    strengthBar.style.width = `${width}%`;
    strengthBar.className = 'strength-bar';
    if (colorClass) strengthBar.classList.add(colorClass);
    strengthText.textContent = text;
}

function updateFeedbackTips(feedback) {
    const applyFeedback = (id, condition) => {
        const element = document.getElementById(id);
        if (element) {
            element.classList.toggle('text-green-400', condition);
            element.classList.toggle('text-red-400', !condition);
            element.querySelector('.feedback-icon').innerHTML = condition ? '✅' : '❌';
        }
    };
    
    applyFeedback('feedback-length', feedback.length);
    applyFeedback('feedback-uppercase', feedback.uppercase);
    applyFeedback('feedback-lowercase', feedback.lowercase);
    applyFeedback('feedback-number', feedback.number);
    applyFeedback('feedback-special', feedback.special);
    applyFeedback('feedback-repetition', feedback.repetition);
}

function updateCharCounts(counts) {
    const ids = { upper: 'charCountUpper', lower: 'charCountLower', numbers: 'charCountNumbers', special: 'charCountSpecial' };
    for (const key in ids) {
        const element = document.getElementById(ids[key]);
        if (element) element.textContent = counts[key];
    }
}

function updateEntropy(password) {
    const entropyText = document.getElementById('entropyText');
    if (entropyText) entropyText.textContent = `Entropy: ${calculateEntropy(password).toFixed(2)} bits`;
}

function updateTimeToCrack(password) {
    const timeToCrackText = document.getElementById('timeToCrack');
    if (!timeToCrackText) return;

    if (password.length === 0) {
        timeToCrackText.textContent = 'Time to crack: N/A';
        return;
    }
    const entropy = calculateEntropy(password);
    const combinations = Math.pow(2, entropy);
    let seconds = combinations / 1e12; // 1 trillion guesses/sec
    const units = { year: 31536000, month: 2592000, day: 86400, hour: 3600, minute: 60 };
    let timeString;
    if (seconds < 1) timeString = 'Instantly';
    else if (seconds < units.minute) timeString = `${Math.round(seconds)} seconds`;
    else if (seconds < units.hour) timeString = `${Math.round(seconds / units.minute)} minutes`;
    else if (seconds < units.day) timeString = `${Math.round(seconds / units.hour)} hours`;
    else if (seconds < units.month) timeString = `${Math.round(seconds / units.day)} days`;
    else if (seconds < units.year) timeString = `${Math.round(seconds / units.month)} months`;
    else {
        const years = seconds / units.year;
        if (years > 1e6) timeString = `${(years / 1e6).toPrecision(3)} million years`;
        else timeString = `${Math.round(years).toLocaleString()} years`;
    }
    timeToCrackText.textContent = `Time to crack: ${timeString}`;
}

function copyPasswordToClipboard(inputElement, triggerElement) {
    const password = inputElement.value;
    if (password) {
        navigator.clipboard.writeText(password)
            .then(() => showMessage('Password copied!', 'success', triggerElement))
            .catch(() => showMessage('Copy failed!', 'error', triggerElement));
    } else {
        showMessage('No password to copy!', 'error', triggerElement);
    }
}

// --- Event Listeners ---
document.addEventListener('DOMContentLoaded', () => {
    // --- Code for Analyzer Page ---
    const passwordInput = document.getElementById('password');
    if (passwordInput) {
        passwordInput.addEventListener('input', debounce(e => analyzePasswordStrength(e.target.value), 150));
        document.getElementById('togglePassword').addEventListener('click', () => {
            const isPassword = passwordInput.getAttribute('type') === 'password';
            passwordInput.setAttribute('type', isPassword ? 'text' : 'password');
            document.getElementById('eyeOpen').classList.toggle('hidden', !isPassword);
            document.getElementById('eyeClosed').classList.toggle('hidden', isPassword);
        });
        document.getElementById('copyAnalyzedPassword').addEventListener('click', e => copyPasswordToClipboard(passwordInput, e.currentTarget));
        document.getElementById('clearPassword').addEventListener('click', e => {
            passwordInput.value = '';
            analyzePasswordStrength('');
            showMessage('Password cleared!', 'success', e.currentTarget);
        });
        // Initial call
        analyzePasswordStrength('');
    }

    // --- Code for Generator Page ---
    const generatePasswordButton = document.getElementById('generatePassword');
    if (generatePasswordButton) {
        const generatedPasswordInput = document.getElementById('generatedPassword');
        const passwordLengthInput = document.getElementById('passwordLength');
        const lengthValueSpan = document.getElementById('lengthValue');
        
        passwordLengthInput.addEventListener('input', e => lengthValueSpan.textContent = e.target.value);
        
        generatePasswordButton.addEventListener('click', (e) => {
            try {
                const options = {
                    upper: document.getElementById('includeUppercase').checked,
                    lower: document.getElementById('includeLowercase').checked,
                    num: document.getElementById('includeNumbers').checked,
                    spec: document.getElementById('includeSpecial').checked
                };
                const newPassword = generatePasswordFunc(parseInt(passwordLengthInput.value), options);
                generatedPasswordInput.value = newPassword;
                generatedPasswordInput.setAttribute('type', 'password');
                document.getElementById('eyeOpenGenerated').classList.remove('hidden');
                document.getElementById('eyeClosedGenerated').classList.add('hidden');
                showMessage('New password generated!', 'success', e.currentTarget);
            } catch (error) {
                showMessage(error.message, 'error', e.currentTarget);
            }
        });
        
        document.getElementById('copyGeneratedPassword').addEventListener('click', e => copyPasswordToClipboard(generatedPasswordInput, e.currentTarget));
        
        document.getElementById('toggleGeneratedPassword').addEventListener('click', () => {
            const isPassword = generatedPasswordInput.getAttribute('type') === 'password';
            generatedPasswordInput.setAttribute('type', isPassword ? 'text' : 'password');
            document.getElementById('eyeOpenGenerated').classList.toggle('hidden', !isPassword);
            document.getElementById('eyeClosedGenerated').classList.toggle('hidden', isPassword);
        });
    }
    
    // Add tooltips on any page that has them
    document.querySelectorAll('[data-tooltip]').forEach(item => {
        const tooltipText = item.getAttribute('data-tooltip');
        if (tooltipText) {
            const tooltipSpan = document.createElement('span');
            tooltipSpan.className = 'tooltip-text';
            tooltipSpan.textContent = tooltipText;
            item.appendChild(tooltipSpan);
        }
    });
});