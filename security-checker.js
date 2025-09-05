// Common passwords that hackers try first
const COMMON_PASSWORDS = [
    '123456', 'password', '123456789', '12345678', '12345',
    'qwerty', '1234567890', 'abc123', 'password123', 'admin',
    'letmein', 'welcome', 'monkey', '1234', 'dragon'
];

// Patterns that make passwords weak
const WEAK_PATTERNS = [
    /^[a-z]+$/,           // All lowercase
    /^[A-Z]+$/,           // All uppercase  
    /^[0-9]+$/,           // All numbers
    /(.)\1{2,}/,          // Repeated characters (aaa, 111)
    /123|abc|qwe/i,       // Sequential patterns
    /password|admin|user/i // Common words
];

class PasswordSecurityChecker {
    
    checkPassword(password) {
        console.log(`🔍 Analyzing password: ${password}`);
        
        const report = {
            password: password,
            length: password.length,
            strength: this.calculateStrength(password),
            vulnerabilities: this.findVulnerabilities(password),
            crackTime: this.estimateHackTime(password),
            tips: this.getSecurityTips(password)
        };
        
        return report;
    }
    
    // Calculate how strong the password is
    calculateStrength(password) {
        let score = 0;
        let reasons = [];
        
        // Length matters most!
        if (password.length >= 12) {
            score += 3;
            reasons.push("Good length (12+ characters)");
        } else if (password.length >= 8) {
            score += 2;
            reasons.push("Decent length (8+ characters)");
        } else {
            score += 0;
            reasons.push("Too short (less than 8 characters)");
        }
        
        // Check for different character types
        if (/[a-z]/.test(password)) {
            score += 1;
            reasons.push("Contains lowercase letters");
        }
        if (/[A-Z]/.test(password)) {
            score += 1;
            reasons.push("Contains uppercase letters");
        }
        if (/[0-9]/.test(password)) {
            score += 1;
            reasons.push("Contains numbers");
        }
        if (/[^a-zA-Z0-9]/.test(password)) {
            score += 2;
            reasons.push("Contains special characters");
        }
        
        // Determine strength level
        let level, color;
        if (score >= 7) {
            level = "STRONG";
            color = "green";
        } else if (score >= 4) {
            level = "MEDIUM";
            color = "orange";
        } else {
            level = "WEAK";
            color = "red";
        }
        
        return { level, score, maxScore: 8, reasons, color };
    }
    
    // Find security problems with the password
    findVulnerabilities(password) {
        const vulnerabilities = [];
        
        // Check if it's a common password
        if (COMMON_PASSWORDS.includes(password.toLowerCase())) {
            vulnerabilities.push({
                type: "COMMON_PASSWORD",
                risk: "CRITICAL", 
                description: "This is one of the most common passwords! Hackers try these first.",
                solution: "Use a completely different, unique password"
            });
        }
        
        // Check for weak patterns
        WEAK_PATTERNS.forEach(pattern => {
            if (pattern.test(password)) {
                if (pattern.source === '^[0-9]+$') {
                    vulnerabilities.push({
                        type: "ALL_NUMBERS",
                        risk: "HIGH",
                        description: "Password contains only numbers - easy for computers to guess",
                        solution: "Mix letters, numbers, and symbols"
                    });
                } else if (pattern.source === '^[a-z]+$') {
                    vulnerabilities.push({
                        type: "ALL_LOWERCASE",
                        risk: "MEDIUM",
                        description: "Using only lowercase letters reduces security",
                        solution: "Add uppercase letters, numbers, and symbols"
                    });
                } else if (pattern.source === '(.)\\1{2,}') {
                    vulnerabilities.push({
                        type: "REPEATED_CHARACTERS",
                        risk: "MEDIUM",
                        description: "Repeated characters (like 'aaa' or '111') are predictable",
                        solution: "Avoid repeating the same character multiple times"
                    });
                }
            }
        });
        
        // Check for personal information patterns (simplified)
        if (/19[5-9][0-9]|20[0-2][0-9]/.test(password)) {
            vulnerabilities.push({
                type: "BIRTH_YEAR",
                risk: "HIGH",
                description: "Password might contain a birth year - easy to guess from social media",
                solution: "Avoid using personal dates or information"
            });
        }
        
        return vulnerabilities;
    }
    
    // Estimate how long it would take a hacker to crack this password
    estimateHackTime(password) {
        // Calculate possible combinations
        let charsetSize = 0;
        if (/[a-z]/.test(password)) charsetSize += 26;
        if (/[A-Z]/.test(password)) charsetSize += 26;
        if (/[0-9]/.test(password)) charsetSize += 10;
        if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;
        
        const combinations = Math.pow(charsetSize, password.length);
        
        // Different attack scenarios
        const attacks = {
            "Online attack (slow)": {
                speed: 100, // attempts per second
                description: "Hacker trying to login to your account online"
            },
            "Offline attack (fast)": {
                speed: 1000000, // 1 million attempts per second
                description: "Hacker has stolen the password database"
            }
        };
        
        const results = {};
        Object.entries(attacks).forEach(([attackType, info]) => {
            const seconds = combinations / (2 * info.speed); // Divide by 2 for average case
            results[attackType] = {
                seconds: seconds,
                humanTime: this.secondsToHumanTime(seconds),
                description: info.description
            };
        });
        
        return results;
    }
    
    // Convert seconds to readable time
    secondsToHumanTime(seconds) {
        if (seconds < 1) return "Less than 1 second";
        if (seconds < 60) return `${Math.round(seconds)} seconds`;
        if (seconds < 3600) return `${Math.round(seconds/60)} minutes`;
        if (seconds < 86400) return `${Math.round(seconds/3600)} hours`;
        if (seconds < 31536000) return `${Math.round(seconds/86400)} days`;
        if (seconds < 31536000000) return `${Math.round(seconds/31536000)} years`;
        return "More than 1000 years";
    }
    
    // Give helpful security tips
    getSecurityTips(password) {
        const tips = [];
        
        if (password.length < 12) {
            tips.push("💡 Make it longer! Every extra character makes it exponentially harder to crack.");
        }
        
        if (!/[A-Z]/.test(password)) {
            tips.push("💡 Add some capital letters to increase complexity.");
        }
        
        if (!/[^a-zA-Z0-9]/.test(password)) {
            tips.push("💡 Include special characters like !@#$%^&* for extra security.");
        }
        
        if (COMMON_PASSWORDS.includes(password.toLowerCase())) {
            tips.push("🚨 This password appears in hacker databases! Choose something unique.");
        }
        
        tips.push("🛡️ Pro tip: Use a password manager to generate and store unique passwords!");
        
        return tips;
    }
}

// Create our security checker
const securityChecker = new PasswordSecurityChecker();

// Function to analyze password and show results
function analyzePassword() {
    const password = document.getElementById('passwordInput').value;
    
    if (!password) {
        document.getElementById('securityReport').innerHTML = '<p>Enter a password to see the security analysis.</p>';
        return;
    }
    
    const report = securityChecker.checkPassword(password);
    displaySecurityReport(report);
}

// Display the security report
function displaySecurityReport(report) {
    let html = `
        <div class="security-info">
            <h3>Security Analysis for: "${report.password}"</h3>
            <h4 style="color: ${report.strength.color}">Strength: ${report.strength.level} (${report.strength.score}/${report.strength.maxScore})</h4>
            
            <h4>Why this score?</h4>
            <ul>
                ${report.strength.reasons.map(reason => `<li>${reason}</li>`).join('')}
            </ul>
        </div>
    `;
    
    // Show vulnerabilities
    if (report.vulnerabilities.length > 0) {
        html += '<h4>⚠️ Security Problems Found:</h4>';
        report.vulnerabilities.forEach(vuln => {
            html += `
                <div class="vulnerability">
                    <strong>${vuln.risk} Risk:</strong> ${vuln.description}<br>
                    <strong>Solution:</strong> ${vuln.solution}
                </div>
            `;
        });
    }
    
    // Show crack times
    html += '<h4>⏱️ How long would it take to hack?</h4>';
    Object.entries(report.crackTime).forEach(([attackType, info]) => {
        html += `
            <div class="attack-time">
                <strong>${attackType}:</strong> ${info.humanTime}<br>
                <em>${info.description}</em>
            </div>
        `;
    });
    
    // Show tips
    html += '<h4>💡 Security Tips:</h4><ul>';
    report.tips.forEach(tip => {
        html += `<li>${tip}</li>`;
    });
    html += '</ul>';
    
    document.getElementById('securityReport').innerHTML = html;
}

// Test specific passwords
function testPassword(password) {
    document.getElementById('passwordInput').value = password;
    analyzePassword();
}

// Toggle password visibility
function togglePasswordVisibility() {
    const input = document.getElementById('passwordInput');
    input.type = input.type === 'password' ? 'text' : 'password';
}

// Analyze password as user types
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('passwordInput').addEventListener('input', analyzePassword);
});