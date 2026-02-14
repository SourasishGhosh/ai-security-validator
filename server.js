const express = require('express');
const app = express();

app.use(express.json({ limit: '10mb' }));

/* -------------------------------
   Content Security Policy
-------------------------------- */
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'none'",
      "connect-src 'self' https:",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self'",
      "font-src 'self'",
      "manifest-src 'self'"
    ].join('; ')
  );
  next();
});

/* -------------------------------
   Security Log (bounded)
-------------------------------- */
const securityLog = [];
const MAX_LOG_SIZE = 1000;

/* -------------------------------
   Utility Functions
-------------------------------- */

// Escape HTML (XSS protection)
function escapeHTML(input) {
  return input.replace(/[&<>"'/]/g, char => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#x27;',
    '/': '&#x2F;'
  }[char]));
}

// Detect SQL Injection
function hasSQLInjection(input) {
  const sqlPatterns = [
    /select\s+.*from/i,
    /union\s+select/i,
    /insert\s+into/i,
    /update\s+.*set/i,
    /drop\s+table/i,
    /--|\/\*|\*|;|@@|\(\s*select/i
  ];
  return sqlPatterns.some(pattern => pattern.test(input));
}

// Redact PII
function redactPII(input) {
  return input
    .replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[SSN_REDACTED]')
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, '[EMAIL_REDACTED]')
    .replace(/\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, '[PHONE_REDACTED]')
    .replace(/\b\d+\s+(Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Drive|Dr)\b/gi, '[ADDRESS_REDACTED]');
}

/* -------------------------------
   Validation Engine
-------------------------------- */
function validateAndSanitize(input) {
  // SQL Injection → HARD BLOCK
  if (hasSQLInjection(input)) {
    return {
      blocked: true,
      reason: 'SQL injection patterns detected',
      sanitizedOutput: '',
      confidence: 0.99
    };
  }

  let sanitized = input;
  let reason = 'Input passed all security checks';
  let confidence = 1.0;

  // XSS → sanitize, not block
  const escaped = escapeHTML(input);
  if (escaped !== input) {
    sanitized = escaped;
    reason = 'HTML/JavaScript sanitized';
    confidence = 0.95;
  }

  // PII → redact
  const redacted = redactPII(sanitized);
  if (redacted !== sanitized) {
    sanitized = redacted;
    reason = 'PII detected and redacted';
    confidence = Math.min(confidence, 0.92);
  }

  return {
    blocked: false,
    reason,
    sanitizedOutput: sanitized,
    confidence
  };
}

/* -------------------------------
   API Endpoint
-------------------------------- */
app.post('/validate', (req, res) => {
  try {
    const { userId = 'anonymous', input } = req.body;

    if (!input || typeof input !== 'string') {
      return res.status(400).json({
        blocked: true,
        reason: 'Invalid input format',
        sanitizedOutput: '',
        confidence: 1.0
      });
    }

    if (input.length > 10000) {
      return res.status(413).json({
        blocked: true,
        reason: 'Input too large',
        sanitizedOutput: '',
        confidence: 1.0
      });
    }

    const result = validateAndSanitize(input);

    // Log event
    securityLog.push({
      timestamp: new Date().toISOString(),
      userId,
      blocked: result.blocked,
      reason: result.reason
    });

    if (securityLog.length > MAX_LOG_SIZE) {
      securityLog.shift();
    }

    res.json(result);

  } catch (err) {
    console.error(err);
    res.status(500).json({
      blocked: true,
      reason: 'Internal server error',
      sanitizedOutput: '',
      confidence: 0.0
    });
  }
});

/* -------------------------------
   Server Start
-------------------------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`AI Security Validator running on port ${PORT}`);
});

module.exports = app;
