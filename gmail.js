const { google } = require('googleapis');

function needsEncoding(s = '') {
  // any byte outside printable ASCII triggers encoding (emoji, accents, en dash, etc.)
  return /[^\x20-\x7E]/.test(s);
}
function encodeWordUTF8(s = '') {
  // RFC 2047 "encoded-word" using Base64
  return `=?UTF-8?B?${Buffer.from(s, 'utf8').toString('base64')}?=`;
}
function headerSafe(s = '') {
  return needsEncoding(s) ? encodeWordUTF8(s) : s;
}
function formatAddress(name, email) {
  return name ? `${headerSafe(name)} <${email}>` : email;
}

function makeRawEmail({ fromName, fromEmail, to, subject, text, html, replyTo }) {
  const from = formatAddress(fromName, fromEmail);
  const subj = headerSafe(subject);

  const boundary = 'bnd_' + Math.random().toString(16).slice(2);
  const hasBoth = html && text;

  const head = [
    'MIME-Version: 1.0',
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subj}`,
    replyTo ? `Reply-To: ${replyTo}` : null
  ].filter(Boolean).join('\r\n');

  if (hasBoth) {
    const body =
      `Content-Type: multipart/alternative; boundary="${boundary}"\r\n\r\n` +
      `--${boundary}\r\n` +
      `Content-Type: text/plain; charset=UTF-8\r\n` +
      `Content-Transfer-Encoding: 8bit\r\n\r\n` +
      `${text}\r\n\r\n` +
      `--${boundary}\r\n` +
      `Content-Type: text/html; charset=UTF-8\r\n` +
      `Content-Transfer-Encoding: 8bit\r\n\r\n` +
      `${html}\r\n\r\n` +
      `--${boundary}--`;
    return Buffer.from(`${head}\r\n${body}`, 'utf8').toString('base64url');
  } else {
    const isHtml = !!html;
    const bodyHeaders = [
      `Content-Type: ${isHtml ? 'text/html' : 'text/plain'}; charset=UTF-8`,
      'Content-Transfer-Encoding: 8bit',
      '', // blank line between headers and body
    ].join('\r\n');
    const body = isHtml ? html : text || '';
    return Buffer.from(`${head}\r\n${bodyHeaders}${body}`, 'utf8').toString('base64url');
  }
}

async function gmailSend({ to, subject, text, html, replyTo }) {
  const {
    GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI, GOOGLE_REFRESH_TOKEN,
    GMAIL_FROM, FROM_NAME
  } = process.env;

  const oauth2 = new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI);
  oauth2.setCredentials({ refresh_token: GOOGLE_REFRESH_TOKEN });

  const gmail = google.gmail({ version: 'v1', auth: oauth2 });
  const raw = makeRawEmail({
    fromName: FROM_NAME || 'SPACEAPP',
    fromEmail: GMAIL_FROM,
    to,
    subject,
    text,
    html,
    replyTo
  });

  return gmail.users.messages.send({ userId: 'me', requestBody: { raw } });
}

module.exports = { gmailSend };