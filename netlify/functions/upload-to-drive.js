// netlify/functions/upload-to-drive.js
//
// Function này nhận file (ảnh/video) từ trình duyệt của khách (dạng base64),
// rồi dùng Google Service Account (đã cấu hình sẵn ở Environment Variables
// trên Netlify) để upload thẳng vào 1 folder Google Drive cố định.
//
// Khách KHÔNG cần đăng nhập Google. Toàn bộ quyền truy cập Drive nằm ở
// Service Account, được cấu hình 1 lần duy nhất bởi người quản trị (bạn).
//
// Cần 3 Environment Variables trên Netlify (Site settings → Environment variables):
//   GOOGLE_SERVICE_ACCOUNT_EMAIL  -> email dạng xxx@xxx.iam.gserviceaccount.com
//   GOOGLE_PRIVATE_KEY            -> private key lấy từ file JSON của Service Account
//   DRIVE_FOLDER_ID               -> ID của folder Drive muốn lưu ảnh vào
//
// Không cần cài thêm package nào (googleapis, google-auth-library...) —
// function tự ký JWT bằng module "crypto" có sẵn trong Node.js.

const crypto = require('crypto');

const MAX_BODY_BYTES = 6 * 1024 * 1024; // Netlify Functions giới hạn ~6MB / request

function base64url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

async function getAccessToken() {
  const email = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
  let privateKey = process.env.GOOGLE_PRIVATE_KEY;
  if (!email || !privateKey) {
    throw new Error('Chưa cấu hình GOOGLE_SERVICE_ACCOUNT_EMAIL / GOOGLE_PRIVATE_KEY trên Netlify.');
  }
  // Netlify env var thường lưu private key với \n bị escape thành chuỗi "\\n" -> cần đổi lại
  privateKey = privateKey.replace(/\\n/g, '\n');

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const claim = {
    iss: email,
    scope: 'https://www.googleapis.com/auth/drive.file',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600
  };

  const unsigned = base64url(JSON.stringify(header)) + '.' + base64url(JSON.stringify(claim));
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(unsigned);
  signer.end();
  const signature = signer.sign(privateKey).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  const jwt = unsigned + '.' + signature;

  const resp = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=' + encodeURIComponent(jwt)
  });
  const data = await resp.json();
  if (!resp.ok || !data.access_token) {
    throw new Error('Không lấy được access token: ' + JSON.stringify(data));
  }
  return data.access_token;
}

exports.handler = async (event) => {
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers: corsHeaders, body: '' };
  }
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers: corsHeaders, body: 'Method Not Allowed' };
  }

  try {
    if (event.body && event.body.length > MAX_BODY_BYTES) {
      return { statusCode: 413, headers: corsHeaders, body: 'File quá lớn (giới hạn ~6MB mỗi lần upload).' };
    }

    const payload = JSON.parse(event.body || '{}');
    const { filename, mimeType, data } = payload;
    if (!filename || !mimeType || !data) {
      return { statusCode: 400, headers: corsHeaders, body: 'Thiếu filename/mimeType/data.' };
    }

    const folderId = process.env.DRIVE_FOLDER_ID;
    const fileBuffer = Buffer.from(data, 'base64');

    const accessToken = await getAccessToken();

    const metadata = { name: filename, mimeType };
    if (folderId) metadata.parents = [folderId];

    // Multipart upload thủ công (không dùng thư viện ngoài)
    const boundary = '-------photobooth' + Date.now();
    const metaPart =
      `--${boundary}\r\n` +
      `Content-Type: application/json; charset=UTF-8\r\n\r\n` +
      `${JSON.stringify(metadata)}\r\n`;
    const filePartHeader =
      `--${boundary}\r\n` +
      `Content-Type: ${mimeType}\r\n` +
      `Content-Transfer-Encoding: base64\r\n\r\n`;
    const closing = `\r\n--${boundary}--`;

    const body = Buffer.concat([
      Buffer.from(metaPart, 'utf-8'),
      Buffer.from(filePartHeader, 'utf-8'),
      Buffer.from(fileBuffer.toString('base64'), 'utf-8'),
      Buffer.from(closing, 'utf-8')
    ]);

    const uploadRes = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + accessToken,
        'Content-Type': `multipart/related; boundary=${boundary}`
      },
      body
    });

    const resultText = await uploadRes.text();
    if (!uploadRes.ok) {
      console.error('Drive upload failed:', resultText);
      return { statusCode: 502, headers: corsHeaders, body: 'Upload Drive thất bại: ' + resultText };
    }

    return { statusCode: 200, headers: corsHeaders, body: resultText };
  } catch (err) {
    console.error(err);
    return { statusCode: 500, headers: corsHeaders, body: 'Lỗi server: ' + err.message };
  }
};
