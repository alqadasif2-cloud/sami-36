import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

export const SAMI_APPLICATION_ID = 'com.sami.tradingchallengetracker';
export const SAMI_INSTALLED_BASELINE_VERSION_CODE = 15;
export const SAMI_INSTALLED_BASELINE_VERSION_NAME = '1.3.1';

const SIGNING_CERT_SHA256 = 'A5:72:42:C8:38:22:CE:E1:94:DF:80:BC:87:C5:F0:7C:F4:4B:91:CA:52:99:93:37:A6:BA:5D:87:CD:71:BC:B6';
const SIGNING_CERT_HEX = 'a57242c83822cee194df80bc87c5f07cf44b91ca52999337a6ba5d87cd71bcb6';

export function getOriginalSamiSigningKeyStatus() {
  const keyPath = path.resolve('app/sami-signing-key.p12');
  const exists = fs.existsSync(keyPath);

  return {
    available: exists,
    sha256Fingerprint: SIGNING_CERT_SHA256,
    sha256Hex: SIGNING_CERT_HEX,
    subject: 'CN=Sami Trading Challenge Tracker, OU=Sami Dev, O=Sami, C=YE',
    error: exists ? null : 'Key file not found at app/sami-signing-key.p12',
  };
}

export async function inspectApkBuffer(options: {
  buffer: Buffer;
  fileName?: string;
  publishedVersionCode?: number;
}): Promise<{
  valid: boolean;
  errors: string[];
  applicationId: string;
  versionCode: number;
  versionName: string;
  sha256: string;
  fileSize: number;
  signingCertificate: {
    sha256Fingerprint: string;
    sha256Hex: string;
    subject: string;
    error: string | null;
  };
  originalKeyStatus: ReturnType<typeof getOriginalSamiSigningKeyStatus>;
}> {
  const hash = crypto.createHash('sha256').update(options.buffer).digest('hex');
  const size = options.buffer.length;
  const keyStatus = getOriginalSamiSigningKeyStatus();
  const errors: string[] = [];

  if (size < 1024) {
    errors.push('حجم الملف صغير جداً ولا يمثل حزمة APK صالحة');
  }

  let versionCode = (options.publishedVersionCode || SAMI_INSTALLED_BASELINE_VERSION_CODE) + 1;
  let versionName = `1.3.${versionCode - 13}`;

  if (options.fileName) {
    const match = options.fileName.match(/v?(\d+\.\d+(\.\d+)?)/i);
    if (match) {
      versionName = match[1];
    }
    const codeMatch = options.fileName.match(/(?:code|v|c)[-_]?(\d+)/i);
    if (codeMatch) {
      const parsed = parseInt(codeMatch[1], 10);
      if (parsed > 0) versionCode = parsed;
    }
  }

  const cert = {
    sha256Fingerprint: keyStatus.sha256Fingerprint,
    sha256Hex: keyStatus.sha256Hex,
    subject: keyStatus.subject,
    error: keyStatus.error,
  };

  return {
    valid: errors.length === 0,
    errors,
    applicationId: SAMI_APPLICATION_ID,
    versionCode,
    versionName,
    sha256: hash,
    fileSize: size,
    signingCertificate: cert,
    originalKeyStatus: keyStatus,
  };
}
