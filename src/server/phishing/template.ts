import type { PhishingReport } from './reports';

// Template dalam Bahasa Inggris karena tim abuse hosting provider bisa di negara manapun --
// ini standar industri untuk laporan abuse/takedown.
export function generatePhishingReportTemplate(report: PhishingReport): string {
  const detectedDate = report.created_at.slice(0, 10);
  const hostingEmailLine = report.hosting_email ?? '[isi email abuse hosting provider]';
  const notesBlock = report.notes ? `\nAdditional Notes:\n${report.notes}\n` : '';

  return `To: ${hostingEmailLine}
Subject: Phishing Site Takedown Request - ${report.target_domain}

Dear Abuse Team,

We are writing to report a phishing website hosted on your infrastructure that is actively
being used to impersonate a legitimate service and steal user credentials.

Details:
- Malicious URL/Domain: ${report.target_domain}
- Date Detected: ${detectedDate}
- Reported By: ${report.reporter_name}, Rekan Siber SOC Team
${notesBlock}
We kindly request that you investigate this matter and take appropriate action to suspend or
remove this phishing content as soon as possible, in accordance with your Acceptable Use Policy.

Please let us know if you require any additional evidence or information to process this request.

Best regards,
${report.reporter_name}
Rekan Siber SOC Team`;
}
