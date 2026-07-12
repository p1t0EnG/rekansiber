import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';
import * as XLSX from 'xlsx';

export interface MonthlyStatRow {
  user_id: number;
  full_name: string;
  email: string;
  total_checks: number;
  malicious_count: number;
  suspicious_count: number;
  clean_count: number;
}

export async function getMonthlyStats(db: D1Database, yearMonth: string): Promise<MonthlyStatRow[]> {
  const result = await db
    .prepare(
      `SELECT
         u.id AS user_id,
         u.full_name,
         u.email,
         COUNT(*) AS total_checks,
         SUM(CASE WHEN ic.verdict = 'malicious' THEN 1 ELSE 0 END) AS malicious_count,
         SUM(CASE WHEN ic.verdict = 'suspicious' THEN 1 ELSE 0 END) AS suspicious_count,
         SUM(CASE WHEN ic.verdict = 'clean' THEN 1 ELSE 0 END) AS clean_count
       FROM ioc_checks ic
       JOIN users u ON u.id = ic.user_id
       WHERE strftime('%Y-%m', ic.checked_at) = ?
       GROUP BY u.id
       ORDER BY total_checks DESC`,
    )
    .bind(yearMonth)
    .all<MonthlyStatRow>();

  return result.results;
}

const MONTH_NAMES_ID = [
  'Januari', 'Februari', 'Maret', 'April', 'Mei', 'Juni',
  'Juli', 'Agustus', 'September', 'Oktober', 'November', 'Desember',
];

function formatMonthLabel(yearMonth: string): string {
  const [year, month] = yearMonth.split('-').map(Number);
  return `${MONTH_NAMES_ID[month - 1]} ${year}`;
}

const PAGE_SIZE: [number, number] = [595, 842]; // A4 (pt)
const COLUMNS = [
  { label: 'Nama', x: 50, width: 160 },
  { label: 'Total', x: 220, width: 50 },
  { label: 'Malicious', x: 280, width: 70 },
  { label: 'Suspicious', x: 360, width: 70 },
  { label: 'Clean', x: 440, width: 50 },
];

export async function buildMonthlyReportPdf(yearMonth: string, rows: MonthlyStatRow[]): Promise<Uint8Array> {
  const pdfDoc = await PDFDocument.create();
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

  let page = pdfDoc.addPage(PAGE_SIZE);
  let y = 800;

  function drawHeader() {
    page.drawText('Rekan Siber -- Report Bulanan IOC Checking', {
      x: 50,
      y,
      size: 16,
      font: fontBold,
      color: rgb(0.1, 0.1, 0.1),
    });
    y -= 22;
    page.drawText(`Periode: ${formatMonthLabel(yearMonth)}`, { x: 50, y, size: 11, font });
    y -= 15;
    page.drawText(`Dibuat: ${new Date().toISOString().slice(0, 10)}`, {
      x: 50,
      y,
      size: 9,
      font,
      color: rgb(0.4, 0.4, 0.4),
    });
    y -= 28;

    for (const col of COLUMNS) {
      page.drawText(col.label, { x: col.x, y, size: 10, font: fontBold });
    }
    y -= 6;
    page.drawLine({ start: { x: 50, y }, end: { x: 545, y }, thickness: 1, color: rgb(0.7, 0.7, 0.7) });
    y -= 16;
  }

  drawHeader();

  if (rows.length === 0) {
    page.drawText('Belum ada data pengecekan pada periode ini.', { x: 50, y, size: 10, font });
    y -= 16;
  }

  for (const row of rows) {
    if (y < 60) {
      page = pdfDoc.addPage(PAGE_SIZE);
      y = 800;
      drawHeader();
    }

    const values = [
      row.full_name,
      String(row.total_checks),
      String(row.malicious_count),
      String(row.suspicious_count),
      String(row.clean_count),
    ];
    COLUMNS.forEach((col, i) => {
      page.drawText(values[i], { x: col.x, y, size: 10, font });
    });
    y -= 18;
  }

  const totalChecks = rows.reduce((sum, r) => sum + r.total_checks, 0);
  y -= 10;
  page.drawText(`Total keseluruhan: ${totalChecks} pengecekan dari ${rows.length} anggota`, {
    x: 50,
    y,
    size: 10,
    font: fontBold,
  });

  return pdfDoc.save();
}

export function buildMonthlyReportXlsx(yearMonth: string, rows: MonthlyStatRow[]): Uint8Array {
  const header = ['Nama', 'Email', 'Total Cek', 'Malicious', 'Suspicious', 'Clean'];
  const data = rows.map((r) => [r.full_name, r.email, r.total_checks, r.malicious_count, r.suspicious_count, r.clean_count]);

  const worksheet = XLSX.utils.aoa_to_sheet([
    [`Report Bulanan IOC Checking -- ${formatMonthLabel(yearMonth)}`],
    [],
    header,
    ...data,
  ]);
  worksheet['!cols'] = [{ wch: 24 }, { wch: 28 }, { wch: 10 }, { wch: 10 }, { wch: 10 }, { wch: 10 }];

  const workbook = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(workbook, worksheet, 'Ringkasan');

  const buffer = XLSX.write(workbook, { type: 'array', bookType: 'xlsx' }) as ArrayBuffer;
  return new Uint8Array(buffer);
}
