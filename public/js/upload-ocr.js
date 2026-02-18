// public/js/upload-ocr.js
// ✅ Tesseract.js v5 with auto-managed WASM loader
(function () {
  let isOCRRunning = false;
  let sharedWorker = null;

  // 🚀 ก่อนสร้าง worker ให้ตั้งค่า Tesseract.js กำหนด WASM path
  if (typeof Tesseract !== 'undefined') {
    // ไม่ต้องระบุ corePath - ให้ Tesseract.js ค้นหาเองจาก CDN
    Tesseract.setLogging(1);
  }

  // 🌐 สร้าง shared worker เมื่อต้องการ (lazy load)
  async function getSharedWorker() {
    if (sharedWorker) return sharedWorker;
    if (typeof Tesseract === 'undefined' || !Tesseract.createWorker) {
      throw new Error('Tesseract.js ไม่พร้อม');
    }
    try {
      sharedWorker = await Tesseract.createWorker();
      console.log('✅ Tesseract Worker พร้อมใช้งาน!');
      return sharedWorker;
    } catch (err) {
      console.error('❌ สร้าง Worker ล้มเหลว:', err);
      throw err;
    }
  }

  // 📐 Crop ฟังก์ชัน (ปรับตำแหน่งให้แม่นยำสำหรับเกียรติบัตรไทย)
  const cropRegion = (dataUrl, config) => new Promise((resolve, reject) => {
    const img = new Image();
    img.crossOrigin = 'anonymous';
    img.onload = () => {
      try {
        const { w, h } = { w: img.width, h: img.height };
        const { sx, sy, sw, sh } = config(w, h);
        
        const canvas = document.createElement('canvas');
        canvas.width = sw; canvas.height = sh;
        const ctx = canvas.getContext('2d');
        
        ctx.fillStyle = '#fff';
        ctx.fillRect(0, 0, sw, sh);
        ctx.drawImage(img, sx, sy, sw, sh, 0, 0, sw, sh);
        
        resolve(canvas.toDataURL('image/jpeg', 0.85));
      } catch (e) { reject(e); }
    };
    img.onerror = () => reject(new Error('โหลดรูปภาพล้มเหลว'));
    img.src = dataUrl;
  });

  // 🔍 ดึงข้อมูลจากภาพ (ใช้ Worker v4.1.1 ที่เสถียร)
  async function extractCertificateData(dataUrl) {
    const worker = sharedWorker || await getWorkerOnDemand();
    
    let certNumber = null;
    let issueDate = null;
    const debugInfo = [];

    // 🎯 1. ขวาบน (หมายเลขเกียรติบัตร) - ตำแหน่งปรับแล้วสำหรับเกียรติบัตรไทย
    try {
      const croppedTR = await cropRegion(dataUrl, (w, h) => ({
        sx: w * 0.55,  // เริ่มจาก 55% ของความกว้าง (ขวาบน)
        sy: h * 0.05,  // 5% จากด้านบน
        sw: w * 0.40,  // กว้าง 40%
        sh: h * 0.18   // สูง 18%
      }));
      
      const res = await worker.recognize(croppedTR);
      const topRightText = cleanText(res?.data?.text || '');
      debugInfo.push(`📍 Top-Right OCR: "${topRightText}"`);
      certNumber = extractCertificateNumber(topRightText);
      debugInfo.push(`🔢 Extracted Cert Number: ${certNumber || 'NOT FOUND'}`);
    } catch (e) { 
      debugInfo.push(`❌ Top-Right crop error: ${e.message}`);
      console.warn('Crop TR failed:', e.message); 
    }

    // 🎯 2. กลางล่าง (วันที่ออก) - ตำแหน่งปรับแล้ว
    try {
      const croppedBC = await cropRegion(dataUrl, (w, h) => ({
        sx: w * 0.20,  // เริ่มจาก 20% ของความกว้าง
        sy: h * 0.78,  // 78% จากด้านบน (ใกล้ด้านล่าง)
        sw: w * 0.60,  // กว้าง 60%
        sh: h * 0.15   // สูง 15%
      }));
      
      const res = await worker.recognize(croppedBC);
      const bottomCenterText = cleanText(res?.data?.text || '');
      debugInfo.push(`📍 Bottom-Center OCR: "${bottomCenterText}"`);
      issueDate = extractIssueDate(bottomCenterText);
      debugInfo.push(`📅 Extracted Issue Date: ${issueDate || 'NOT FOUND'}`);
    } catch (e) { 
      debugInfo.push(`❌ Bottom-Center crop error: ${e.message}`);
      console.warn('Crop BC failed:', e.message); 
    }

    // ⚡ 3. รันทั้งภาพเฉพาะเมื่อจำเป็น
    if (!certNumber || !issueDate) {
      try {
        const res = await worker.recognize(dataUrl);
        const fullText = cleanText(res?.data?.text || '');
        debugInfo.push(`📄 Full-page OCR: "${fullText}"`);
        if (!certNumber) {
          certNumber = extractCertificateNumber(fullText);
          debugInfo.push(`🔢 Fallback Cert Number: ${certNumber || 'NOT FOUND'}`);
        }
        if (!issueDate) {
          issueDate = extractIssueDate(fullText);
          debugInfo.push(`📅 Fallback Issue Date: ${issueDate || 'NOT FOUND'}`);
        }
      } catch (e) { 
        debugInfo.push(`❌ Full OCR error: ${e.message}`);
        console.warn('Full OCR failed:', e.message); 
      }
    }

    // แสดง debug info
    console.log('=== OCR Debug Info ===');
    debugInfo.forEach(line => console.log(line));
    console.log('=====================');

    return { certNumber, issueDate };
  }

  // 🤖 สร้าง Worker แบบ on-demand (กรณีพรีโหลดล้มเหลว)
  async function getWorkerOnDemand() {
    if (sharedWorker) return sharedWorker;
    
    showOCRStatusSafe('⚙️ เริ่มเครื่องมือประมวลผล (ครั้งแรกอาจใช้เวลา 5-10 วินาที)...', 'info');
    try {
      sharedWorker = await Tesseract.createWorker('tha+eng', 1);
      return sharedWorker;
    } catch (err) {
      console.error('Worker creation failed:', err);
      throw err;
    }
  }

  // 🔢 ฟังก์ชันช่วยเหลือ (เหมือนเดิม)
  const convertThaToEng = t => t?.replace(/[๐-๙]/g, c => ({'๐':'0','๑':'1','๒':'2','๓':'3','๔':'4','๕':'5','๖':'6','๗':'7','๘':'8','๙':'9'})[c]) || t || '';
  const cleanText = t => (t || '').replace(/\n+/g, ' ').replace(/\s{2,}/g, ' ').trim();

  function extractCertificateNumber(text) {
    if (!text) return null;
    const norm = convertThaToEng(text).toUpperCase();
    
    // ลองหารูปแบบต่าง ๆ ของหมายเลขเกียรติบัตร
    const patterns = [
      // เลขที่ XXXXX/YYYY หรือ XXXXX-YYYY
      /(?:เลขที่|เลข|NO|NUMBER|#)[\s:]*(\d{1,6})[\/\-](\d{4})/i,
      // XXXXX/YYYY ตรง ๆ (หมายเลข/ปี)
      /(\d{2,6})[\/\-](\d{4})/,
      // XXXXX-YYYY
      /(\d{2,6})-(\d{4})/
    ];
    
    for (const p of patterns) {
      const m = norm.match(p);
      if (m) {
        // ดึงตัวเลขสุดท้ายสองส่วน
        const part1 = (m[1] || m[2] || '').replace(/\D/g, '').slice(-6).padStart(1, '0');
        const part2 = (m[2] || m[3] || m[4] || '').replace(/\D/g, '').slice(-4);
        if (part1 && part2 && part2.length === 4) {
          return `${part1}/${part2}`;
        }
      }
    }
    
    // Fallback: ค้นหาจำนวน XXXXX/YYYY ที่ไม่มี prefix
    const fallbackMatch = norm.match(/(\d{2,6})[\/\-](\d{4})/);
    if (fallbackMatch) {
      return `${fallbackMatch[1]}/${fallbackMatch[2]}`;
    }
    
    return null;
  }

  function extractIssueDate(text) {
    if (!text) return null;
    const norm = convertThaToEng(text).toLowerCase();
    
    // รูปแบบวันที่ต่าง ๆ: DD/MM/YYYY, YYYY-MM-DD, DD ชื่อเดือน YYYY
    const patterns = [
      // DD/MM/YYYY หรือ DD-MM-YYYY
      /(\d{1,2})[\/\-\s](\d{1,2})[\/\-\s](\d{4})/,
      // YYYY-MM-DD
      /(\d{4})-(\d{2})-(\d{2})/,
      // DD Month YYYY (Thai/Eng months)
      /(\d{1,2})\s+(ม\.ค\.|ก\.พ\.|มี\.ค\.|เม\.ย\.|พ\.ค\.|มิ\.ย\.|ก\.ค\.|ส\.ค\.|ก\.ย\.|ต\.ค\.|พ\.ย\.|ธ\.ค\.|january|february|march|april|may|june|july|august|september|october|november|december|jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\s*(\d{4})/i
    ];
    
    const monthMap = {
      'ม.ค.':'01', 'ก.พ.':'02', 'มี.ค.':'03', 'เม.ย.':'04', 'พ.ค.':'05', 'มิ.ย.':'06',
      'ก.ค.':'07', 'ส.ค.':'08', 'ก.ย.':'09', 'ต.ค.':'10', 'พ.ย.':'11', 'ธ.ค.':'12',
      'january':'01', 'february':'02', 'march':'03', 'april':'04', 'may':'05', 'june':'06',
      'july':'07', 'august':'08', 'september':'09', 'october':'10', 'november':'11', 'december':'12',
      'jan':'01', 'feb':'02', 'mar':'03', 'apr':'04', 'may':'05', 'jun':'06',
      'jul':'07', 'aug':'08', 'sep':'09', 'oct':'10', 'nov':'11', 'dec':'12'
    };
    
    for (const p of patterns) {
      const m = norm.match(p);
      if (m) {
        try {
          let day, month, year;
          
          // กรณี YYYY-MM-DD
          if (m[1].length === 4) {
            year = parseInt(m[1]);
            month = m[2].padStart(2, '0');
            day = m[3].padStart(2, '0');
          }
          // กรณี DD/MM/YYYY หรือ DD Month YYYY
          else {
            day = m[1].padStart(2, '0');
            month = monthMap[m[2].toLowerCase()?.trim()] || m[2].padStart(2, '0');
            year = parseInt(m[3]);
          }
          
          // แปลง Buddhist year เป็น Gregorian (2500+ -> minus 543)
          if (year > 2500) year -= 543;
          if (year < 100) year += 2000;
          
          // ตรวจสอบความถูกต้อง
          const numMonth = parseInt(month);
          const numDay = parseInt(day);
          if (year >= 1900 && year <= 2100 && numMonth >= 1 && numMonth <= 12 && numDay >= 1 && numDay <= 31) {
            return `${year}-${month}-${day}`;
          }
        } catch (e) { /* ignore */ }
      }
    }
    
    return null;
  }

  // 💬 แสดงสถานะ
  function showOCRStatusSafe(msg, type = 'info') {
    const el = document.getElementById('ocrStatus');
    if (!el) return;
    
    const icons = {
      info: '<i class="fas fa-info-circle me-1"></i>',
      success: '<i class="fas fa-check-circle me-1"></i>',
      warning: '<i class="fas fa-exclamation-triangle me-1"></i>',
      danger: '<i class="fas fa-times-circle me-1"></i>'
    };
    
    el.className = `alert alert-${type} py-2 px-3 small mb-0 fade show`;
    el.innerHTML = `${icons[type] || icons.info}${msg}`;
    el.style.display = 'block';
    
    if (type === 'success') setTimeout(() => { el.style.display = 'none'; }, 4000);
  }

  // 🚀 เริ่มระบบ
  document.addEventListener('DOMContentLoaded', () => {
    const ocrBtn = document.getElementById('ocrExtractBtn');
    const fileInput = document.getElementById('file');
    const fileNameEl = document.getElementById('fileName');
    const certInput = document.getElementById('certificate_number');
    const dateInput = document.getElementById('issue_date');
    
    if (!ocrBtn || !fileInput) return;

    fileInput.addEventListener('change', () => {
      fileNameEl.innerHTML = fileInput.files.length 
        ? `<i class="fas fa-file-image text-primary me-2"></i><strong>${fileInput.files[0].name}</strong>`
        : '';
      fileNameEl.className = fileInput.files.length ? 'mt-2 fw-semibold text-dark' : '';
    });

    ocrBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      if (isOCRRunning) return;
      
      const file = fileInput.files?.[0];
      if (!file) return showOCRStatusSafe('⚠️ กรุณาเลือกไฟล์ก่อน', 'warning');
      if (!['image/jpeg', 'image/jpg', 'image/png'].includes(file.type)) {
        return showOCRStatusSafe('❌ รองรับเฉพาะ JPG/PNG', 'danger');
      }
      if (file.size > 10 * 1024 * 1024) {
        return showOCRStatusSafe('❌ ไฟล์ใหญ่เกิน 10 MB', 'danger');
      }

      isOCRRunning = true;
      ocrBtn.disabled = true;
      ocrBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>กำลังประมวลผล...';
      showOCRStatusSafe('🚀 เริ่มวิเคราะห์เอกสาร...', 'info');

      try {
        const dataUrl = await new Promise((resolve, reject) => {
          const reader = new FileReader();
          reader.onload = e => resolve(e.target.result);
          reader.onerror = () => reject(new Error('อ่านไฟล์ล้มเหลว'));
          reader.readAsDataURL(file);
        });

        const { certNumber, issueDate } = await extractCertificateData(dataUrl);
        
        let found = 0;
        if (certNumber && certInput && !certInput.value) {
          certInput.value = certNumber;
          certInput.classList.add('border', 'border-success', 'border-2');
          found++;
        }
        if (issueDate && dateInput && !dateInput.value) {
          dateInput.value = issueDate;
          dateInput.classList.add('border', 'border-success', 'border-2');
          found++;
        }

        if (found) {
          showOCRStatusSafe(`✅ ดึงข้อมูลสำเร็จ ${found} รายการ! ตรวจสอบก่อนอัปโหลด`, 'success');
          setTimeout(() => {
            certInput?.classList.remove('border', 'border-success', 'border-2');
            dateInput?.classList.remove('border', 'border-success', 'border-2');
          }, 2000);
        } else {
          showOCRStatusSafe('⚠️ ไม่พบข้อมูล แนะนำ: ถ่ายรูปให้ชัดเจน หรือกรอกด้วยตนเอง', 'warning');
        }
      } catch (err) {
        console.error('Critical Error:', err);
        const msg = err.message?.includes('network') 
          ? '❌ ตรวจสอบการเชื่อมต่ออินเทอร์เน็ต'
          : `❌ ${err.message || 'เกิดข้อผิดพลาดระบบ'}`;
        showOCRStatusSafe(msg, 'danger');
        if (sharedWorker) {
          sharedWorker.terminate?.().catch(() => {});
          sharedWorker = null;
        }
      } finally {
        isOCRRunning = false;
        ocrBtn.disabled = false;
        ocrBtn.innerHTML = '<i class="fas fa-magic me-2"></i>ดึงข้อมูลอัตโนมัติ';
      }
    });

    window.addEventListener('beforeunload', () => {
      if (sharedWorker) sharedWorker.terminate?.().catch(() => {});
    });
  });

})();