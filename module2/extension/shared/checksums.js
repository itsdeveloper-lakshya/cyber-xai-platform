/**
 * Validation Checksums for Client-Side Detection (Section 6.2)
 * Eliminates false positives from random digit strings.
 */

// Verhoeff checksum algorithm for 12-digit Indian Aadhaar validation (ID-01)
const Verhoeff = {
  d: [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
  ],
  p: [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
  ],
  validate: function(str) {
    if (!str || typeof str !== 'string') return false;
    const clean = str.replace(/\s+/g, '');
    if (!/^\d{12}$/.test(clean)) return false;
    let c = 0;
    const digits = clean.split('').reverse().map(Number);
    for (let i = 0; i < digits.length; i++) {
      c = this.d[c][this.p[i % 8][digits[i]]];
    }
    return c === 0;
  }
};

// Luhn checksum algorithm for Credit / Debit Payment Cards (ID-04)
const Luhn = {
  validate: function(str) {
    if (!str || typeof str !== 'string') return false;
    const clean = str.replace(/[\s-]+/g, '');
    if (!/^\d{13,19}$/.test(clean)) return false;
    let sum = 0;
    let alternate = false;
    for (let i = clean.length - 1; i >= 0; i--) {
      let n = parseInt(clean.charAt(i), 10);
      if (alternate) {
        n *= 2;
        if (n > 9) n -= 9;
      }
      sum += n;
      alternate = !alternate;
    }
    return sum % 10 === 0;
  }
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { Verhoeff, Luhn };
}
