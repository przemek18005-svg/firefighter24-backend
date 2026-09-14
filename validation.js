// validation.js — walidacja danych wejściowych API.
// Front-end już waliduje te same rzeczy, ale to nie wystarcza: ktoś może
// wysłać żądanie z pominięciem interfejsu (curl, Postman, zmodyfikowany JS)
// więc backend musi sam pilnować poprawności danych, niezależnie od frontu.

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const MONTH_RE = /^\d{4}-\d{2}$/;

function isNonEmptyString(v, max = 300) {
  return typeof v === 'string' && v.trim().length > 0 && v.trim().length <= max;
}
function isValidEmail(v) {
  return typeof v === 'string' && v.trim().length <= 254 && EMAIL_RE.test(v.trim());
}
function isValidDate(v) {
  if (v === '' || v === null || v === undefined) return true; // pola dat są opcjonalne w wielu miejscach
  return typeof v === 'string' && DATE_RE.test(v) && !isNaN(Date.parse(v));
}
function isValidMonth(v) {
  if (v === '' || v === null || v === undefined) return false;
  return typeof v === 'string' && MONTH_RE.test(v);
}
function isPositiveNumber(v) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0;
}
function isNonNegativeNumber(v) {
  const n = Number(v);
  return Number.isFinite(n) && n >= 0;
}
function isInEnum(v, allowed) {
  return allowed.includes(v);
}
function isValidPassword(v) {
  return typeof v === 'string' && v.length >= 6 && v.length <= 200;
}

/**
 * Middleware fabrykujące walidację ciała żądania na podstawie prostego opisu pól.
 * rules: { pole: { required, type: 'string'|'email'|'date'|'month'|'positiveNumber'|'nonNegativeNumber'|'enum'|'password', enum: [...], max } }
 * W razie błędu odpowiada 400 z czytelnym komunikatem po polsku i nie wywołuje next().
 */
function validateBody(rules) {
  return (req, res, next) => {
    const body = req.body || {};
    for (const [field, rule] of Object.entries(rules)) {
      const val = body[field];
      const present = val !== undefined && val !== null && val !== '';
      if (rule.required && !present) {
        return res.status(400).json({ error: `Pole "${field}" jest wymagane.` });
      }
      if (!present) continue; // pole opcjonalne i puste — pomijamy dalszą walidację
      let ok = true;
      switch (rule.type) {
        case 'string': ok = isNonEmptyString(val, rule.max || 300); break;
        case 'email': ok = isValidEmail(val); break;
        case 'date': ok = isValidDate(val); break;
        case 'month': ok = isValidMonth(val); break;
        case 'positiveNumber': ok = isPositiveNumber(val); break;
        case 'nonNegativeNumber': ok = isNonNegativeNumber(val); break;
        case 'enum': ok = isInEnum(val, rule.enum || []); break;
        case 'password': ok = isValidPassword(val); break;
        default: ok = true;
      }
      if (!ok) {
        return res.status(400).json({ error: `Pole "${field}" ma nieprawidłową wartość.` });
      }
    }
    next();
  };
}

module.exports = {
  isNonEmptyString, isValidEmail, isValidDate, isValidMonth,
  isPositiveNumber, isNonNegativeNumber, isInEnum, isValidPassword,
  validateBody,
};
