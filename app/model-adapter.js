/** AI 3 integration boundary. No trained model or fallback scoring is shipped.
 * Input: exactly 11 allowlisted features (nullable); never IDs, timestamp or labels.
 * Output: null OR { risk_score: integer (0..100), reasons: string[], model_version: string }.
 * A future implementation must stay entirely in the customer's environment.
 */
export async function predictRisk(_features) {
  return null;
}

export function validatePrediction(result) {
  if (result === null) return null;
  if (!result || !Number.isInteger(result.risk_score) || result.risk_score < 0 || result.risk_score > 100 ||
      typeof result.model_version !== 'string' || !result.model_version.trim() || result.model_version.length > 80 ||
      !Array.isArray(result.reasons) || result.reasons.length > 6 ||
      result.reasons.some(reason => typeof reason !== 'string' || !reason.trim() || reason.length > 240)) {
    throw new Error('Model yanıtı sözleşmeyle eşleşmiyor. Oturum puanlanmadı.');
  }
  return { risk_score: result.risk_score, reasons: [...result.reasons], model_version: result.model_version };
}
