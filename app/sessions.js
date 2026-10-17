import { selectFeatures } from './schema.js';
import { validatePrediction } from './model-adapter.js';

export async function buildSessions(events, predict, { active = () => true, yieldControl = null } = {}) {
  const groups = new Map();
  let processed = 0;
  for (const event of events) {
    if (yieldControl && processed++ % 250 === 0) await yieldControl();
    if (!active()) throw new Error('İçe aktarma iptal edildi.');
    let group = groups.get(event.session_token);
    if (!group) {
      group = { id: event.session_token, events: [], latest: event, score: null, reasons: [], modelVersion: null, scoredEvent: null, unscored: 0, error: false, mock: false };
      groups.set(event.session_token, group);
    }
    group.events.push(event);
    if (Date.parse(event.event_ts_utc) > Date.parse(group.latest.event_ts_utc)) group.latest = event;
    try {
      const prediction = validatePrediction(await predict(selectFeatures(event)));
      if (prediction === null) { group.unscored++; continue; }
      if (group.score === null || prediction.risk_score > group.score ||
          (prediction.risk_score === group.score && Date.parse(event.event_ts_utc) > Date.parse(group.scoredEvent.event_ts_utc))) {
        group.score = prediction.risk_score;
        group.reasons = prediction.reasons;
        group.modelVersion = prediction.model_version;
        group.scoredEvent = event;
      }
    } catch {
      group.error = true;
      group.unscored++;
    }
  }
  // A partially scored session must not appear completely evaluated.
  for (const group of groups.values()) {
    if (group.unscored) {
      group.score = null;
      group.reasons = [];
      group.modelVersion = null;
      group.scoredEvent = null;
    }
  }
  return [...groups.values()].sort((a, b) => Date.parse(b.latest.event_ts_utc) - Date.parse(a.latest.event_ts_utc));
}
