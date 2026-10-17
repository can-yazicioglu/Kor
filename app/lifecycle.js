// This releases application references. It does not promise physical memory wiping.
export const MAX_RETENTION_MINUTES = 15;
export function createRetention({ onExpire, now = Date.now, schedule = setTimeout, cancel = clearTimeout }) {
  let deadline = null;
  let timer = null;
  function clear() {
    if (timer !== null) cancel(timer);
    timer = null;
    deadline = null;
  }
  function check() {
    if (deadline !== null && now() >= deadline) {
      clear();
      onExpire();
      return true;
    }
    return false;
  }
  function start(minutes) {
    if (!Number.isInteger(minutes) || minutes < 1 || minutes > MAX_RETENTION_MINUTES) throw new Error('Retention must be between 1 and 15 minutes.');
    clear();
    deadline = now() + minutes * 60000;
    timer = schedule(check, minutes * 60000);
    return deadline;
  }
  return { start, clear, check, remaining: () => deadline === null ? null : Math.max(0, deadline - now()) };
}
