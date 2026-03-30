const LOG_LEVEL = process.env.LOG_LEVEL || "info";

const levels = { error: 0, warn: 1, info: 2, debug: 3 };

function shouldLog(level) {
  const lv = levels[level];
  const cur = levels[LOG_LEVEL];
  if (lv == null || cur == null) return true;
  return lv <= cur;
}

function emit(level, message, data = {}, requestId = null) {
  if (level !== "error" && !shouldLog(level)) return;
  const payload = {
    level,
    timestamp: new Date().toISOString(),
    message,
  };
  if (requestId) payload.requestId = requestId;
  if (data && Object.keys(data).length) payload.data = data;
  const line = JSON.stringify(payload);
  if (level === "error") console.error(line);
  else console.log(line);
}

function createLogger(requestId) {
  return {
    info: (message, data) => emit("info", message, data, requestId),
    warn: (message, data) => emit("warn", message, data, requestId),
    error: (message, data) => emit("error", message, data, requestId),
    debug: (message, data) => emit("debug", message, data, requestId),
  };
}

module.exports = { createLogger, emit };
