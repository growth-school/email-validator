const net = require("net");
const { cache } = require("../utils/cache");

const CONNECT_MS = Number(process.env.SMTP_CONNECT_MS) || 8000;
const CMD_MS = Number(process.env.SMTP_CMD_MS) || 5000;

function extractDomain(email) {
  const i = email.lastIndexOf("@");
  return i >= 0 ? email.slice(i + 1) : "";
}

function parseSmtpCode(line) {
  const m = /^(\d{3})([ -])/.exec(line || "");
  return m ? parseInt(m[1], 10) : 0;
}

function createLineReader(socket) {
  let buffer = "";
  return {
    nextLine(timeoutMs) {
      return new Promise((resolve, reject) => {
        const tryFlush = () => {
          const idx = buffer.indexOf("\r\n");
          if (idx === -1) return null;
          const line = buffer.slice(0, idx);
          buffer = buffer.slice(idx + 2);
          return line;
        };
        const immediate = tryFlush();
        if (immediate != null) {
          resolve(immediate);
          return;
        }
        const timer = setTimeout(() => {
          socket.removeListener("data", onData);
          socket.removeListener("error", onErr);
          reject(new Error("read_timeout"));
        }, timeoutMs);
        function onData(chunk) {
          buffer += chunk.toString();
          const line = tryFlush();
          if (line != null) {
            clearTimeout(timer);
            socket.removeListener("data", onData);
            socket.removeListener("error", onErr);
            resolve(line);
          }
        }
        function onErr(err) {
          clearTimeout(timer);
          socket.removeListener("data", onData);
          socket.removeListener("error", onErr);
          reject(err);
        }
        socket.on("data", onData);
        socket.once("error", onErr);
      });
    },
    async readResponse(timeoutMs) {
      let lastLine = "";
      let code = 0;
      while (true) {
        const line = await this.nextLine(timeoutMs);
        lastLine = line;
        code = parseSmtpCode(line);
        if (/^\d{3} /.test(line)) break;
      }
      return { lastLine, code };
    },
  };
}

function connectMx(host) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ port: 25, host }, () => {
      clearTimeout(timer);
      resolve(socket);
    });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("connect_timeout"));
    }, CONNECT_MS);
    socket.once("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

/**
 * @param {string} email
 * @param {string[]} mxRecords sorted by priority (lowest first)
 * @returns {Promise<{ pass: boolean, code: number, catchAll: boolean, reason: string | null, risky?: boolean }>}
 */
async function checkSMTP(email, mxRecords) {
  if (!mxRecords || mxRecords.length === 0) {
    return { pass: false, code: 0, catchAll: false, reason: "no_mx" };
  }

  const primary = mxRecords[0].replace(/\.$/, "");
  const waitMs = cache.smtpThrottleWait(primary, 10_000);
  if (waitMs > 0) {
    await new Promise((r) => setTimeout(r, waitMs));
  }
  cache.recordSmtpAttempt(primary);

  let socket;
  try {
    socket = await connectMx(primary);
  } catch (err) {
    const code = err && err.code;
    if (code === "ECONNREFUSED" || code === "EHOSTUNREACH" || code === "ENETUNREACH") {
      return { pass: false, code: 0, catchAll: false, reason: "connection_refused" };
    }
    if (err.message === "connect_timeout") {
      return { pass: false, code: 0, catchAll: false, reason: "timeout" };
    }
    return { pass: false, code: 0, catchAll: false, reason: "connect_error" };
  }

  const reader = createLineReader(socket);

  try {
    const banner = await reader.readResponse(CMD_MS);
    if (Math.floor(banner.code / 100) !== 2) {
      return { pass: false, code: banner.code, catchAll: false, reason: "bad_banner" };
    }

    socket.write("EHLO validator.check\r\n");
    const ehlo = await reader.readResponse(CMD_MS);
    if (Math.floor(ehlo.code / 100) !== 2) {
      return { pass: false, code: ehlo.code, catchAll: false, reason: "ehlo_failed" };
    }

    socket.write("MAIL FROM:<check@validator.check>\r\n");
    const mailFrom = await reader.readResponse(CMD_MS);
    if (Math.floor(mailFrom.code / 100) !== 2) {
      return { pass: false, code: mailFrom.code, catchAll: false, reason: "mail_from_rejected" };
    }

    const domain = extractDomain(email);
    const probeLocal = "zzznobodyhere_test_123";
    const probeAddr = `${probeLocal}@${domain}`;

    socket.write(`RCPT TO:<${probeAddr}>\r\n`);
    const probeResp = await reader.readResponse(CMD_MS);
    const probeCode = probeResp.code;

    if (probeCode === 250) {
      socket.write("QUIT\r\n");
      try {
        await reader.readResponse(CMD_MS);
      } catch {
        /* ignore */
      }
      return { pass: true, code: 250, catchAll: true, reason: null };
    }

    const tempCodes = new Set([421, 450, 451, 452]);
    if (tempCodes.has(probeCode)) {
      socket.write("QUIT\r\n");
      try {
        await reader.readResponse(CMD_MS);
      } catch {
        /* ignore */
      }
      return { pass: false, code: probeCode, catchAll: false, reason: "temp_failure", risky: true };
    }

    socket.write(`RCPT TO:<${email}>\r\n`);
    const rcpt = await reader.readResponse(CMD_MS);
    const code = rcpt.code;

    socket.write("QUIT\r\n");
    try {
      await reader.readResponse(CMD_MS);
    } catch {
      /* ignore */
    }

    if (code === 250) {
      return { pass: true, code: 250, catchAll: false, reason: null };
    }

    if (tempCodes.has(code)) {
      return { pass: false, code, catchAll: false, reason: "temp_failure", risky: true };
    }

    if ([550, 551, 552, 553].includes(code)) {
      return { pass: false, code, catchAll: false, reason: "mailbox_unavailable" };
    }

    if (code >= 500 && code < 600) {
      return { pass: false, code, catchAll: false, reason: "smtp_5xx" };
    }

    return { pass: false, code, catchAll: false, reason: "rcpt_rejected" };
  } catch (err) {
    if (err.message === "read_timeout") {
      return { pass: false, code: 0, catchAll: false, reason: "timeout" };
    }
    return { pass: false, code: 0, catchAll: false, reason: "smtp_error" };
  } finally {
    try {
      socket.destroy();
    } catch {
      /* ignore */
    }
  }
}

module.exports = { checkSMTP, extractDomain, createLineReader, parseSmtpCode };
