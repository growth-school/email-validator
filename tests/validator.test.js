const dns = require("dns").promises;
const net = require("net");
const { EventEmitter } = require("events");

jest.mock("dns", () => {
  const resolve4 = jest.fn();
  const resolveMx = jest.fn();
  const resolve = jest.fn();
  const resolveTxt = jest.fn().mockRejectedValue(
    Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" })
  );
  class Resolver {
    setServers() {}
    resolve4(...args) {
      return resolve4(...args);
    }
  }
  return {
    promises: {
      resolveMx,
      resolve4,
      resolve,
      resolveTxt,
      Resolver,
    },
  };
});

jest.mock("net", () => ({
  createConnection: jest.fn(),
}));

jest.mock("https", () => ({
  get: jest.fn(),
}));

const { checkSyntax } = require("../src/validators/syntax");
const { checkMX } = require("../src/validators/mx");
const { checkTypo, levenshtein } = require("../src/validators/typo");
const { checkSpamhaus } = require("../src/validators/spamhaus");
const { checkSMTP, createLineReader } = require("../src/validators/smtp");
const { cache } = require("../src/utils/cache");

/** @param {string[]} replies full SMTP lines including CRLF */
function mockSmtpConnection(replies) {
  let idx = 0;
  /** @type {((chunk: Buffer) => void) | null} */
  let dataCb = null;

  const socket = {
    write: jest.fn(() => {
      const line = replies[idx++];
      if (line != null && dataCb) {
        queueMicrotask(() => dataCb(Buffer.from(line)));
      }
    }),
    on: jest.fn((ev, fn) => {
      if (ev === "data") dataCb = fn;
    }),
    once: jest.fn(),
    removeListener: jest.fn(),
    destroy: jest.fn(),
  };

  net.createConnection.mockImplementation((_opts, cb) => {
    queueMicrotask(() => {
      cb();
      queueMicrotask(() => {
        const line = replies[idx++];
        if (line != null && dataCb) {
          dataCb(Buffer.from(line));
        }
      });
    });
    return socket;
  });

  return socket;
}

describe("syntax", () => {
  test("valid email", async () => {
    const r = await checkSyntax("user.name+tag@example.com");
    expect(r.pass).toBe(true);
  });

  test("missing @", async () => {
    const r = await checkSyntax("userexample.com");
    expect(r.pass).toBe(false);
  });

  test("double @", async () => {
    const r = await checkSyntax("a@@b.com");
    expect(r.pass).toBe(false);
  });

  test("local part too long", async () => {
    const local = "a".repeat(65);
    const r = await checkSyntax(`${local}@x.com`);
    expect(r.pass).toBe(false);
  });

  test("invalid TLD", async () => {
    const r = await checkSyntax("u@example.c");
    expect(r.pass).toBe(false);
  });
});

describe("typo", () => {
  test("gmial.com suggests gmail.com", async () => {
    const r = await checkTypo("x@gmial.com");
    expect(r.pass).toBe(false);
    expect(r.suggestion).toBe("gmail.com");
  });

  test("yahoo.com exact match", async () => {
    const r = await checkTypo("a@yahoo.com");
    expect(r.pass).toBe(true);
    expect(r.suggestion).toBeNull();
  });

  test("distance > 2 passes", async () => {
    const r = await checkTypo("a@zzzztotallyunrelated.com");
    expect(r.pass).toBe(true);
  });

  test("levenshtein", () => {
    expect(levenshtein("a", "b")).toBe(1);
    expect(levenshtein("", "abc")).toBe(3);
  });
});

describe("mx", () => {
  beforeEach(() => {
    cache.clear();
    jest.clearAllMocks();
  });

  test("uses MX records when present", async () => {
    dns.resolveMx.mockResolvedValue([
      { priority: 20, exchange: "mx2.example.com." },
      { priority: 10, exchange: "mx1.example.com." },
    ]);
    const r = await checkMX("a@example.com");
    expect(r.pass).toBe(true);
    expect(r.records[0]).toBe("mx1.example.com");
  });

  test("NXDOMAIN fails", async () => {
    const err = new Error("not found");
    err.code = "ENOTFOUND";
    dns.resolveMx.mockRejectedValue(err);
    const r = await checkMX("a@nope.invalid");
    expect(r.pass).toBe(false);
    expect(r.reason).toBe("nxdomain");
  });

  test("dns timeout", async () => {
    dns.resolveMx.mockImplementation(
      () => new Promise((resolve) => setTimeout(() => resolve([]), 6000))
    );
    const r = await checkMX("a@example.com");
    expect(r.pass).toBe(false);
    expect(r.reason).toBe("dns_timeout");
  }, 7000);
});

describe("spamhaus", () => {
  beforeEach(() => {
    cache.clear();
    jest.clearAllMocks();
  });

  test("unlisted domain", async () => {
    const eno = new Error("nx");
    eno.code = "ENOTFOUND";
    dns.resolve4.mockImplementation((host) => {
      if (String(host).endsWith(".dbl.spamhaus.org")) return Promise.reject(eno);
      if (String(host) === "good.example") return Promise.resolve(["1.2.3.4"]);
      if (String(host) === "4.3.2.1.zen.spamhaus.org") return Promise.reject(eno);
      return Promise.reject(eno);
    });
    const r = await checkSpamhaus("u@good.example");
    expect(r.pass).toBe(true);
    expect(r.listed).toBe(false);
    expect(r.warning).toBeNull();
  });

  test("DBL listed", async () => {
    const eno = new Error("nx");
    eno.code = "ENOTFOUND";
    dns.resolve4.mockImplementation((host) => {
      if (String(host).endsWith(".dbl.spamhaus.org")) return Promise.resolve(["127.0.1.4"]);
      if (String(host) === "bad.example") return Promise.resolve(["1.2.3.4"]);
      if (String(host) === "4.3.2.1.zen.spamhaus.org") return Promise.reject(eno);
      return Promise.reject(eno);
    });
    const r = await checkSpamhaus("u@bad.example");
    expect(r.pass).toBe(false);
    expect(r.listed).toBe(true);
    expect(r.lists).toContain("DBL");
  });

  test("policy IP 127.255.255.254 yields warning not clean pass", async () => {
    dns.resolve4.mockImplementation((host) => {
      if (String(host).endsWith(".dbl.spamhaus.org")) return Promise.resolve(["127.255.255.254"]);
      return Promise.reject(Object.assign(new Error("nx"), { code: "ENOTFOUND" }));
    });
    const r = await checkSpamhaus("u@any.example");
    expect(r.pass).toBe(true);
    expect(r.listed).toBe(false);
    expect(r.warning).toBe("spamhaus_resolver_blocked");
  });

  test("soft-fail on timeout", async () => {
    dns.resolve4.mockImplementation(
      () => new Promise((resolve) => setTimeout(() => resolve(["127.0.0.1"]), 6000))
    );
    const r = await checkSpamhaus("u@x.com");
    expect(r.pass).toBe(true);
    expect(r.warning).toBe("spamhaus_unavailable");
  }, 7000);
});

describe("smtp", () => {
  beforeEach(() => {
    cache.clear();
    jest.clearAllMocks();
  });

  test("250 valid mailbox", async () => {
    mockSmtpConnection([
      "220 mx ready\r\n",
      "250 hello\r\n",
      "250 ok\r\n",
      "550 probe\r\n",
      "250 ok\r\n",
      "221 bye\r\n",
    ]);
    const r = await checkSMTP("real@example.com", ["mx.example.com"]);
    expect(r.pass).toBe(true);
    expect(r.catchAll).toBe(false);
    expect(r.code).toBe(250);
  });

  test("catch-all when probe gets 250", async () => {
    mockSmtpConnection([
      "220 mx ready\r\n",
      "250 hello\r\n",
      "250 ok\r\n",
      "250 ok\r\n",
      "221 bye\r\n",
    ]);
    const r = await checkSMTP("real@example.com", ["mx.example.com"]);
    expect(r.pass).toBe(true);
    expect(r.catchAll).toBe(true);
  });

  test("550 on real RCPT", async () => {
    mockSmtpConnection([
      "220 mx ready\r\n",
      "250 hello\r\n",
      "250 ok\r\n",
      "550 no\r\n",
      "550 no\r\n",
      "221 bye\r\n",
    ]);
    const r = await checkSMTP("real@example.com", ["mx.example.com"]);
    expect(r.pass).toBe(false);
    expect(r.code).toBe(550);
  });

  test("read timeout returns reason timeout", async () => {
    let dataCb = null;
    const socket = {
      write: jest.fn(),
      on: jest.fn((ev, fn) => {
        if (ev === "data") dataCb = fn;
      }),
      once: jest.fn(),
      removeListener: jest.fn(),
      destroy: jest.fn(),
    };
    net.createConnection.mockImplementation((_opts, cb) => {
      queueMicrotask(() => {
        cb();
        queueMicrotask(() => {
          if (dataCb) dataCb(Buffer.from("220 hi\r\n"));
        });
      });
      return socket;
    });
    const r = await checkSMTP("a@example.com", ["mx.example.com"]);
    expect(r.reason).toBe("timeout");
  }, 15000);
});

describe("lineReader", () => {
  test("read timeout rejects", async () => {
    const socket = new EventEmitter();
    const reader = createLineReader(socket);
    await expect(reader.nextLine(20)).rejects.toThrow("read_timeout");
  });
});

describe("disposable", () => {
  function mockHttpsList(body) {
    const httpsMod = require("https");
    httpsMod.get.mockImplementation((_url, _opts, cb) => {
      const res = new EventEmitter();
      res.statusCode = 200;
      const req = new EventEmitter();
      req.setTimeout = jest.fn();
      req.destroy = jest.fn();
      queueMicrotask(() => {
        cb(res);
        res.emit("data", Buffer.from(body));
        res.emit("end");
      });
      return req;
    });
  }

  beforeEach(() => {
    jest.resetModules();
    jest.clearAllMocks();
    cache.clear();
  });

  test("blocks known disposable from mock fetch", async () => {
    mockHttpsList("mailinator.com\n");
    const d = require("../src/validators/disposable");
    const r = await d.checkDisposable("u@mailinator.com");
    expect(r.pass).toBe(false);
  });

  test("allows domain not in blocklist", async () => {
    mockHttpsList("mailinator.com\n");
    const d = require("../src/validators/disposable");
    const r = await d.checkDisposable("u@company.com");
    expect(r.pass).toBe(true);
  });
});
