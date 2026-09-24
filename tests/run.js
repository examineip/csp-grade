'use strict';
// node tests/run.js
//
// The important cases here are the REAL policies in tests/real-policies.json.
// Synthetic tests would not have caught the bug this library exists to avoid,
// because they would have been written with the same wrong assumption that
// produced it.

const path = require('path');
const assert = require('assert');
const csp = require(path.join(__dirname, '..', 'csp-grade.js'));
const REAL = require(path.join(__dirname, 'real-policies.json'));

let passed = 0;
const failures = [];

function check(label, fn) {
  try {
    fn();
    passed++;
  } catch (e) {
    failures.push(`${label}\n    ${e.message.split('\n').join('\n    ')}`);
  }
}

// ---------------------------------------------------------------------------
// 1. Real policies — the regression set
//
// github.com and developer.mozilla.org both set style-src 'unsafe-inline'
// beside a hash-based script-src. A substring search over the header marks
// both weak. They are not weak, and that is the whole point of the library.
// ---------------------------------------------------------------------------
check('github.com grades ok despite unsafe-inline in style-src', () => {
  const pol = REAL.policies['github.com'];
  assert.ok(pol, 'fixture missing');
  assert.ok(pol.indexOf("'unsafe-inline'") !== -1, 'fixture should contain unsafe-inline somewhere');
  const g = csp.grade(pol);
  assert.strictEqual(g.status, 'ok', g.note);
  assert.strictEqual(g.how, 'hash-based');
});

check('developer.mozilla.org grades ok, judged on script-src-elem', () => {
  const pol = REAL.policies['developer.mozilla.org'];
  assert.ok(pol, 'fixture missing');
  const g = csp.grade(pol);
  assert.strictEqual(g.status, 'ok', g.note);
  assert.strictEqual(g.directive, 'script-src-elem');
});

check('cloudflare.com grades weak - unsafe-inline really is in script-src', () => {
  const pol = REAL.policies['cloudflare.com'];
  assert.ok(pol, 'fixture missing');
  const g = csp.grade(pol);
  assert.strictEqual(g.status, 'weak');
  assert.ok(g.findings.indexOf('unsafe-inline') !== -1, JSON.stringify(g.findings));
});

check('every captured policy is graded without throwing', () => {
  for (const [site, pol] of Object.entries(REAL.policies)) {
    const g = csp.grade(pol);
    assert.ok(['ok', 'weak', 'missing'].indexOf(g.status) !== -1, site);
    assert.ok(typeof g.note === 'string' && g.note.length > 0, site);
  }
});

// ---------------------------------------------------------------------------
// 2. The CSP Level 3 rule: a nonce or hash makes browsers IGNORE
//    'unsafe-inline' in the same directive. 'unsafe-eval' is not affected.
// ---------------------------------------------------------------------------
check("unsafe-inline alone is weak", () => {
  const g = csp.grade("script-src 'self' 'unsafe-inline'");
  assert.strictEqual(g.status, 'weak');
  assert.ok(g.findings.indexOf('unsafe-inline') !== -1);
});

check("unsafe-inline WITH a nonce is fine, and says so", () => {
  const g = csp.grade("script-src 'nonce-r4nd0m' 'unsafe-inline'");
  assert.strictEqual(g.status, 'ok');
  assert.strictEqual(g.how, 'nonce-based');
  assert.ok(g.findings.indexOf('unsafe-inline-neutralised') !== -1);
  assert.ok(/ignore/i.test(g.note), 'the note should explain why it is not a weakness');
});

check("unsafe-inline WITH a hash is fine", () => {
  const g = csp.grade("script-src 'sha256-abc123=' 'unsafe-inline'");
  assert.strictEqual(g.status, 'ok');
  assert.strictEqual(g.how, 'hash-based');
});

check("a nonce does NOT rescue unsafe-eval", () => {
  const g = csp.grade("script-src 'nonce-r4nd0m' 'unsafe-eval'");
  assert.strictEqual(g.status, 'weak');
  assert.ok(g.findings.indexOf('unsafe-eval') !== -1);
});

check('sha384 and sha512 count as hashes too', () => {
  assert.strictEqual(csp.grade("script-src 'sha384-x' 'unsafe-inline'").status, 'ok');
  assert.strictEqual(csp.grade("script-src 'sha512-x' 'unsafe-inline'").status, 'ok');
});

// ---------------------------------------------------------------------------
// 3. Which directive is consulted
// ---------------------------------------------------------------------------
check('script-src overrides default-src', () => {
  const g = csp.grade("default-src 'unsafe-inline'; script-src 'self'");
  assert.strictEqual(g.directive, 'script-src');
  assert.strictEqual(g.status, 'ok');
});

check('default-src is used when there is no script-src', () => {
  const g = csp.grade("default-src 'self'");
  assert.strictEqual(g.directive, 'default-src');
  assert.strictEqual(g.status, 'ok');
});

check('script-src-elem wins over script-src', () => {
  const g = csp.grade("script-src 'unsafe-inline'; script-src-elem 'self'");
  assert.strictEqual(g.directive, 'script-src-elem');
  assert.strictEqual(g.status, 'ok');
});

check('unsafe-inline in style-src is ignored entirely', () => {
  const g = csp.grade("script-src 'self'; style-src 'unsafe-inline'");
  assert.strictEqual(g.status, 'ok');
  assert.deepStrictEqual(g.findings, []);
});

check('a duplicate directive is ignored - the FIRST one wins', () => {
  // CSP says a repeated directive name in one policy is ignored, not merged
  // and not overriding. Taking the last one grades by a directive the browser
  // will never apply.
  const d = csp.parse("script-src 'self'; script-src 'unsafe-inline'");
  assert.strictEqual(d['script-src'], "'self'");
  assert.strictEqual(csp.grade("script-src 'self'; script-src 'unsafe-inline'").status, 'ok');
});

// ---------------------------------------------------------------------------
// 4. Policies that look like protection and are not
// ---------------------------------------------------------------------------
check('a policy with no fetch directive restricts nothing', () => {
  const g = csp.grade('upgrade-insecure-requests');
  assert.strictEqual(g.status, 'weak');
  assert.ok(g.findings.indexOf('no-fetch-directive') !== -1);
});

check('report-only blocks nothing', () => {
  const g = csp.grade("script-src 'self'", { reportOnly: true });
  assert.strictEqual(g.status, 'weak');
  assert.ok(g.findings.indexOf('report-only') !== -1);
});

check('a wildcard source list is not real protection', () => {
  assert.strictEqual(csp.grade('script-src *').status, 'weak');
  assert.strictEqual(csp.grade('script-src https:').status, 'weak');
});

check("but a wildcard alongside strict-dynamic is fine - the allowlist is ignored", () => {
  const g = csp.grade("script-src 'nonce-abc' 'strict-dynamic' https:");
  assert.strictEqual(g.status, 'ok');
  assert.ok(g.findings.indexOf('strict-dynamic') !== -1);
});

check("'none' is the strongest answer", () => {
  const g = csp.grade("script-src 'none'");
  assert.strictEqual(g.status, 'ok');
  assert.strictEqual(g.how, 'none');
});

// ---------------------------------------------------------------------------
// 5. Absent and malformed input
// ---------------------------------------------------------------------------
check('no header is missing, not weak', () => {
  assert.strictEqual(csp.grade('').status, 'missing');
  assert.strictEqual(csp.grade('   ').status, 'missing');
  assert.strictEqual(csp.grade(null).status, 'missing');
  assert.strictEqual(csp.grade(undefined).status, 'missing');
});

check('case and stray semicolons do not matter', () => {
  const g = csp.grade(";; SCRIPT-SRC 'SELF' ;;");
  assert.strictEqual(g.status, 'ok');
  assert.strictEqual(g.directive, 'script-src');
});

check('non-strings do not throw', () => {
  for (const v of [42, {}, [], true]) {
    const g = csp.grade(v);
    assert.ok(g && typeof g.status === 'string');
  }
});

// ---------------------------------------------------------------------------
console.log(`${passed} passed, ${failures.length} failed`);
if (failures.length) {
  console.log('');
  for (const f of failures) { console.log('  FAIL  ' + f); }
  process.exit(1);
}
