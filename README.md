# csp-grade

Grade a Content-Security-Policy on whether it actually stops injected script.

Most CSP checkers search the header for `'unsafe-inline'` and report a weakness if they find
it. That is wrong twice over, and both mistakes are common enough to see on real sites.

One file, no dependencies, works in Node and the browser.

```js
const csp = require('csp-grade');

csp.grade("script-src 'nonce-r4nd0m' 'unsafe-inline'");
// {
//   status:    'ok',
//   directive: 'script-src',
//   how:       'nonce-based',
//   findings:  ['unsafe-inline-neutralised'],
//   note:      "Restricts where script may load from (nonce-based). It also lists
//               'unsafe-inline', which browsers ignore because a nonce is present -
//               that is the intended fallback for older browsers, not a weakness."
// }
```

## The two mistakes

**A nonce or hash makes browsers ignore `'unsafe-inline'` in that directive.** That is CSP
Level 3, and sites include the keyword deliberately as a fallback for older browsers. Flagging
it reports the *recommended* pattern as a weakness. `'unsafe-eval'` is a separate matter — a
nonce does not neutralise it, and this library still marks it weak.

**Only the directive the browser consults counts.** For a `<script>` element that is
`script-src-elem`, falling back to `script-src`, then `default-src`. Grading the whole header
string catches `'unsafe-inline'` sitting harmlessly in `style-src`.

Both mistakes are in the test fixtures, taken from real sites:

| site | shape | naive check | this library |
|---|---|---|---|
| github.com | hash in `script-src`, `unsafe-inline` in `style-src` | weak | **ok** |
| developer.mozilla.org | hash in `script-src-elem`, `unsafe-inline` in `style-src` | weak | **ok** |
| cloudflare.com | `unsafe-inline` **and** `unsafe-eval` in `script-src` | weak | **weak** |

The third one matters as much as the first two: a library that simply never reports a weakness
would also "pass" the first two rows.

## Also caught

**A policy with no fetch directive.** `upgrade-insecure-requests` on its own is a valid header
that restricts nothing relevant to XSS. Reported as weak rather than as protection.

**Report-only.** `Content-Security-Policy-Report-Only` records violations and blocks nothing.
Pass `{ reportOnly: true }` and it is graded accordingly.

**Wildcard source lists.** `script-src *` or `script-src https:` allows script from anywhere,
so the allowlist is not restricting anything — unless `'strict-dynamic'` is present, which
tells browsers to ignore host allowlists in favour of the nonce or hash. Then it is fine.

**Duplicate directives.** CSP says a repeated directive name within one policy is *ignored* —
not merged, not overriding. `parse()` keeps the first. Taking the last, which is the obvious
implementation, grades the policy by a directive the browser will never apply.

## API

| call | returns |
|---|---|
| `grade(policy, opts)` | `{ status, directive, value, how, findings, note }`. `status` is `'ok'`, `'weak'` or `'missing'`. `opts.reportOnly` marks it as a report-only header. |
| `parse(policy)` | `{ name: value }`, first occurrence winning. |
| `effectiveScriptSrc(dir)` | Which directive governs script, and its value. |

`how` is `'nonce-based'`, `'hash-based'`, `'source-list'`, `'none'` or `null`.

## What it does not do

It grades **one header**. It does not fetch anything, does not look at the page, and cannot
tell you whether the nonce is actually random per-response, whether the allowlisted hosts are
trustworthy, or whether a JSONP endpoint on an allowlisted origin undoes the whole policy.

A policy can grade `ok` here and still be bypassable. The `ok` means the directive that governs
script does not obviously defeat itself.

## Tests

```
node tests/run.js
```

`tests/real-policies.json` holds policies captured from live sites with `curl` on the date
recorded in the file. They are **fixtures for regression testing, not a live check** — those
sites may change their policies at any time, and the file does not update itself.

They are in there because synthetic tests would not have caught the bug this library exists to
avoid: they would have been written with the same wrong assumption that produced it.

## Live version

**https://tools.examineip.com/security-headers/**

## Licence

MIT
