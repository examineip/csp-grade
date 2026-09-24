/*!
 * csp-grade — grade a Content-Security-Policy on whether it actually stops
 * injected script, rather than on which keywords appear in the header.
 * Works in Node (require) and the browser (window.cspGrade). No dependencies.
 * MIT licence — https://github.com/examineip/csp-grade
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.cspGrade = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /* Directives that make a policy relevant to script injection at all. A
     header containing only upgrade-insecure-requests restricts nothing that
     matters for XSS, and should not be graded as protection. */
  var FETCH_DIRECTIVES = ['default-src', 'script-src', 'script-src-elem', 'object-src'];

  /**
   * Parse a policy into { name: value }.
   *
   * The FIRST occurrence of a directive wins: CSP says a duplicate directive
   * name in the same policy is ignored, not merged and not overriding. Taking
   * the last one — the obvious implementation — grades a policy by a directive
   * the browser will never apply.
   */
  function parse(policy) {
    var dir = {};
    if (typeof policy !== 'string') { return dir; }
    var parts = policy.split(';');
    for (var i = 0; i < parts.length; i++) {
      var d = parts[i].trim();
      if (d === '') { continue; }
      var bits = d.split(/\s+/);
      var name = String(bits.shift()).toLowerCase();
      if (name === '') { continue; }
      if (Object.prototype.hasOwnProperty.call(dir, name)) { continue; }  /* first wins */
      dir[name] = bits.join(' ').toLowerCase();
    }
    return dir;
  }

  /**
   * The directive a browser actually consults for a <script> element:
   * script-src-elem, else script-src, else default-src.
   *
   * Grading the whole header string instead is the single most common mistake.
   * github.com and developer.mozilla.org both set style-src 'unsafe-inline'
   * beside a hash-based script-src; a substring search over the header marks
   * both of them weak, which is simply wrong.
   */
  function effectiveScriptSrc(dir) {
    if (Object.prototype.hasOwnProperty.call(dir, 'script-src-elem')) {
      return { name: 'script-src-elem', value: dir['script-src-elem'] };
    }
    if (Object.prototype.hasOwnProperty.call(dir, 'script-src')) {
      return { name: 'script-src', value: dir['script-src'] };
    }
    if (Object.prototype.hasOwnProperty.call(dir, 'default-src')) {
      return { name: 'default-src', value: dir['default-src'] };
    }
    return { name: null, value: '' };
  }

  function has(value, token) {
    return value.indexOf(token) !== -1;
  }

  function hasHash(value) {
    if (has(value, "'sha256-")) { return true; }
    if (has(value, "'sha384-")) { return true; }
    if (has(value, "'sha512-")) { return true; }
    return false;
  }

  /** A source list that allows script from anywhere defeats the purpose. */
  function wildcardSources(value) {
    var found = [];
    var tokens = value.split(/\s+/);
    for (var i = 0; i < tokens.length; i++) {
      var t = tokens[i];
      if (t === '*') { found.push('*'); }
      if (t === 'https:') { found.push('https:'); }
      if (t === 'http:') { found.push('http:'); }
      if (t === 'data:') { found.push('data:'); }
    }
    return found;
  }

  /**
   * Grade a policy.
   *
   * @param {string} policy       the Content-Security-Policy header value
   * @param {object} [opts]       { reportOnly: true } if it came from the
   *                              Content-Security-Policy-Report-Only header
   * @returns {object} { status, directive, value, how, findings, note }
   *   status is 'ok', 'weak' or 'missing'.
   */
  function grade(policy, opts) {
    opts = opts || {};
    var findings = [];

    if (typeof policy !== 'string' || policy.trim() === '') {
      return {
        status: 'missing',
        directive: null,
        value: '',
        how: null,
        findings: findings,
        note: 'No policy, so the browser will run script from anywhere the page references.'
      };
    }

    if (opts.reportOnly) {
      return {
        status: 'weak',
        directive: null,
        value: policy,
        how: null,
        findings: ['report-only'],
        note: 'Only a report-only policy is set. It records violations and blocks nothing.'
      };
    }

    var dir = parse(policy);

    var hasFetch = false;
    for (var i = 0; i < FETCH_DIRECTIVES.length; i++) {
      if (Object.prototype.hasOwnProperty.call(dir, FETCH_DIRECTIVES[i])) { hasFetch = true; }
    }
    if (!hasFetch) {
      return {
        status: 'weak',
        directive: null,
        value: policy,
        how: null,
        findings: ['no-fetch-directive'],
        note: 'The header is present but sets no script or default source, so it '
            + 'restricts nothing that matters for XSS. A policy of only '
            + 'upgrade-insecure-requests is the common example.'
      };
    }

    var eff = effectiveScriptSrc(dir);
    var value = eff.value;

    if (has(value, "'none'")) {
      return {
        status: 'ok',
        directive: eff.name,
        value: policy,
        how: 'none',
        findings: [],
        note: eff.name + " is 'none', so no script may load at all."
      };
    }

    var nonce = has(value, "'nonce-");
    var hash = hasHash(value);
    var keyed = nonce || hash;
    var strictDynamic = has(value, "'strict-dynamic'");

    /* CSP Level 3: when a nonce or hash is present, browsers IGNORE
       'unsafe-inline' in that directive. Sites include it deliberately as a
       fallback for older browsers, so penalising it reports the recommended
       pattern as a weakness. 'unsafe-eval' is NOT neutralised this way. */
    var inlineListed = has(value, "'unsafe-inline'");
    var inlineLive = inlineListed ? !keyed : false;
    var evalLive = has(value, "'unsafe-eval'");

    if (inlineLive) { findings.push('unsafe-inline'); }
    if (evalLive) { findings.push('unsafe-eval'); }

    var wild = strictDynamic ? [] : wildcardSources(value);
    for (var w = 0; w < wild.length; w++) { findings.push('wildcard:' + wild[w]); }

    if (inlineLive) {
      return {
        status: 'weak',
        directive: eff.name,
        value: policy,
        how: 'source-list',
        findings: findings,
        note: eff.name + " allows 'unsafe-inline' with no nonce or hash, which "
            + 'permits exactly the injected inline script CSP exists to block.'
      };
    }

    if (evalLive) {
      return {
        status: 'weak',
        directive: eff.name,
        value: policy,
        how: nonce ? 'nonce-based' : (hash ? 'hash-based' : 'source-list'),
        findings: findings,
        note: eff.name + " allows 'unsafe-eval', so eval() and friends still run. "
            + 'A nonce does not cancel this one out.'
      };
    }

    if (wild.length && !keyed) {
      return {
        status: 'weak',
        directive: eff.name,
        value: policy,
        how: 'source-list',
        findings: findings,
        note: eff.name + ' allows script from ' + wild.join(', ')
            + ', which is broad enough that the allowlist is not really restricting anything.'
      };
    }

    var how = nonce ? 'nonce-based' : (hash ? 'hash-based' : 'source-list');
    var note = 'Restricts where script may load from (' + how + ').';

    if (inlineListed) {
      note += " It also lists 'unsafe-inline', which browsers ignore because a "
           + (nonce ? 'nonce' : 'hash')
           + ' is present - that is the intended fallback for older browsers, '
           + 'not a weakness.';
      findings.push('unsafe-inline-neutralised');
    }
    if (strictDynamic) {
      note += " 'strict-dynamic' is set, so host allowlists are ignored in favour "
           + 'of the nonce or hash.';
      findings.push('strict-dynamic');
    }

    return {
      status: 'ok',
      directive: eff.name,
      value: policy,
      how: how,
      findings: findings,
      note: note
    };
  }

  return {
    grade: grade,
    parse: parse,
    effectiveScriptSrc: effectiveScriptSrc
  };
});
