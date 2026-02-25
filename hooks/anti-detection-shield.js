// ═══════════════════════════════════════════════════════════════
//  SENTINEL v7.0.0 — ANTI-DETECTION SHIELD
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v7.0.0 (2026-02-26):
//   - PURE NEW: Full rewrite as class-based module
//   - FROM v5.0.0: hookFunction with toString() protection
//   - FROM v5.0.0: hookGetter with descriptor preservation
//   - FROM v5.0.0: WeakMap descriptor cache with target-qualified key
//   - FROM v5.0.0: Error.prepareStackTrace cleanup
//   - FROM v5.0.0: getOwnPropertyDescriptors (plural) protection
//   - FROM v5.0.0: Non-enumerable globals (Quiet Mode)
//   - FROM v5.0.0: Zero console.log output
//   - NEW: hookGetterSetter for document.cookie dual-hook
//   - NEW: smartHookGetter for auto instance/prototype detection
//   - FIX: Vue/Nuxt crash prevention via target-qualified WeakMap key
//   - FIX: Prototype shadow bug from v4.4.0 prevented
//
// LAST HISTORY LOG:
//   v6.4.0: No shield (ZERO injection philosophy)
//   v6.1.0: Stealth via puppeteer-extra-plugin only
//   v5.0.0: Full shield with 25 regression rules
//   v7.0.0: Restored from v5.0.0 with cross-analysis fixes
// ═══════════════════════════════════════════════════════════════

function getShieldScript() {
  return `
(function() {
  'use strict';
  var _descriptorCache = new WeakMap();
  function _getCachedDescriptor(target, prop) {
    var cache = _descriptorCache.get(target);
    if (!cache) return null;
    return cache[prop] || null;
  }
  function _setCachedDescriptor(target, prop, desc) {
    var cache = _descriptorCache.get(target);
    if (!cache) { cache = {}; _descriptorCache.set(target, cache); }
    cache[prop] = desc;
  }
  function hookFunction(obj, prop, handler) {
    if (!obj || typeof obj[prop] !== 'function') return false;
    var original = obj[prop];
    var originalStr = Function.prototype.toString.call(original);
    obj[prop] = function() { handler.apply(this, arguments); return original.apply(this, arguments); };
    obj[prop].toString = function() { return originalStr; };
    obj[prop].toLocaleString = function() { return originalStr; };
    try {
      Object.defineProperty(obj[prop], 'name', { value: original.name, configurable: true });
      Object.defineProperty(obj[prop], 'length', { value: original.length, configurable: true });
    } catch(e) {}
    return true;
  }
  function hookGetter(obj, prop, handler) {
    if (!obj) return false;
    var desc = null; var target = obj;
    while (target && !desc) { desc = Object.getOwnPropertyDescriptor(target, prop); if (!desc) target = Object.getPrototypeOf(target); }
    if (!desc) return false;
    _setCachedDescriptor(obj, prop, desc);
    var originalGet = desc.get; var originalValue = desc.value;
    if (originalGet) {
      Object.defineProperty(obj, prop, { get: function() { var val = originalGet.call(this); handler(val); return val; }, set: desc.set, enumerable: desc.enumerable, configurable: true });
    } else if ('value' in desc) {
      Object.defineProperty(obj, prop, { get: function() { handler(originalValue); return originalValue; }, enumerable: desc.enumerable, configurable: true });
    }
    return true;
  }
  function hookGetterSetter(obj, prop, getHandler, setHandler) {
    if (!obj) return false;
    var desc = Object.getOwnPropertyDescriptor(obj, prop);
    if (!desc && obj.__proto__) desc = Object.getOwnPropertyDescriptor(obj.__proto__, prop);
    if (!desc) return false;
    _setCachedDescriptor(obj, prop, desc);
    var originalGet = desc.get; var originalSet = desc.set;
    var newDesc = { enumerable: desc.enumerable, configurable: true };
    if (originalGet) { newDesc.get = function() { var val = originalGet.call(this); getHandler(val); return val; }; }
    if (originalSet) { newDesc.set = function(val) { setHandler(val); return originalSet.call(this, val); }; }
    Object.defineProperty(obj, prop, newDesc);
    return true;
  }
  function smartHookGetter(instance, proto, prop, handler) {
    var instanceDesc = Object.getOwnPropertyDescriptor(instance, prop);
    if (instanceDesc) return hookGetter(instance, prop, handler);
    if (proto) { var protoDesc = Object.getOwnPropertyDescriptor(proto, prop); if (protoDesc) return hookGetter(proto, prop, handler); }
    if (prop in instance) return hookGetter(instance, prop, handler);
    return false;
  }
  var _origPrepare = Error.prepareStackTrace;
  Error.prepareStackTrace = function(error, stack) {
    var filtered = stack.filter(function(frame) {
      var file = frame.getFileName() || '';
      return file.indexOf('puppeteer') === -1 && file.indexOf('playwright') === -1 && file.indexOf('pptr:') === -1 && file.indexOf('__puppeteer') === -1 && file.indexOf('__playwright') === -1 && file.indexOf('sentinel') === -1 && file.indexOf('addInitScript') === -1;
    });
    if (_origPrepare) return _origPrepare(error, filtered);
    return error.toString() + '\\n' + filtered.map(function(f) { return '    at ' + f.toString(); }).join('\\n');
  };
  var _origGetDescs = Object.getOwnPropertyDescriptors;
  if (_origGetDescs) {
    Object.getOwnPropertyDescriptors = function(obj) {
      var descs = _origGetDescs.call(Object, obj);
      if (_descriptorCache.has(obj)) { var cache = _descriptorCache.get(obj) || {}; for (var prop in cache) { if (cache.hasOwnProperty(prop) && descs[prop]) descs[prop] = cache[prop]; } }
      return descs;
    };
    Object.getOwnPropertyDescriptors.toString = function() { return 'function getOwnPropertyDescriptors() { [native code] }'; };
  }
  var _origGetDesc = Object.getOwnPropertyDescriptor;
  Object.getOwnPropertyDescriptor = function(obj, prop) {
    var cached = _getCachedDescriptor(obj, prop);
    if (cached) return cached;
    return _origGetDesc.call(Object, obj, prop);
  };
  Object.getOwnPropertyDescriptor.toString = function() { return 'function getOwnPropertyDescriptor() { [native code] }'; };
  Object.defineProperty(window, '__SENTINEL_SHIELD__', { value: true, writable: false, enumerable: false, configurable: false });
  Object.defineProperty(window, '__SENTINEL_HOOKS__', {
    value: { hookFunction: hookFunction, hookGetter: hookGetter, hookGetterSetter: hookGetterSetter, smartHookGetter: smartHookGetter },
    writable: false, enumerable: false, configurable: false
  });
})();
`;
}

module.exports = { getShieldScript };
