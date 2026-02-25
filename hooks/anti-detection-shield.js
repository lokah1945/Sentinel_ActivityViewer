// ═══════════════════════════════════════════════════════════════
//  SENTINEL v6.0.0 — ANTI-DETECTION SHIELD + QUIET MODE
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v6.0.0 (2026-02-25):
//   FROM v5.0.0:
//   - CHANGED: Stack trace filter now also filters 'patchright' strings
//   - KEPT: All C-SHD-01 through C-SHD-12 contracts intact
//   - KEPT: WeakMap descriptor cache (target-qualified key)
//   - KEPT: Function.prototype.toString masking
//   - KEPT: getOwnPropertyDescriptor/getOwnPropertyDescriptors override
//   - KEPT: Error.prepareStackTrace cleanup
//   - KEPT: Quiet Mode (non-enumerable exports)
//
// LAST HISTORY LOG:
//   v5.0.0: WeakMap cache + toString masking + stack cleanup + Quiet Mode (180 lines)
//   v6.0.0: Added patchright to stack filter
//
// CONTRACT: C-SHD-01 through C-SHD-12
// ═══════════════════════════════════════════════════════════════

function generateShieldScript() {
  return `(function() {
    'use strict';
    if (window.__SENTINEL_SHIELD_OK__) return;

    var realGetOwnPropDesc = Object.getOwnPropertyDescriptor;
    var realGetOwnPropDescs = Object.getOwnPropertyDescriptors;
    var realDefineProperty = Object.defineProperty;
    var realDefineProperties = Object.defineProperties;
    var realToString = Function.prototype.toString;
    var realKeys = Object.keys;
    var realGetOwnPropNames = Object.getOwnPropertyNames;

    // [C-SHD-04] WeakMap descriptor cache — TARGET-QUALIFIED key
    var targetIds = new WeakMap();
    var nextTargetId = 1;
    function getTargetId(target) {
      if (target === null || target === undefined) return '0';
      if (typeof target !== 'object' && typeof target !== 'function') return '0';
      var id = targetIds.get(target);
      if (!id) { id = nextTargetId++; targetIds.set(target, id); }
      return String(id);
    }

    var descCache = {};
    function cacheDescriptor(target, prop, desc) {
      var key = getTargetId(target) + ':' + prop;
      if (!descCache[key] && desc) { descCache[key] = desc; }
    }
    function getCachedDescriptor(target, prop) {
      var key = getTargetId(target) + ':' + prop;
      return descCache[key] || null;
    }

    // [C-SHD-05] Function.prototype.toString protection
    var nativeStrings = new Map();
    function storeNativeString(fn, str) {
      if (typeof fn === 'function') { nativeStrings.set(fn, str); }
    }

    // [C-SHD-12] Preserve function name/length
    function preserveFnProps(hooked, original) {
      try {
        realDefineProperty(hooked, 'length', { value: original.length, configurable: true });
        realDefineProperty(hooked, 'name', { value: original.name, configurable: true });
      } catch(e) {}
    }

    // ─── [C-SHD-01] hookFunction ───
    function hookFunction(target, prop, hookFn) {
      try {
        var original = target[prop];
        if (typeof original !== 'function') return false;
        var origStr = realToString.call(original);
        var hooked = function() {
          hookFn(this, arguments, prop);
          return original.apply(this, arguments);
        };
        preserveFnProps(hooked, original);
        storeNativeString(hooked, origStr);
        target[prop] = hooked;
        return true;
      } catch(e) { return false; }
    }

    // ─── [C-SHD-02] hookGetter ───
    function hookGetter(target, prop, hookFn, opts) {
      try {
        var desc = realGetOwnPropDesc.call(Object, target, prop);
        if (!desc) return false;
        cacheDescriptor(target, prop, desc);
        var origGetter = desc.get;
        if (!origGetter) return false;
        var origStr = realToString.call(origGetter);
        var newGetter = function() {
          var val = origGetter.call(this);
          hookFn(this, prop, val);
          return val;
        };
        storeNativeString(newGetter, origStr);
        var newDesc = { get: newGetter, set: desc.set, enumerable: desc.enumerable, configurable: desc.configurable };
        realDefineProperty(target, prop, newDesc);
        return true;
      } catch(e) { return false; }
    }

    // ─── [C-SHD-03] hookGetterSetter ───
    function hookGetterSetter(target, prop, getterHook, setterHook) {
      try {
        var desc = realGetOwnPropDesc.call(Object, target, prop);
        if (!desc) return false;
        cacheDescriptor(target, prop, desc);
        var origGetter = desc.get;
        var origSetter = desc.set;
        var newGetter = origGetter ? function() {
          var val = origGetter.call(this);
          if (getterHook) getterHook(this, prop, val);
          return val;
        } : desc.get;
        var newSetter = origSetter ? function(v) {
          if (setterHook) setterHook(this, prop, v);
          return origSetter.call(this, v);
        } : desc.set;
        if (origGetter) storeNativeString(newGetter, realToString.call(origGetter));
        if (origSetter) storeNativeString(newSetter, realToString.call(origSetter));
        realDefineProperty(target, prop, {
          get: newGetter, set: newSetter,
          enumerable: desc.enumerable, configurable: desc.configurable
        });
        return true;
      } catch(e) { return false; }
    }

    // ─── [C-SHD-05] toString override ───
    Function.prototype.toString = function() {
      var stored = nativeStrings.get(this);
      if (stored) return stored;
      return realToString.call(this);
    };
    storeNativeString(Function.prototype.toString, 'function toString() { [native code] }');

    // ─── [C-SHD-06] getOwnPropertyDescriptor override ───
    Object.getOwnPropertyDescriptor = function(target, prop) {
      var cached = getCachedDescriptor(target, prop);
      if (cached) return cached;
      return realGetOwnPropDesc.call(Object, target, prop);
    };
    storeNativeString(Object.getOwnPropertyDescriptor, 'function getOwnPropertyDescriptor() { [native code] }');

    // ─── [C-SHD-07] getOwnPropertyDescriptors override ───
    Object.getOwnPropertyDescriptors = function(target) {
      var result = realGetOwnPropDescs.call(Object, target);
      var props = realGetOwnPropNames.call(Object, target);
      for (var i = 0; i < props.length; i++) {
        var cached = getCachedDescriptor(target, props[i]);
        if (cached) result[props[i]] = cached;
      }
      return result;
    };
    storeNativeString(Object.getOwnPropertyDescriptors, 'function getOwnPropertyDescriptors() { [native code] }');

    // ─── [C-SHD-08] Error.prepareStackTrace cleanup ───
    if (typeof Error.prepareStackTrace !== 'undefined' || true) {
      var origPrepare = Error.prepareStackTrace;
      Error.prepareStackTrace = function(error, stack) {
        var filtered = [];
        for (var i = 0; i < stack.length; i++) {
          var fn = stack[i].getFileName() || '';
          if (fn.indexOf('sentinel') === -1 && fn.indexOf('playwright') === -1 &&
              fn.indexOf('pptr') === -1 && fn.indexOf('__puppeteer') === -1 &&
              fn.indexOf('addInitScript') === -1 &&
              fn.indexOf('patchright') === -1) {
            filtered.push(stack[i]);
          }
        }
        if (origPrepare) return origPrepare(error, filtered);
        return filtered;
      };
    }

    // ─── [C-SHD-09/10/11] Quiet Mode ───
    // Guard with random name
    realDefineProperty(window, '__SENTINEL_SHIELD_OK__', {
      value: true, writable: false, enumerable: false, configurable: false
    });

    // Export shield API (non-enumerable)
    var shieldAPI = { hookFunction: hookFunction, hookGetter: hookGetter, hookGetterSetter: hookGetterSetter };
    realDefineProperty(window, '__SENTINEL_SHIELD__', {
      value: shieldAPI, writable: false, enumerable: false, configurable: false
    });
  })();`;
}

module.exports = { generateShieldScript };
