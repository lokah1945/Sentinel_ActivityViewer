// Sentinel v4.4.2 — Anti-Detection Shield (Layer 2)
// WeakMap descriptor cache + toString + stack cleanup + hookGetterSetter

function getAntiDetectionScript() {
  return `
(function() {
  'use strict';
  if (window.__SENTINEL_SHIELD) return;

  var realGetOwnPropDesc = Object.getOwnPropertyDescriptor;
  var realDefineProperty = Object.defineProperty;
  var realToString = Function.prototype.toString;
  var realKeys = Object.keys;
  var realGetOwnPropNames = Object.getOwnPropertyNames;
  var realGetOwnPropDescs = Object.getOwnPropertyDescriptors;

  // WeakMap-based target-qualified descriptor cache
  var targetIds = new WeakMap();
  var nextTargetId = 1;
  var descCache = {};
  var toStringCache = new WeakMap();

  function getTargetId(target) {
    if (!target || typeof target !== 'object' && typeof target !== 'function') return 0;
    var id = targetIds.get(target);
    if (!id) { id = nextTargetId++; targetIds.set(target, id); }
    return id;
  }

  function cacheDescriptor(target, prop, desc) {
    var key = getTargetId(target) + ':' + prop;
    if (!descCache[key] && desc) { descCache[key] = desc; }
  }

  function getCachedDescriptor(target, prop) {
    var key = getTargetId(target) + ':' + prop;
    return descCache[key] || null;
  }

  // hookFunction: wrap a prototype method with toString protection
  function hookFunction(target, prop, hookFn) {
    try {
      var orig = target[prop];
      if (typeof orig !== 'function') return false;
      var origDesc = realGetOwnPropDesc.call(Object, target, prop);
      cacheDescriptor(target, prop, origDesc);
      var origStr = realToString.call(orig);
      var wrapped = function() {
        return hookFn.call(this, orig, arguments);
      };
      try { realDefineProperty(wrapped, 'name', { value: orig.name }); } catch(e) {}
      try { realDefineProperty(wrapped, 'length', { value: orig.length }); } catch(e) {}
      toStringCache.set(wrapped, origStr);
      target[prop] = wrapped;
      return true;
    } catch(e) { return false; }
  }

  // hookGetter: wrap a property getter with toString protection
  function hookGetter(target, prop, hookFn) {
    try {
      var desc = realGetOwnPropDesc.call(Object, target, prop);
      if (!desc) return false;
      cacheDescriptor(target, prop, desc);
      var origGetter = desc.get;
      if (!origGetter && desc.value !== undefined) return false;
      if (!origGetter) return false;
      var origStr = '';
      try { origStr = realToString.call(origGetter); } catch(e) { origStr = 'function ' + prop + '() { [native code] }'; }
      var newGetter = function() {
        return hookFn.call(this, origGetter);
      };
      toStringCache.set(newGetter, origStr);
      var newDesc = { get: newGetter, configurable: true, enumerable: desc.enumerable };
      if (desc.set) newDesc.set = desc.set;
      realDefineProperty(target, prop, newDesc);
      return true;
    } catch(e) { return false; }
  }

  // hookGetterSetter: wrap getter AND setter simultaneously
  function hookGetterSetter(target, prop, getterHook, setterHook) {
    try {
      var desc = realGetOwnPropDesc.call(Object, target, prop);
      if (!desc) return false;
      cacheDescriptor(target, prop, desc);
      var origGetter = desc.get;
      var origSetter = desc.set;
      var newDesc = { configurable: true, enumerable: desc.enumerable };
      if (origGetter && getterHook) {
        var origGetStr = '';
        try { origGetStr = realToString.call(origGetter); } catch(e) { origGetStr = 'function get ' + prop + '() { [native code] }'; }
        var newGetter = function() { return getterHook.call(this, origGetter); };
        toStringCache.set(newGetter, origGetStr);
        newDesc.get = newGetter;
      } else if (origGetter) {
        newDesc.get = origGetter;
      }
      if (origSetter && setterHook) {
        var origSetStr = '';
        try { origSetStr = realToString.call(origSetter); } catch(e) { origSetStr = 'function set ' + prop + '() { [native code] }'; }
        var newSetter = function(v) { return setterHook.call(this, origSetter, v); };
        toStringCache.set(newSetter, origSetStr);
        newDesc.set = newSetter;
      } else if (origSetter) {
        newDesc.set = origSetter;
      }
      realDefineProperty(target, prop, newDesc);
      return true;
    } catch(e) { return false; }
  }

  // Protect Function.prototype.toString
  var origToString = Function.prototype.toString;
  Function.prototype.toString = function() {
    var cached = toStringCache.get(this);
    if (cached) return cached;
    return origToString.call(this);
  };
  toStringCache.set(Function.prototype.toString, realToString.call(origToString));

  // Protect Object.getOwnPropertyDescriptor (singular)
  Object.getOwnPropertyDescriptor = function(target, prop) {
    var cached = getCachedDescriptor(target, prop);
    if (cached) return cached;
    return realGetOwnPropDesc.call(Object, target, prop);
  };
  toStringCache.set(Object.getOwnPropertyDescriptor,
    realToString.call(realGetOwnPropDesc));

  // Protect Object.getOwnPropertyDescriptors (plural)
  if (typeof realGetOwnPropDescs === 'function') {
    Object.getOwnPropertyDescriptors = function(target) {
      var result = realGetOwnPropDescs.call(Object, target);
      if (target && typeof target === 'object') {
        var props = realGetOwnPropNames.call(Object, target);
        for (var i = 0; i < props.length; i++) {
          var cached = getCachedDescriptor(target, props[i]);
          if (cached) result[props[i]] = cached;
        }
      }
      return result;
    };
    toStringCache.set(Object.getOwnPropertyDescriptors,
      realToString.call(realGetOwnPropDescs));
  }

  // Clean Error.prepareStackTrace to remove automation traces
  if (typeof Error.prepareStackTrace === 'undefined' || true) {
    var origPrepare = Error.prepareStackTrace;
    Error.prepareStackTrace = function(error, stack) {
      var cleaned = [];
      for (var i = 0; i < stack.length; i++) {
        var fn = '';
        try { fn = stack[i].getFileName() || ''; } catch(e) {}
        var fnLower = fn.toLowerCase();
        if (fnLower.indexOf('sentinel') === -1 &&
            fnLower.indexOf('puppeteer') === -1 &&
            fnLower.indexOf('playwright') === -1 &&
            fnLower.indexOf('pptr') === -1 &&
            fnLower.indexOf('__playwright') === -1) {
          cleaned.push(stack[i]);
        }
      }
      if (origPrepare) return origPrepare(error, cleaned);
      return error + '\\n' + cleaned.map(function(f) {
        return '    at ' + f.toString();
      }).join('\\n');
    };
  }

  window.__SENTINEL_SHIELD = {
    hookFunction: hookFunction,
    hookGetter: hookGetter,
    hookGetterSetter: hookGetterSetter
  };
})();
`;
}

module.exports = { getAntiDetectionScript };
