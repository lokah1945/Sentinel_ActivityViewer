/**
 * Sentinel v4.4.1 — Anti-Detection Shield (Layer 2)
 * 
 * Preserves WeakMap descriptor cache from v4.3.
 * Exports as TEMPLATE STRING (not function reference) for correct MAIN world execution.
 * 
 * Provides:
 *   - window.__SENTINEL_SHIELD__ with hookFunction() and hookGetter()
 *   - Function.prototype.toString protection
 *   - Object.getOwnPropertyDescriptor(s) protection
 *   - Error.prepareStackTrace cleanup
 */

function getAntiDetectionScript() {
  return `
  (function() {
    'use strict';

    var _realToString = Function.prototype.toString;
    var _realDefineProperty = Object.defineProperty;
    var _realGetOwnPropDesc = Object.getOwnPropertyDescriptor;
    var _realGetOwnPropDescs = Object.getOwnPropertyDescriptors;

    // ── Target-Qualified Descriptor Cache (WeakMap, from v4.3) ──
    var _targetIds = new WeakMap();
    var _nextTargetId = 1;
    var _descCache = {};
    var _hookedFunctions = new WeakMap();
    var _nativeStrings = new WeakMap();

    function getTargetId(target) {
      if (!target || (typeof target !== 'object' && typeof target !== 'function')) return 0;
      var id = _targetIds.get(target);
      if (!id) { id = _nextTargetId++; _targetIds.set(target, id); }
      return id;
    }

    function cacheDescriptor(target, prop, descriptor) {
      var tid = getTargetId(target);
      _descCache[tid + ':' + prop] = descriptor;
    }

    function getCachedDescriptor(target, prop) {
      var tid = getTargetId(target);
      return _descCache[tid + ':' + prop] || null;
    }

    var _shield = {
      originals: _hookedFunctions,
      nativeStrings: _nativeStrings,

      hookFunction: function(target, prop, hookFn) {
        try {
          var original = target[prop];
          if (!original || typeof original !== 'function') return original;
          var nativeStr;
          try { nativeStr = _realToString.call(original); } catch(e) { 
            nativeStr = 'function ' + prop + '() { [native code] }'; 
          }
          var origDesc;
          try { origDesc = _realGetOwnPropDesc.call(Object, target, prop); } catch(e) {}
          if (origDesc) cacheDescriptor(target, prop, origDesc);

          var hooked = function() {
            var args = [];
            for (var i = 0; i < arguments.length; i++) args[i] = arguments[i];
            return hookFn.apply(this, [original].concat(args));
          };
          _hookedFunctions.set(hooked, original);
          _nativeStrings.set(hooked, nativeStr);
          try { _realDefineProperty(hooked, 'name', { value: original.name || prop, configurable: true }); } catch(e) {}
          try { _realDefineProperty(hooked, 'length', { value: original.length || 0, configurable: true }); } catch(e) {}
          if (original.prototype) hooked.prototype = original.prototype;
          target[prop] = hooked;
          return original;
        } catch(e) { return null; }
      },

      hookGetter: function(target, prop, hookFn) {
        try {
          var desc = _realGetOwnPropDesc.call(Object, target, prop);
          if (!desc || !desc.get) return null;
          var originalGetter = desc.get;
          var nativeStr;
          try { nativeStr = _realToString.call(originalGetter); } catch(e) { 
            nativeStr = 'function get ' + prop + '() { [native code] }'; 
          }
          cacheDescriptor(target, prop, desc);
          var hookedGetter = function() {
            return hookFn.call(this, originalGetter);
          };
          _hookedFunctions.set(hookedGetter, originalGetter);
          _nativeStrings.set(hookedGetter, nativeStr);
          try { _realDefineProperty(hookedGetter, 'name', { value: 'get ' + prop, configurable: true }); } catch(e) {}
          _realDefineProperty.call(Object, target, prop, {
            get: hookedGetter,
            set: desc.set,
            enumerable: desc.enumerable,
            configurable: true
          });
          return originalGetter;
        } catch(e) { return null; }
      },

      hookGetterSetter: function(target, prop, getterHook, setterHook) {
        try {
          var desc = _realGetOwnPropDesc.call(Object, target, prop);
          if (!desc) return null;
          cacheDescriptor(target, prop, desc);
          var newDesc = { enumerable: desc.enumerable, configurable: true };

          if (desc.get) {
            var origGet = desc.get;
            var hookedGet = function() { return getterHook.call(this, origGet); };
            var nativeGetStr;
            try { nativeGetStr = _realToString.call(origGet); } catch(e) { nativeGetStr = 'function get ' + prop + '() { [native code] }'; }
            _hookedFunctions.set(hookedGet, origGet);
            _nativeStrings.set(hookedGet, nativeGetStr);
            newDesc.get = hookedGet;
          }
          if (desc.set && setterHook) {
            var origSet = desc.set;
            var hookedSet = function(v) { return setterHook.call(this, origSet, v); };
            var nativeSetStr;
            try { nativeSetStr = _realToString.call(origSet); } catch(e) { nativeSetStr = 'function set ' + prop + '() { [native code] }'; }
            _hookedFunctions.set(hookedSet, origSet);
            _nativeStrings.set(hookedSet, nativeSetStr);
            newDesc.set = hookedSet;
          } else if (desc.set) {
            newDesc.set = desc.set;
          }

          _realDefineProperty.call(Object, target, prop, newDesc);
          return desc;
        } catch(e) { return null; }
      }
    };

    // ═══ Protect Function.prototype.toString ═══
    Function.prototype.toString = function() {
      var storedStr = _nativeStrings.get(this);
      if (storedStr) return storedStr;
      if (this === Function.prototype.toString) return 'function toString() { [native code] }';
      return _realToString.call(this);
    };
    _nativeStrings.set(Function.prototype.toString, 'function toString() { [native code] }');

    // ═══ Protect Object.getOwnPropertyDescriptor ═══
    Object.getOwnPropertyDescriptor = function(target, prop) {
      var cached = getCachedDescriptor(target, prop);
      if (cached) return cached;
      return _realGetOwnPropDesc.call(Object, target, prop);
    };
    _hookedFunctions.set(Object.getOwnPropertyDescriptor, _realGetOwnPropDesc);
    _nativeStrings.set(Object.getOwnPropertyDescriptor, 'function getOwnPropertyDescriptor() { [native code] }');

    if (_realGetOwnPropDescs) {
      Object.getOwnPropertyDescriptors = function(target) {
        var result = _realGetOwnPropDescs.call(Object, target);
        var tid = getTargetId(target);
        if (tid > 0) {
          var propNames = Object.getOwnPropertyNames(result);
          for (var i = 0; i < propNames.length; i++) {
            var p = propNames[i];
            var cachedD = getCachedDescriptor(target, p);
            if (cachedD) result[p] = cachedD;
          }
        }
        return result;
      };
      _hookedFunctions.set(Object.getOwnPropertyDescriptors, _realGetOwnPropDescs);
      _nativeStrings.set(Object.getOwnPropertyDescriptors, 'function getOwnPropertyDescriptors() { [native code] }');
    }

    // ═══ Protect Error.prepareStackTrace ═══
    try {
      var _origPrepare = Error.prepareStackTrace;
      _realDefineProperty(Error, 'prepareStackTrace', {
        configurable: true, enumerable: false,
        get: function() { return _origPrepare; },
        set: function(val) { _origPrepare = val; }
      });
    } catch (e) {}

    window.__SENTINEL_SHIELD__ = _shield;
  })();
  `;
}

module.exports = { getAntiDetectionScript };
