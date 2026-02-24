/**
 * Sentinel v4.4 — Anti-Detection Shield (Layer 2)
 * 
 * CRITICAL FIX from v4.3:
 *   v4.3 exported a FUNCTION reference → toString() + IIFE wrapping caused
 *   the shield to run but window.__sentinelShield__ was set in wrong context.
 *   
 *   v4.4 returns a TEMPLATE STRING (like v4.1) that runs directly in page context.
 *   WeakMap descriptor cache from v4.3 is preserved (Bug #8 fix).
 * 
 * Architecture:
 *   - WeakMap-based target-qualified descriptor cache (v4.3 innovation)
 *   - Function.prototype.toString protection
 *   - Object.getOwnPropertyDescriptor(s) protection
 *   - Error.prepareStackTrace cleanup
 *   - Exports window.__SENTINEL_SHIELD__ for api-interceptor
 */

function getAntiDetectionScript() {
  return `
  (function() {
    'use strict';

    // Store real natives FIRST before anything can touch them
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
      if (!target || (typeof target !== 'object' && typeof target !== 'function')) {
        return 0;
      }
      var id = _targetIds.get(target);
      if (!id) {
        id = _nextTargetId++;
        _targetIds.set(target, id);
      }
      return id;
    }

    function cacheDescriptor(target, prop, descriptor) {
      var tid = getTargetId(target);
      var key = tid + ':' + prop;
      _descCache[key] = descriptor;
    }

    function getCachedDescriptor(target, prop) {
      var tid = getTargetId(target);
      var key = tid + ':' + prop;
      return _descCache[key] || null;
    }

    var _shield = {
      originals: _hookedFunctions,
      nativeStrings: _nativeStrings,

      /**
       * Hook a function on a target while preserving toString() and descriptor.
       * Combines v4.1's WeakMap toString protection + v4.3's descriptor cache.
       */
      hookFunction: function(target, prop, hookFn) {
        try {
          var original = target[prop];
          if (!original || typeof original !== 'function') return original;

          // Capture native toString BEFORE replacement
          var nativeStr;
          try { nativeStr = _realToString.call(original); } catch(e) { 
            nativeStr = 'function ' + prop + '() { [native code] }'; 
          }

          // Cache original descriptor BEFORE hooking
          var origDesc;
          try { origDesc = _realGetOwnPropDesc.call(Object, target, prop); } catch(e) {}
          if (origDesc) {
            cacheDescriptor(target, prop, origDesc);
          }

          // Create hooked wrapper
          var hooked = function() {
            var args = [];
            for (var i = 0; i < arguments.length; i++) args[i] = arguments[i];
            return hookFn.apply(this, [original].concat(args));
          };

          // Store mappings for toString + descriptor protection
          _hookedFunctions.set(hooked, original);
          _nativeStrings.set(hooked, nativeStr);

          // Preserve name and length
          try { _realDefineProperty(hooked, 'name', { value: original.name || prop, configurable: true }); } catch(e) {}
          try { _realDefineProperty(hooked, 'length', { value: original.length || 0, configurable: true }); } catch(e) {}
          if (original.prototype) { hooked.prototype = original.prototype; }

          target[prop] = hooked;
          return original;
        } catch(e) {
          return null;
        }
      },

      /**
       * Hook a getter on a prototype while preserving descriptor appearance.
       */
      hookGetter: function(target, prop, hookFn) {
        try {
          var desc = _realGetOwnPropDesc.call(Object, target, prop);
          if (!desc || !desc.get) return null;

          var originalGetter = desc.get;
          var nativeStr;
          try { nativeStr = _realToString.call(originalGetter); } catch(e) { 
            nativeStr = 'function get ' + prop + '() { [native code] }'; 
          }

          // Cache original descriptor
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
        } catch(e) {
          return null;
        }
      }
    };

    // ═══ Protect Function.prototype.toString ═══
    Function.prototype.toString = function() {
      var storedStr = _nativeStrings.get(this);
      if (storedStr) return storedStr;
      if (this === Function.prototype.toString) {
        return 'function toString() { [native code] }';
      }
      return _realToString.call(this);
    };
    _nativeStrings.set(Function.prototype.toString, 'function toString() { [native code] }');

    // ═══ Protect Object.getOwnPropertyDescriptor (singular) ═══
    Object.getOwnPropertyDescriptor = function(target, prop) {
      var cached = getCachedDescriptor(target, prop);
      if (cached) return cached;
      return _realGetOwnPropDesc.call(Object, target, prop);
    };
    _hookedFunctions.set(Object.getOwnPropertyDescriptor, _realGetOwnPropDesc);
    _nativeStrings.set(Object.getOwnPropertyDescriptor, 
      'function getOwnPropertyDescriptor() { [native code] }');

    // ═══ Protect Object.getOwnPropertyDescriptors (plural) ═══
    if (_realGetOwnPropDescs) {
      Object.getOwnPropertyDescriptors = function(target) {
        var result = _realGetOwnPropDescs.call(Object, target);
        var tid = getTargetId(target);
        if (tid > 0) {
          var propNames = Object.getOwnPropertyNames(result);
          for (var i = 0; i < propNames.length; i++) {
            var p = propNames[i];
            var cachedD = getCachedDescriptor(target, p);
            if (cachedD) {
              result[p] = cachedD;
            }
          }
        }
        return result;
      };
      _hookedFunctions.set(Object.getOwnPropertyDescriptors, _realGetOwnPropDescs);
      _nativeStrings.set(Object.getOwnPropertyDescriptors,
        'function getOwnPropertyDescriptors() { [native code] }');
    }

    // ═══ Protect Error.prepareStackTrace ═══
    try {
      var _origPrepare = Error.prepareStackTrace;
      _realDefineProperty(Error, 'prepareStackTrace', {
        configurable: true,
        enumerable: false,
        get: function() { return _origPrepare; },
        set: function(val) { _origPrepare = val; }
      });
    } catch (e) {}

    // ═══ Export shield for api-interceptor ═══
    window.__SENTINEL_SHIELD__ = _shield;
  })();
  `;
}

module.exports = { getAntiDetectionScript };
