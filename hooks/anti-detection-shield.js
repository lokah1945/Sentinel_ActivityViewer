/**
 * Sentinel v4.3 — Anti-Detection Shield
 * CRITICAL FIX: WeakMap-based target-qualified descriptor cache
 * 
 * Bug #8 (v4.2.1): Used _descCache["" + prop] as key — returned wrong
 * descriptors for ANY object, breaking Vue 3/Nuxt 3 reactivity.
 * 
 * Fix: WeakMap assigns unique numeric ID per target object.
 * Cache key = targetId + ":" + prop — descriptors only returned for
 * the exact target+property combination that was hooked.
 * 
 * Also restores:
 * - Error.prepareStackTrace cleanup (removed in v4.2.1)
 * - Object.getOwnPropertyDescriptors (plural) protection (removed in v4.2.1)
 */

function getAntiDetectionShield() {
  return function antiDetectionShield() {
    // ── Target-Qualified Descriptor Cache ──
    var _targetIds = new WeakMap();
    var _nextTargetId = 1;
    var _descCache = {};
    var _hookedFunctions = new WeakMap();

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

    // ── Hook Function (make hooked functions look native) ──
    function hookFunction(target, prop, hookedFn, originalFn) {
      // Store original descriptor BEFORE hooking
      var origDescriptor;
      try {
        origDescriptor = Object.getOwnPropertyDescriptor(target, prop);
      } catch (e) {
        origDescriptor = null;
      }
      if (origDescriptor) {
        cacheDescriptor(target, prop, origDescriptor);
      }

      // Make hooked function look like the original
      try {
        Object.defineProperty(hookedFn, 'name', {
          value: originalFn.name || prop,
          configurable: true
        });
        Object.defineProperty(hookedFn, 'length', {
          value: originalFn.length || 0,
          configurable: true
        });
      } catch (e) { /* some properties may not be configurable */ }

      // Mark as hooked
      _hookedFunctions.set(hookedFn, originalFn);

      return hookedFn;
    }

    // ── Protect toString ──
    var _origToString = Function.prototype.toString;
    var _toStringHooked = false;

    function protectToString() {
      if (_toStringHooked) return;
      _toStringHooked = true;

      Function.prototype.toString = function() {
        var original = _hookedFunctions.get(this);
        if (original) {
          return _origToString.call(original);
        }
        return _origToString.call(this);
      };

      // Protect toString itself
      _hookedFunctions.set(Function.prototype.toString, _origToString);
    }

    // ── Protect Object.getOwnPropertyDescriptor (singular) ──
    var _origGetOwnPropDesc = Object.getOwnPropertyDescriptor;

    function protectGetOwnPropertyDescriptor() {
      Object.getOwnPropertyDescriptor = function(target, prop) {
        // Check if we have a cached original descriptor for THIS specific target+prop
        var cached = getCachedDescriptor(target, prop);
        if (cached) {
          return cached;
        }
        // Otherwise call original
        return _origGetOwnPropDesc.call(Object, target, prop);
      };
      _hookedFunctions.set(Object.getOwnPropertyDescriptor, _origGetOwnPropDesc);
    }

    // ── Protect Object.getOwnPropertyDescriptors (plural) ──
    var _origGetOwnPropDescs = Object.getOwnPropertyDescriptors;

    function protectGetOwnPropertyDescriptors() {
      if (!_origGetOwnPropDescs) return;
      Object.getOwnPropertyDescriptors = function(target) {
        var result = _origGetOwnPropDescs.call(Object, target);
        // Replace any hooked descriptors with cached originals
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
      _hookedFunctions.set(Object.getOwnPropertyDescriptors, _origGetOwnPropDescs);
    }

    // ── Protect Error.prepareStackTrace ──
    function protectStackTrace() {
      try {
        var _origPrepare = Error.prepareStackTrace;
        Object.defineProperty(Error, 'prepareStackTrace', {
          configurable: true,
          enumerable: false,
          get: function() { return _origPrepare; },
          set: function(val) { _origPrepare = val; }
        });
      } catch (e) { /* not available in all environments */ }
    }

    // ── Initialize All Protections ──
    protectToString();
    protectGetOwnPropertyDescriptor();
    protectGetOwnPropertyDescriptors();
    protectStackTrace();

    // Expose hookFunction for api-interceptor to use
    if (typeof window !== 'undefined') {
      window.__sentinelShield__ = {
        hookFunction: hookFunction,
        protectToString: protectToString
      };
    }
  };
}

module.exports = { getAntiDetectionShield };
