/**
 * Sentinel v4.1 — Anti-Detection Shield (Layer 2)
 * FIXED: v4.0 shield crashed the entire injection pipeline because:
 *   1) Object.getOwnPropertyDescriptor override used target.toString() as cache key
 *      which throws on some prototypes after toString is overridden
 *   2) Error.prepareStackTrace override could crash before V8 init
 *   3) Function.prototype.toString override broke hookGetter descriptor lookups
 *
 * v4.1 approach: Minimal, safe shield that only protects toString on hooked functions.
 * Does NOT override Object.getOwnPropertyDescriptor or Error.prepareStackTrace globally.
 */

function getAntiDetectionScript() {
  return `
  (function() {
    'use strict';

    // Store real natives FIRST before anything can touch them
    const _realToString = Function.prototype.toString;
    const _realDefineProperty = Object.defineProperty;
    const _realGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;

    const _shield = {
      originals: new WeakMap(),    // hooked fn -> original fn
      nativeStrings: new WeakMap() // hooked fn -> native toString string
    };

    /**
     * Hook a function on a prototype while preserving its toString() appearance.
     * Uses WeakMap keyed on function references (no string keys, no crash risk).
     */
    _shield.hookFunction = function(target, prop, hookFn) {
      try {
        const original = target[prop];
        if (!original || typeof original !== 'function') return original;

        // Capture native toString BEFORE we replace anything
        let nativeStr;
        try { nativeStr = _realToString.call(original); } catch(e) { nativeStr = 'function ' + prop + '() { [native code] }'; }

        const hooked = function() {
          return hookFn.call(this, original, ...arguments);
        };

        // Store mapping for toString protection
        _shield.originals.set(hooked, original);
        _shield.nativeStrings.set(hooked, nativeStr);

        // Preserve name and length
        try { _realDefineProperty(hooked, 'name', { value: original.name, configurable: true }); } catch(e) {}
        try { _realDefineProperty(hooked, 'length', { value: original.length, configurable: true }); } catch(e) {}
        if (original.prototype) { hooked.prototype = original.prototype; }

        target[prop] = hooked;
        return original;
      } catch(e) {
        // If hooking fails, return silently — don't crash the pipeline
        return null;
      }
    };

    /**
     * Hook a getter on a prototype while preserving descriptor appearance.
     */
    _shield.hookGetter = function(target, prop, hookFn) {
      try {
        const desc = _realGetOwnPropertyDescriptor.call(Object, target, prop);
        if (!desc || !desc.get) return null;

        const originalGetter = desc.get;
        let nativeStr;
        try { nativeStr = _realToString.call(originalGetter); } catch(e) { nativeStr = 'function get ' + prop + '() { [native code] }'; }

        const hookedGetter = function() {
          return hookFn.call(this, originalGetter);
        };

        _shield.originals.set(hookedGetter, originalGetter);
        _shield.nativeStrings.set(hookedGetter, nativeStr);

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
    };

    // ═══ Protect Function.prototype.toString ═══
    // Only intercept toString for functions WE hooked (via WeakMap lookup)
    Function.prototype.toString = function() {
      // Check if this is one of our hooked functions
      const storedStr = _shield.nativeStrings.get(this);
      if (storedStr) return storedStr;

      // For toString itself, return native appearance
      if (this === Function.prototype.toString) {
        return 'function toString() { [native code] }';
      }

      // Everything else: call the real toString
      return _realToString.call(this);
    };

    // Make our toString look native
    _shield.nativeStrings.set(Function.prototype.toString, 'function toString() { [native code] }');

    // Export shield for api-interceptor to use
    window.__SENTINEL_SHIELD__ = _shield;
  })();
  `;
}

module.exports = { getAntiDetectionScript };
