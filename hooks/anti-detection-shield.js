/**
 * Sentinel v4 — Anti-Detection Shield (Layer 2)
 * Prevents CreepJS/bots from detecting our hooks
 * - toString spoofing
 * - Property descriptor traps
 * - Stack trace cleanup
 * - Prototype integrity preservation
 */

function getAntiDetectionScript() {
  return `
  (function() {
    'use strict';

    // ═══ ANTI-DETECTION SHIELD v4 ═══
    // This MUST run before any hooks are installed

    const _shield = {
      originals: new Map(),
      toStrings: new Map(),
      descriptorCache: new Map()
    };

    // Store the REAL native toString before anything touches it
    const _realFunctionToString = Function.prototype.toString;
    const _realObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
    const _realObjectKeys = Object.keys;
    const _realReflectOwnKeys = typeof Reflect !== 'undefined' ? Reflect.ownKeys : null;
    const _realObjectDefineProperty = Object.defineProperty;

    /**
     * Wrap a function with a hook while preserving its native toString() appearance.
     * This is the CORE of anti-detection: CreepJS checks toString to find lies.
     */
    window.__SENTINEL_SHIELD__ = {
      /**
       * Hook a function on a prototype, preserving toString and descriptors
       * @param {object} target - The prototype (e.g., HTMLCanvasElement.prototype)
       * @param {string} prop - Property name (e.g., 'toDataURL')
       * @param {function} hookFn - Function that receives (original, ...args) and returns result
       * @returns {function} The original function for direct calls
       */
      hookFunction: function(target, prop, hookFn) {
        const original = target[prop];
        if (!original || typeof original !== 'function') return original;

        const nativeStr = _realFunctionToString.call(original);
        _shield.originals.set(prop, original);
        _shield.toStrings.set(prop, nativeStr);

        // Cache original descriptor
        const origDesc = _realObjectGetOwnPropertyDescriptor(target, prop);
        if (origDesc) _shield.descriptorCache.set(target.toString() + '.' + prop, origDesc);

        const hooked = function(...args) {
          return hookFn.call(this, original, ...args);
        };

        // Make toString return the native string
        hooked.toString = function() { return nativeStr; };
        hooked.toLocaleString = function() { return nativeStr; };

        // Preserve function name and length
        _realObjectDefineProperty(hooked, 'name', { value: original.name, configurable: true });
        _realObjectDefineProperty(hooked, 'length', { value: original.length, configurable: true });

        // Copy prototype if exists
        if (original.prototype) {
          hooked.prototype = original.prototype;
        }

        target[prop] = hooked;
        return original;
      },

      /**
       * Hook a getter on a prototype while preserving descriptor appearance
       */
      hookGetter: function(target, prop, hookFn) {
        const desc = _realObjectGetOwnPropertyDescriptor(target, prop);
        if (!desc || !desc.get) return null;

        const originalGetter = desc.get;
        const nativeStr = _realFunctionToString.call(originalGetter);
        _shield.originals.set('get_' + prop, originalGetter);
        _shield.toStrings.set('get_' + prop, nativeStr);

        const hookedGetter = function() {
          return hookFn.call(this, originalGetter);
        };

        hookedGetter.toString = function() { return nativeStr; };
        _realObjectDefineProperty(hookedGetter, 'name', { value: 'get ' + prop, configurable: true });

        const newDesc = {
          get: hookedGetter,
          set: desc.set,
          enumerable: desc.enumerable,
          configurable: true
        };

        _realObjectDefineProperty(target, prop, newDesc);
        return originalGetter;
      },

      /**
       * Hook a setter on a prototype
       */
      hookSetter: function(target, prop, hookFn) {
        const desc = _realObjectGetOwnPropertyDescriptor(target, prop);
        if (!desc || !desc.set) return null;

        const originalSetter = desc.set;
        const nativeStr = _realFunctionToString.call(originalSetter);

        const hookedSetter = function(val) {
          return hookFn.call(this, originalSetter, val);
        };

        hookedSetter.toString = function() { return nativeStr; };

        _realObjectDefineProperty(target, prop, {
          get: desc.get,
          set: hookedSetter,
          enumerable: desc.enumerable,
          configurable: true
        });

        return originalSetter;
      },

      getOriginal: function(name) {
        return _shield.originals.get(name);
      }
    };

    // ═══ Protect Function.prototype.toString itself ═══
    // CreepJS explicitly checks if toString has been tampered with
    const _origToString = Function.prototype.toString;
    Function.prototype.toString = function() {
      // If this function has a stored native string, return it
      const storedStr = _shield.toStrings.get(this.name);
      if (storedStr) return storedStr;

      // For our own toString hook, return the native appearance
      if (this === Function.prototype.toString) {
        return 'function toString() { [native code] }';
      }

      return _realFunctionToString.call(this);
    };
    // Make our toString look native too
    _realObjectDefineProperty(Function.prototype.toString, 'name', { value: 'toString', configurable: true });
    _realObjectDefineProperty(Function.prototype.toString, 'length', { value: 0, configurable: true });

    // ═══ Protect Object.getOwnPropertyDescriptor ═══
    // CreepJS uses this to detect modified descriptors
    const _origGetDesc = Object.getOwnPropertyDescriptor;
    Object.getOwnPropertyDescriptor = function(obj, prop) {
      const cacheKey = (obj && obj.toString ? obj.toString() : '') + '.' + prop;
      const cached = _shield.descriptorCache.get(cacheKey);
      if (cached) return cached;
      return _origGetDesc.call(Object, obj, prop);
    };
    Object.getOwnPropertyDescriptor.toString = function() {
      return 'function getOwnPropertyDescriptor() { [native code] }';
    };

    // ═══ Protect Object.getOwnPropertyDescriptors ═══
    if (Object.getOwnPropertyDescriptors) {
      const _origGetDescs = Object.getOwnPropertyDescriptors;
      Object.getOwnPropertyDescriptors = function(obj) {
        return _origGetDescs.call(Object, obj);
      };
      Object.getOwnPropertyDescriptors.toString = function() {
        return 'function getOwnPropertyDescriptors() { [native code] }';
      };
    }

    // ═══ Stack Trace Cleanup ═══
    // Remove Sentinel/Playwright/Puppeteer frames from Error stacks
    const _origErrorPrepare = Error.prepareStackTrace;
    Error.prepareStackTrace = function(error, structuredStack) {
      const filtered = structuredStack.filter(frame => {
        const fileName = frame.getFileName() || '';
        const funcName = frame.getFunctionName() || '';
        return !fileName.includes('sentinel') &&
               !fileName.includes('puppeteer') &&
               !fileName.includes('playwright') &&
               !fileName.includes('pptr:') &&
               !fileName.includes('__puppeteer') &&
               !fileName.includes('__playwright') &&
               !funcName.includes('__SENTINEL') &&
               !funcName.includes('hookFn');
      });
      if (_origErrorPrepare) {
        return _origErrorPrepare(error, filtered);
      }
      return error.toString() + '\n' + filtered.map(f => '    at ' + f.toString()).join('\n');
    };
    Error.prepareStackTrace.toString = function() {
      return _realFunctionToString.call(_origErrorPrepare || function(){});
    };

    console.log('[Sentinel v4 Shield] Anti-detection layer active');
  })();
  `;
}

module.exports = { getAntiDetectionScript };
