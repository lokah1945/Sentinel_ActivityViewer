/**
 * Sentinel v4.2.1 — Anti-Detection Shield (Layer 2)
 * Zero Escape Architecture — Prevents ALL detection of hooks
 *
 * FIXES from v4.2.0:
 * - Removed spread syntax for broader compatibility
 * - Uses arguments/Array.prototype.slice pattern
 * - Proper toString masking for all hooked functions
 */

function getAntiDetectionScript() {
  return '(function() {\n' +
    '"use strict";\n' +
    'if (window.__SENTINEL_ACTIVE__) return;\n' +
    'window.__SENTINEL_ACTIVE__ = true;\n' +
    '\n' +
    'var _origMap = new WeakMap();\n' +
    'var _nameMap = {};\n' +
    'var _descCache = {};\n' +
    '\n' +
    'var _realToString = Function.prototype.toString;\n' +
    'var _realGetDesc = Object.getOwnPropertyDescriptor;\n' +
    'var _realDefProp = Object.defineProperty;\n' +
    '\n' +
    'window.__REAL_GET_DESC__ = _realGetDesc;\n' +
    'window.__REAL_DEF_PROP__ = _realDefProp;\n' +
    '\n' +
    'window.__SENTINEL_SHIELD__ = {\n' +
    '  hookFunction: function(target, prop, hookFn) {\n' +
    '    var original = target[prop];\n' +
    '    if (!original || typeof original !== "function") return original;\n' +
    '    var nativeStr = _realToString.call(original);\n' +
    '    _nameMap[prop] = nativeStr;\n' +
    '    var origDesc = _realGetDesc(target, prop);\n' +
    '    if (origDesc) { _descCache["" + prop] = origDesc; }\n' +
    '    var hooked = function() {\n' +
    '      var args = Array.prototype.slice.call(arguments);\n' +
    '      return hookFn.apply(this, [original].concat(args));\n' +
    '    };\n' +
    '    _origMap.set(hooked, { nativeStr: nativeStr, original: original });\n' +
    '    hooked.toString = function() { return nativeStr; };\n' +
    '    hooked.toLocaleString = function() { return nativeStr; };\n' +
    '    try { _realDefProp(hooked, "name", { value: original.name, configurable: true }); } catch(e) {}\n' +
    '    try { _realDefProp(hooked, "length", { value: original.length, configurable: true }); } catch(e) {}\n' +
    '    if (original.prototype) { hooked.prototype = original.prototype; }\n' +
    '    target[prop] = hooked;\n' +
    '    return original;\n' +
    '  },\n' +
    '  hookGetter: function(target, prop, hookFn) {\n' +
    '    var desc = _realGetDesc(target, prop);\n' +
    '    if (!desc || !desc.get) return null;\n' +
    '    var originalGetter = desc.get;\n' +
    '    var nativeStr = _realToString.call(originalGetter);\n' +
    '    _nameMap["get_" + prop] = nativeStr;\n' +
    '    var hookedGetter = function() {\n' +
    '      return hookFn.call(this, originalGetter);\n' +
    '    };\n' +
    '    _origMap.set(hookedGetter, { nativeStr: nativeStr, original: originalGetter });\n' +
    '    hookedGetter.toString = function() { return nativeStr; };\n' +
    '    try { _realDefProp(hookedGetter, "name", { value: "get " + prop, configurable: true }); } catch(e) {}\n' +
    '    _realDefProp(target, prop, {\n' +
    '      get: hookedGetter,\n' +
    '      set: desc.set,\n' +
    '      enumerable: desc.enumerable,\n' +
    '      configurable: true\n' +
    '    });\n' +
    '    return originalGetter;\n' +
    '  },\n' +
    '  hookSetter: function(target, prop, hookFn) {\n' +
    '    var desc = _realGetDesc(target, prop);\n' +
    '    if (!desc || !desc.set) return null;\n' +
    '    var originalSetter = desc.set;\n' +
    '    var nativeStr = _realToString.call(originalSetter);\n' +
    '    var hookedSetter = function(val) {\n' +
    '      return hookFn.call(this, originalSetter, val);\n' +
    '    };\n' +
    '    _origMap.set(hookedSetter, { nativeStr: nativeStr, original: originalSetter });\n' +
    '    hookedSetter.toString = function() { return nativeStr; };\n' +
    '    _realDefProp(target, prop, {\n' +
    '      get: desc.get,\n' +
    '      set: hookedSetter,\n' +
    '      enumerable: desc.enumerable,\n' +
    '      configurable: true\n' +
    '    });\n' +
    '    return originalSetter;\n' +
    '  }\n' +
    '};\n' +
    '\n' +
    'Function.prototype.toString = function() {\n' +
    '  var info = _origMap.get(this);\n' +
    '  if (info) return info.nativeStr;\n' +
    '  if (this.name && _nameMap[this.name]) return _nameMap[this.name];\n' +
    '  if (this === Function.prototype.toString) return "function toString() { [native code] }";\n' +
    '  return _realToString.call(this);\n' +
    '};\n' +
    'try { _realDefProp(Function.prototype.toString, "name", { value: "toString", configurable: true }); } catch(e) {}\n' +
    'try { _realDefProp(Function.prototype.toString, "length", { value: 0, configurable: true }); } catch(e) {}\n' +
    '\n' +
    'Object.getOwnPropertyDescriptor = function(obj, prop) {\n' +
    '  var cached = _descCache["" + prop];\n' +
    '  if (cached) return cached;\n' +
    '  return _realGetDesc.call(Object, obj, prop);\n' +
    '};\n' +
    'Object.getOwnPropertyDescriptor.toString = function() { return "function getOwnPropertyDescriptor() { [native code] }"; };\n' +
    '\n' +
    'window.__SENTINEL_L1__ = false;\n' +
    'window.__SENTINEL_L2__ = false;\n' +
    'window.__SENTINEL_L3__ = false;\n' +
    '\n' +
    '})();';
}

module.exports = { getAntiDetectionScript };
