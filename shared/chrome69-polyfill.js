/*
 * Polyfill service v3.111.0
 * Disable minification (remove `.min` from URL path) for more info
*/

try {
    (function(self, undefined) {Object.defineProperty(Symbol,"matchAll",{value:Symbol("matchAll")});function AdvanceStringIndex(e,n,t){if(n>Number.MAX_SAFE_INTEGER)throw new TypeError("Assertion failed: `index` must be <= 2**53");return!1===t?n+1:n+1>=e.length?n+1:n+e.codePointAt(n).length}function Call(t,l){var n=arguments.length>2?arguments[2]:[];if(!1===IsCallable(t))throw new TypeError(Object.prototype.toString.call(t)+"is not a function.");return t.apply(l,n)}function CreateDataProperty(e,r,t){var a={value:t,writable:!0,enumerable:!0,configurable:!0};try{return Object.defineProperty(e,r,a),!0}catch(n){return!1}}function CreateDataPropertyOrThrow(t,r,o){var e=CreateDataProperty(t,r,o);if(!e)throw new TypeError("Cannot assign value `"+Object.prototype.toString.call(o)+"` to property `"+Object.prototype.toString.call(r)+"` on object `"+Object.prototype.toString.call(t)+"`");return e}function CreateMethodProperty(e,r,t){var a={value:t,writable:!0,enumerable:!1,configurable:!0};Object.defineProperty(e,r,a)}function Get(n,t){return n[t]}function IsCallable(n){return"function"==typeof n}function RequireObjectCoercible(e){if(null===e||e===undefined)throw TypeError(Object.prototype.toString.call(e)+" is not coercible to Object.");return e}function ToBoolean(o){return Boolean(o)}function ToNumber(r){return Number(r)}function ToIntegerOrInfinity(n){var i=ToNumber(n);if(isNaN(i)||0===i||1/i==-Infinity)return 0;if(i===Infinity)return Infinity;if(i===-Infinity)return-Infinity;var r=Math.floor(Math.abs(i));return i<0&&(r=-r),r}function ToObject(e){if(null===e||e===undefined)throw TypeError();return Object(e)}function GetV(t,e){return ToObject(t)[e]}function GetMethod(e,n){var r=GetV(e,n);if(null===r||r===undefined)return undefined;if(!1===IsCallable(r))throw new TypeError("Method not callable: "+n);return r}function Invoke(n,e){var t=arguments.length>2?arguments[2]:[],l=GetV(n,e);return Call(l,n,t)}function Type(e){switch(typeof e){case"undefined":return"undefined";case"boolean":return"boolean";case"number":return"number";case"string":return"string";case"symbol":return"symbol";default:return null===e?"null":"Symbol"in self&&(e instanceof self.Symbol||e.constructor===self.Symbol)?"symbol":"object"}}function CreateIterResultObject(e,r){if("boolean"!==Type(r))throw new Error;var t={};return CreateDataProperty(t,"value",e),CreateDataProperty(t,"done",r),t}function GetIterator(t){var e=arguments.length>1?arguments[1]:GetMethod(t,Symbol.iterator),r=Call(e,t);if("object"!==Type(r))throw new TypeError("bad iterator");var o=GetV(r,"next"),a=Object.create(null);return a["[[Iterator]]"]=r,a["[[NextMethod]]"]=o,a["[[Done]]"]=!1,a}function GetPrototypeFromConstructor(t,o){var r=Get(t,"prototype");return"object"!==Type(r)&&(r=o),r}function OrdinaryCreateFromConstructor(r,e){var t=arguments[2]||{},o=GetPrototypeFromConstructor(r,e),a=Object.create(o);for(var n in t)Object.prototype.hasOwnProperty.call(t,n)&&Object.defineProperty(a,n,{configurable:!0,enumerable:!1,writable:!0,value:t[n]});return a}var GetSubstitution=function(){function e(e){return/^[0-9]$/.test(e)}return function t(n,r,l,i,a,f){for(var s=n.length,h=r.length,c=l+s,u=i.length,v="",g=0;g<f.length;g+=1){var o=f.charAt(g),$=g+1>=f.length,d=g+2>=f.length;if("$"!==o||$)v+=f.charAt(g);else{var p=f.charAt(g+1);if("$"===p)v+="$",g+=1;else if("&"===p)v+=n,g+=1;else if("`"===p)v+=0===l?"":r.slice(0,l-1),g+=1;else if("'"===p)v+=c>=h?"":r.slice(c),g+=1;else{var A=d?null:f.charAt(g+2);if(!e(p)||"0"===p||!d&&e(A))if(e(p)&&(d||e(A))){var y=p+A,I=parseInt(y,10)-1;v+=y<=u&&"Undefined"===Type(i[I])?"":i[I],g+=2}else v+="$";else{var T=parseInt(p,10);v+=T<=u&&"Undefined"===Type(i[T-1])?"":i[T-1],g+=1}}}}return v}}();function IsConstructor(t){return"object"===Type(t)&&("function"==typeof t&&!!t.prototype)}function Construct(r){var t=arguments.length>2?arguments[2]:r,o=arguments.length>1?arguments[1]:[];if(!IsConstructor(r))throw new TypeError("F must be a constructor.");if(!IsConstructor(t))throw new TypeError("newTarget must be a constructor.");if(t===r)return new(Function.prototype.bind.apply(r,[null].concat(o)));var n=OrdinaryCreateFromConstructor(t,Object.prototype);return Call(r,n,o)}function IsRegExp(e){if("object"!==Type(e))return!1;var n="Symbol"in self&&"match"in self.Symbol?Get(e,self.Symbol.match):undefined;if(n!==undefined)return ToBoolean(n);try{var t=e.lastIndex;return e.lastIndex=0,RegExp.prototype.exec.call(e),!0}catch(l){}finally{e.lastIndex=t}return!1}function IteratorClose(r,t){if("object"!==Type(r["[[Iterator]]"]))throw new Error(Object.prototype.toString.call(r["[[Iterator]]"])+"is not an Object.");var e=r["[[Iterator]]"],o=GetMethod(e,"return");if(o===undefined)return t;try{var n=Call(o,e)}catch(c){var a=c}if(t)return t;if(a)throw a;if("object"!==Type(n))throw new TypeError("Iterator's return method returned a non-object.");return t}function IteratorComplete(t){if("object"!==Type(t))throw new Error(Object.prototype.toString.call(t)+"is not an Object.");return ToBoolean(Get(t,"done"))}function IteratorNext(t){if(arguments.length<2)var e=Call(t["[[NextMethod]]"],t["[[Iterator]]"]);else e=Call(t["[[NextMethod]]"],t["[[Iterator]]"],[arguments[1]]);if("object"!==Type(e))throw new TypeError("bad iterator");return e}function IteratorStep(t){var r=IteratorNext(t);return!0!==IteratorComplete(r)&&r}function IteratorValue(t){if("object"!==Type(t))throw new Error(Object.prototype.toString.call(t)+"is not an Object.");return Get(t,"value")}var AddEntriesFromIterable=function(){var r={}.toString,t="".split;return function e(a,o,n){if(!1===IsCallable(n))throw new TypeError("adder is not callable.");for(var l=GetIterator(o);;){var c=IteratorStep(l);if(!1===c)return a;var i=IteratorValue(c);if("object"!==Type(i)){var s=new TypeError("nextItem is not an object");throw IteratorClose(l,s),s}i=("string"===Type(i)||i instanceof String)&&"[object String]"==r.call(i)?t.call(i,""):i;var I;try{I=Get(i,"0")}catch(I){return IteratorClose(l,I)}var u;try{u=Get(i,"1")}catch(u){return IteratorClose(l,u)}try{Call(n,a,[I,u])}catch(v){return IteratorClose(l,v)}}}}();function IterableToList(t){for(var r=arguments.length>1?GetIterator(t,arguments[1]):GetIterator(t),e=[],a=!0;!1!==a;)if(!1!==(a=IteratorStep(r))){var o=IteratorValue(a);e.push(o)}return e}!function(){function r(r,e){var t=void 0===e?new Error:new Error(e);CreateDataPropertyOrThrow(this,"name","AggregateError"),CreateDataPropertyOrThrow(this,"message",t.message),CreateDataPropertyOrThrow(this,"stack",t.stack);var o;if(Array.isArray(r))o=r.slice();else try{o=IterableToList(r)}catch(a){throw new TypeError("Argument is not iterable")}CreateDataPropertyOrThrow(this,"errors",o)}r.prototype=Object.create(Error.prototype),r.prototype.constructor=r,self.AggregateError=r}();!function(){CreateMethodProperty(Promise,"allSettled",function e(r){var t=this;if("object"!==Type(t))throw new TypeError("`this` value must be an object");var n;if(Array.isArray(r))n=r;else try{n=IterableToList(r)}catch(o){return Promise.reject(new TypeError("Argument of Promise.allSettled is not iterable"))}var a=n.map(function(e){var r=function(e){return{status:"fulfilled",value:e}},n=function(e){return{status:"rejected",reason:e}},a=t.resolve(e);try{return a.then(r,n)}catch(o){return t.reject(o)}});return t.all(a)})}();!function(){var r=function(r){return r};CreateMethodProperty(Promise,"any",function e(t){var n=this;if("object"!==Type(n))throw new TypeError("`this` value must be an object");var o;if(Array.isArray(t))o=t;else try{o=IterableToList(t)}catch(c){return Promise.reject(new TypeError("Argument of Promise.any is not iterable"))}var a=function(r){return n.reject(r)},i=o.map(function(e){var t=n.resolve(e);try{return t.then(a,r)}catch(o){return o}});return n.all(i).then(function(r){throw new AggregateError(r,"Every promise rejected")},r)})}();function OrdinaryToPrimitive(r,t){if("string"===t)var e=["toString","valueOf"];else e=["valueOf","toString"];for(var i=0;i<e.length;++i){var n=e[i],a=Get(r,n);if(IsCallable(a)){var o=Call(a,r);if("object"!==Type(o))return o}}throw new TypeError("Cannot convert to primitive.")}function RegExpExec(e,l){var r=Get(e,"exec");if(IsCallable(r)){var t=Call(r,e,[l]);if("object"!==Type(t)&&"null"!==Type(t))throw new TypeError("Invalid result: must be an object or null.");return t}return Call(RegExp.prototype.exec,e,[l])}function SpeciesConstructor(e,o){var r=Get(e,"constructor");if(r===undefined)return o;if("object"!==Type(r))throw new TypeError("O.constructor is not an Object");var n="function"==typeof self.Symbol&&"symbol"==typeof self.Symbol.species?r[self.Symbol.species]:undefined;if(n===undefined||null===n)return o;if(IsConstructor(n))return n;throw new TypeError("No constructor found")}function StringIndexOf(r,n,e){var f=r.length;if(""===n&&e<=f)return e;for(var t=n.length,a=e,i=-1;a+t<=f;){for(var g=!0,o=0;o<t;o+=1)if(r[a+o]!==n[o]){g=!1;break}if(g){i=a;break}a+=1}return i}function ToInteger(n){if("symbol"===Type(n))throw new TypeError("Cannot convert a Symbol value to a number");var t=Number(n);return isNaN(t)?0:1/t===Infinity||1/t==-Infinity||t===Infinity||t===-Infinity?t:(t<0?-1:1)*Math.floor(Math.abs(t))}function ToLength(n){var t=ToInteger(n);return t<=0?0:Math.min(t,Math.pow(2,53)-1)}function LengthOfArrayLike(e){return ToLength(Get(e,"length"))}function ToPrimitive(e){var t=arguments.length>1?arguments[1]:undefined;if("object"===Type(e)){if(arguments.length<2)var i="default";else t===String?i="string":t===Number&&(i="number");var r="function"==typeof self.Symbol&&"symbol"==typeof self.Symbol.toPrimitive?GetMethod(e,self.Symbol.toPrimitive):undefined;if(r!==undefined){var n=Call(r,e,[i]);if("object"!==Type(n))return n;throw new TypeError("Cannot convert exotic object to primitive.")}return"default"===i&&(i="number"),OrdinaryToPrimitive(e,i)}return e}function ToString(t){switch(Type(t)){case"symbol":throw new TypeError("Cannot convert a Symbol value to a string");case"object":return ToString(ToPrimitive(t,String));default:return String(t)}}CreateMethodProperty(Array.prototype,"at",function t(e){var r=ToObject(this),n=LengthOfArrayLike(r),o=ToIntegerOrInfinity(e),i=o>=0?o:n+o;return i<0||i>=n?undefined:Get(r,ToString(i))});CreateMethodProperty(String.prototype,"at",function e(t){var r=RequireObjectCoercible(this),n=ToString(r),i=n.length,o=ToIntegerOrInfinity(t),g=o>=0?o:i+o;return g<0||g>=i?undefined:n.substring(g,g+1)});CreateMethodProperty(String.prototype,"replaceAll",function e(r,t){"use strict";var n=RequireObjectCoercible(this);if(r!==undefined&&null!==r){if(IsRegExp(r)){var i=Get(r,"flags");if(!("flags"in RegExp.prototype||!0===r.global))throw TypeError("");if("flags"in RegExp.prototype&&(RequireObjectCoercible(i),-1===ToString(i).indexOf("g")))throw TypeError("")}var l="Symbol"in self&&"replace"in self.Symbol?GetMethod(r,self.Symbol.replace):undefined;if(l!==undefined)return Call(l,r,[n,t])}var o=ToString(n),a=ToString(r),f=IsCallable(t);!1===f&&(t=ToString(t));for(var g=a.length,s=Math.max(1,g),u=[],p=StringIndexOf(o,a,0);-1!==p;)u.push(p),p=StringIndexOf(o,a,p+s);for(var d=0,b="",S=0;S<u.length;S++){var h=o.substring(d,u[S]);if(f)var c=ToString(Call(t,undefined,[a,u[S],o]));else{var v=[];c=GetSubstitution(a,o,u[S],v,undefined,t)}b=b+h+c,d=u[S]+g}return d<o.length&&(b+=o.substring(d)),b});!function(){function t(t,r){return e?t[r]:t._getter(r)}function r(r){var e=this,o=e.length,a=ToIntegerOrInfinity(r),p=a>=0?a:o+a;return p<0||p>=o?undefined:t(e,ToString(p))}var e=function(){var t=new Uint8Array(2);return t[0]=42,42===t[0]};"__proto__"in self.Int8Array.prototype?CreateMethodProperty(self.Int8Array.prototype.__proto__,"at",r):(CreateMethodProperty(self.Int8Array.prototype,"at",r),CreateMethodProperty(self.Uint8Array.prototype,"at",r),CreateMethodProperty(self.Uint8ClampedArray.prototype,"at",r),CreateMethodProperty(self.Int16Array.prototype,"at",r),CreateMethodProperty(self.Uint16Array.prototype,"at",r),CreateMethodProperty(self.Int32Array.prototype,"at",r),CreateMethodProperty(self.Uint32Array.prototype,"at",r),CreateMethodProperty(self.Float32Array.prototype,"at",r),CreateMethodProperty(self.Float64Array.prototype,"at",r))}();function CreateRegExpStringIterator(e,t,r,n){var a={};return CreateMethodProperty(a,"next",function i(){if(!0===this["[[Done]]"])return CreateIterResultObject(undefined,!0);var a=RegExpExec(e,t);if(null===a)return this["[[Done]]"]=!0,CreateIterResultObject(undefined,!0);if(!1===r){var i=CreateIterResultObject(a,!1);return this["[[Done]]"]=!0,i}if(""===ToString(Get(a,"0"))){var o=ToLength(Get(e,"lastIndex")),u=AdvanceStringIndex(t,o,n);e.lastIndex=u}return CreateIterResultObject(a,!1)}),Object.defineProperty(a,Symbol.toStringTag,{configurable:!0,enumerable:!1,writable:!1,value:"RegExp String Iterator"}),CreateMethodProperty(a,Symbol.iterator,function o(){return this}),a}var supportsRegexpLiteralConstructorWithFlags=function(){try{return new RegExp(/x/,"g"),!0}catch(t){return!1}}();CreateMethodProperty(RegExp.prototype,Symbol.matchAll,function(t){"use strict";var e=this;if("object"!==Type(e))throw new TypeError("Method called on incompatible type: must be an object.");var r=ToString(t),o=SpeciesConstructor(e,RegExp),n=ToString(Get(e,"flags"));"flags"in RegExp.prototype||(n="",!0===e.global&&(n+="g"),!0===e.ignoreCase&&(n+="i"),!0===e.multiline&&(n+="m"));var a=Construct(o,[supportsRegexpLiteralConstructorWithFlags?e:e.source,n]),i=ToLength(Get(e,"lastIndex"));a.lastIndex=i;var p=n.indexOf("g")>-1,s=n.indexOf("u")>-1;return CreateRegExpStringIterator(a,r,p,s)});CreateMethodProperty(String.prototype,"matchAll",function e(l){"use strict";var r=RequireObjectCoercible(this);if(l!==undefined&&null!==l){if(IsRegExp(l)){var t=Get(l,"flags");if(!("flags"in RegExp.prototype||!0===l.global))throw TypeError("");if("flags"in RegExp.prototype&&(RequireObjectCoercible(t),-1===ToString(t).indexOf("g")))throw TypeError("")}var o="Symbol"in self&&"matchAll"in self.Symbol?GetMethod(l,self.Symbol.matchAll):undefined;if(o!==undefined)return Call(o,l,[r])}var i=ToString(r),n=new RegExp(l,"g");return Invoke(n,"Symbol"in self&&"matchAll"in self.Symbol&&self.Symbol.matchAll,[i])});function ToPropertyKey(r){var i=ToPrimitive(r,String);return"symbol"===Type(i)?i:ToString(i)}CreateMethodProperty(Object,"fromEntries",function r(e){RequireObjectCoercible(e);var t={},o=function(r,e){var t=this,o=ToPropertyKey(r);CreateDataPropertyOrThrow(t,o,e)};return AddEntriesFromIterable(t,e,o)});})('object' === typeof window && window || 'object' === typeof self && self || 'object' === typeof global && global || {});
} catch {}
