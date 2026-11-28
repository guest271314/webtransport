// Usage (any runtime): node patch-bundle.js wt-client-bundle-browser.js wt-client-bundle-tjs.js
// 1. Replaces the bundler's empty stubs for node:dgram / node:dns with the tjs shims.
// 2. Installs the bundle's own inlined Buffer polyfill as globalThis.Buffer (the QUIC code
//    uses a bare `Buffer`, which Node/Deno/Bun provide natively but tjs does not).
import { readFileSync, writeFileSync } from "node:fs";
const [src = "wt-client-bundle-browser.js", dst = "wt-client-bundle-tjs.js"] = process.argv.slice(2);
let code = readFileSync(src, "utf8");

let n = 0;
code = code.replace(
  /var \{ default: (dgram\d*|dns\d*)\s*\} = \(\(\) => \(\{\}\)\);/g,
  (_, name) => (n++, `var { default: ${name} } = { default: globalThis.__tjs_${name.startsWith("dgram") ? "dgram" : "dns"} };`),
);
if (n !== 10) console.warn(`expected 10 stubs (4 dgram + 6 dns), patched ${n}`);

// Must run after init_buffer is defined and before the first top-level bare `Buffer` use.
const marker = "\n// node:net\n";
if (code.split(marker).length !== 2) throw new Error("couldn't find the unique '// node:net' marker");
code = code.replace(
  marker,
  `\nglobalThis.Buffer ??= (init_buffer(), __toCommonJS(exports_buffer)).Buffer;\n${marker}`,
);

// 3. Debugging aid: quico's swallowing emitter hides exceptions thrown inside event handlers
//    (`catch (e) {}`), so a missing tjs API silently kills the connection. Log them when QUICO_DEBUG is set.
const swallow = "    try {\n      fn.apply(null, args);\n    } catch (e) {}";
if (code.split(swallow).length !== 2) throw new Error("couldn't find the emitter swallow site");
code = code.replace(
  swallow,
  '    try {\n      fn.apply(null, args);\n    } catch (e) {\n      if (DEBUG)\n        console.log("[swallowed handler error]", String(e), e && e.stack);\n    }',
);

// 4. ImmutableHeaders extends Headers and throws from append/set/delete. Node's Headers constructor
//    fills itself internally, but tjs's polyfill constructor calls this.append() for each entry, so the
//    subclass threw while being constructed, WebTransport never resolved `ready`, and the error was
//    swallowed. Only throw once construction is finished (flag set by responseHeadersOf).
const imm = `class ImmutableHeaders extends Headers {
  set() {
    throw new TypeError("responseHeaders cannot be changed");
  }
  append() {
    throw new TypeError("responseHeaders cannot be changed");
  }
  delete() {
    throw new TypeError("responseHeaders cannot be changed");
  }
}`;
if (code.split(imm).length !== 2) throw new Error("couldn't find ImmutableHeaders");
code = code.replace(imm, `class ImmutableHeaders extends Headers {
  set() {
    if (this.__sealed) throw new TypeError("responseHeaders cannot be changed");
    return super.set.apply(this, arguments);
  }
  append() {
    if (this.__sealed) throw new TypeError("responseHeaders cannot be changed");
    return super.append.apply(this, arguments);
  }
  delete() {
    if (this.__sealed) throw new TypeError("responseHeaders cannot be changed");
    return super.delete.apply(this, arguments);
  }
}`);
const ret = "  return new ImmutableHeaders(pairs);\n}";
if (code.split(ret).length !== 2) throw new Error("couldn't find responseHeadersOf return");
code = code.replace(ret, `  var sealed = new ImmutableHeaders(pairs);
  Object.defineProperty(sealed, "__sealed", { value: true });
  return sealed;
}`);

writeFileSync(dst, code);
console.log(`patched ${n} stubs + Buffer global + swallow logging + ImmutableHeaders -> ${dst}`);
