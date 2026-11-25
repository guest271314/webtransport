//! quico-bundle.js
//! guest271314 11-23-2026
//! export { createServer as createH3Server } from "./node_modules/quico/src/h3_server.js";
//! bun build --target=browser --format=esm --outfile=quico-bundle.js export.js
/*!
node -e '
const fs = require("fs");
let code = fs.readFileSync("quico-bundle.js", "utf8");
code = code.replace(/(\b[\w$]+(?:\.[\w$]+)*)\.__proto__\s*=\s*([^;,\n)]+)/g, "Object.setPrototypeOf($1,$2)");
code = code.replace(/(\b[\w$]+(?:\.[\w$]+)*)\.__proto__/g, "Object.getPrototypeOf($1)");
fs.writeFileSync("quico-bundle.js", code);
'
*/
//! bun build --target=browser --format=esm --minify --outfile=quico-bundle-min.js quico-bundle.js
/*! 
node -e '
const fs = require("fs");
let code = fs.readFileSync("quico-bundle-min.js", "utf8");
code = code.replace(/(\b[\w$]+(?:\.[\w$]+)*)\.__proto__\s*=\s*([^;,\n)]+)/g, "Object.setPrototypeOf($1,$2)");
code = code.replace(/(\b[\w$]+(?:\.[\w$]+)*)\.__proto__/g, "Object.getPrototypeOf($1)");
fs.writeFileSync("quico-bundle-min.js", code);
'
*/
export { createServer as createH3Server } from './node_modules/quico/src/h3_server.js';
