# Cryptix WASM SDK

An integration wrapper around [`cryptix-wasm`](https://www.npmjs.com/package/cryptix-wasm) module that uses [`websocket`](https://www.npmjs.com/package/websocket) W3C adaptor for WebSocket communication.

This is a Node.js module that provides bindings to the Cryptix WASM SDK strictly for use in the Node.js environment. The web browser version of the SDK is available as part of official SDK releases at [https://github.com/cryptixnet/rusty-cryptix/releases](https://github.com/cryptixnet/rusty-cryptix/releases)

## Usage

Cryptix NPM module exports include all WASM32 bindings.
```javascript
const cryptix = require('cryptix');
console.log(cryptix.version());
```

## Documentation

Documentation is available at [https://cryptix.aspectron.org/docs/](https://cryptix.aspectron.org/docs/)


## Building from source & Examples

SDK examples as well as information on building the project from source can be found at [https://github.com/cryptixnet/rusty-cryptix/tree/master/wasm](https://github.com/cryptixnet/rusty-cryptix/tree/master/wasm)

## Releases

Official releases as well as releases for Web Browsers are available at [https://github.com/cryptixnet/rusty-cryptix/releases](https://github.com/cryptixnet/rusty-cryptix/releases).

Nightly / developer builds are available at: [https://aspectron.org/en/projects/cryptix-wasm.html](https://aspectron.org/en/projects/cryptix-wasm.html)

