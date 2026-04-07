#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

function patchFile(filePath) {
    let source = fs.readFileSync(filePath, "utf8");
    const original = source;

    source = source.replace(
        /\s*console\.warn\('using deprecated parameters for `initSync\(\)`; pass a single object instead'\)\r?\n/g,
        "\n"
    );
    source = source.replace(
        /\s*console\.warn\('using deprecated parameters for the initialization function; pass a single object instead'\)\r?\n/g,
        "\n"
    );

    if (source !== original) {
        fs.writeFileSync(filePath, source, "utf8");
        console.log(`patched ${filePath}`);
    }
}

function walk(entryPath) {
    if (!fs.existsSync(entryPath)) {
        return;
    }

    const stat = fs.statSync(entryPath);
    if (stat.isFile()) {
        if (entryPath.endsWith(".js")) {
            patchFile(entryPath);
        }
        return;
    }

    for (const name of fs.readdirSync(entryPath)) {
        walk(path.join(entryPath, name));
    }
}

const targets = process.argv.slice(2);
if (targets.length === 0) {
    walk(path.resolve(process.cwd(), "web"));
    walk(path.resolve(process.cwd(), "nodejs"));
} else {
    for (const target of targets) {
        walk(path.resolve(process.cwd(), target));
    }
}

