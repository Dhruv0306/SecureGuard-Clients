// Checks the colour tokens and the font files in desktop/src/tokens.css.
// No dependencies: run with `node --test "desktop/tests/**/*.test.js"`.
// The values are what the redesign plan fixed after the contrast check, so a
// later edit that breaks a text pair or a fallback fails here.

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { parseTokens, toRgb, fromHex, contrast } from "./oklch.js";

const src = new URL("../src/", import.meta.url);
const css = fs.readFileSync(new URL("tokens.css", src), "utf8");
const tokens = parseTokens(css);

const NAMES = ["bg", "side", "ink", "muted", "accent", "accent-ink", "tint", "line",
    "bad", "bad-bg", "sus", "sus-bg", "ok"];

// Text colour, surface, and the least ratio WCAG AA asks of body text.
const PAIRS = [
    ["ink", "bg"], ["ink", "side"], ["ink", "bad-bg"], ["ink", "sus-bg"],
    ["muted", "bg"], ["muted", "side"],
    ["accent", "bg"], ["accent", "tint"], ["accent-ink", "accent"],
    ["bad", "bg"], ["bad", "bad-bg"], ["sus", "bg"], ["sus", "sus-bg"], ["ok", "bg"],
];

test("every colour token is defined as OKLCH", () => {
    for (const name of NAMES) {
        assert.ok(tokens.oklch[name], `--${name} is missing`);
    }
});

test("every token is inside the sRGB gamut", () => {
    for (const name of NAMES) {
        assert.ok(toRgb(tokens.oklch[name]).inGamut, `--${name} is outside sRGB`);
    }
});

test("each text pair meets WCAG AA (4.5)", () => {
    for (const [fg, bgName] of PAIRS) {
        const ratio = contrast(toRgb(tokens.oklch[fg]), toRgb(tokens.oklch[bgName]));
        assert.ok(ratio >= 4.5, `--${fg} on --${bgName} is ${ratio.toFixed(2)}`);
    }
});

test("every OKLCH token has a hex fallback within 1/255 per channel", () => {
    for (const name of NAMES) {
        assert.ok(tokens.hex[name], `--${name} has no hex fallback`);
        const want = toRgb(tokens.oklch[name]);
        const got = fromHex(tokens.hex[name]);
        for (const ch of ["r", "g", "b"]) {
            assert.ok(Math.abs(want[ch] - got[ch]) <= 1, `--${name} ${ch}: ${got[ch]} vs ${want[ch]}`);
        }
    }
});

test("the fallbacks meet the same contrast pairs", () => {
    for (const [fg, bgName] of PAIRS) {
        const ratio = contrast(fromHex(tokens.hex[fg]), fromHex(tokens.hex[bgName]));
        assert.ok(ratio >= 4.5, `fallback --${fg} on --${bgName} is ${ratio.toFixed(2)}`);
    }
});

test("four Hanken Grotesk weights are declared with swap and the files exist", () => {
    for (const weight of [400, 500, 600, 700]) {
        const rule = css.match(new RegExp(`@font-face\\s*\\{[^}]*font-weight:\\s*${weight}\\s*;[^}]*\\}`));
        assert.ok(rule, `no @font-face for ${weight}`);
        assert.match(rule[0], /font-family:\s*"Hanken Grotesk"/);
        assert.match(rule[0], /font-display:\s*swap/);
        const url = rule[0].match(/url\("([^"]+)"\)/);
        assert.ok(url, `no url for ${weight}`);
        assert.ok(fs.existsSync(new URL(url[1], src)), `${url[1]} is missing`);
    }
});

test("the font licence ships with the fonts", () => {
    const licence = fs.readFileSync(new URL("fonts/OFL.txt", src), "utf8");
    assert.match(licence, /SIL OPEN FONT LICENSE/i);
});
