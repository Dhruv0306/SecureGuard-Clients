// Test helper for desktop/src/tokens.css. Not a test file: the CI glob only
// picks up *.test.js. Converts OKLCH to 8-bit sRGB and computes WCAG contrast,
// so the colour tokens can be checked without a browser.

// Text between the braces of the block that starts at `open` (the "{").
function blockAt(text, open) {
    let depth = 0;
    for (let i = open; i < text.length; i++) {
        if (text[i] === "{") depth++;
        else if (text[i] === "}" && --depth === 0) return text.slice(open + 1, i);
    }
    throw new Error("unbalanced braces");
}

function declarations(block) {
    const out = {};
    for (const m of block.matchAll(/--([a-z-]+)\s*:\s*([^;]+);/g)) out[m[1]] = m[2].trim();
    return out;
}

// Reads the first :root block (OKLCH values) and the :root block inside
// `@supports not (color: oklch(0 0 0))` (hex values) from the stylesheet.
export function parseTokens(css) {
    const text = css.replace(/\/\*[\s\S]*?\*\//g, "");
    const supports = text.indexOf("@supports not (color: oklch(0 0 0))");
    const head = supports === -1 ? text : text.slice(0, supports);
    const rootAt = head.search(/:root\s*\{/);
    if (rootAt === -1) throw new Error("no :root block");
    const oklch = {};
    for (const [name, value] of Object.entries(declarations(blockAt(head, head.indexOf("{", rootAt))))) {
        const m = value.match(/^oklch\(\s*([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*\)$/);
        if (m) oklch[name] = { l: Number(m[1]), c: Number(m[2]), h: Number(m[3]) };
    }
    const hex = {};
    if (supports !== -1) {
        const inner = blockAt(text, text.indexOf("{", supports));
        const rootInner = inner.search(/:root\s*\{/);
        if (rootInner !== -1) {
            for (const [name, value] of Object.entries(declarations(blockAt(inner, inner.indexOf("{", rootInner))))) {
                if (/^#[0-9a-f]{6}$/i.test(value)) hex[name] = value.toLowerCase();
            }
        }
    }
    return { oklch, hex };
}

const encode = x => (x <= 0.0031308 ? 12.92 * x : 1.055 * Math.pow(x, 1 / 2.4) - 0.055);

// { l: 0..1, c, h: degrees } to { r, g, b: 0..255 integers, inGamut }.
export function toRgb({ l, c, h }) {
    const a = c * Math.cos((h * Math.PI) / 180);
    const b = c * Math.sin((h * Math.PI) / 180);
    const l_ = Math.pow(l + 0.3963377774 * a + 0.2158037573 * b, 3);
    const m_ = Math.pow(l - 0.1055613458 * a - 0.0638541728 * b, 3);
    const s_ = Math.pow(l - 0.0894841775 * a - 1.291485548 * b, 3);
    const lin = [
        4.0767416621 * l_ - 3.3077115913 * m_ + 0.2309699292 * s_,
        -1.2684380046 * l_ + 2.6097574011 * m_ - 0.3413193965 * s_,
        -0.0041960863 * l_ - 0.7034186147 * m_ + 1.707614701 * s_,
    ];
    const inGamut = lin.every(v => v >= -0.0005 && v <= 1.0005);
    const [r, g, bl] = lin.map(v => Math.round(Math.min(1, Math.max(0, encode(Math.min(1, Math.max(0, v))))) * 255));
    return { r, g, b: bl, inGamut };
}

export function fromHex(hex) {
    const n = parseInt(hex.slice(1), 16);
    return { r: (n >> 16) & 255, g: (n >> 8) & 255, b: n & 255 };
}

function luminance({ r, g, b }) {
    const f = v => {
        const s = v / 255;
        return s <= 0.04045 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
    };
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
}

// WCAG 2 contrast ratio of two 8-bit sRGB colours (1 to 21).
export function contrast(a, b) {
    const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
    return (hi + 0.05) / (lo + 0.05);
}
