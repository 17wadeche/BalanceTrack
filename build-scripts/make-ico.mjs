// build-scripts/make-win-assets.mjs
import fs from "node:fs/promises";
import path from "node:path";
import sharp from "sharp";
import toIco from "to-ico";

const SRC = "public/pwa-512.png";

// Where electron-builder looks by default:
const OUT_DIR_ICO = "build";
const OUT_DIR_APPX = "build/appx";

// 1) ICO (good spread of sizes)
const icoSizes = [16, 24, 32, 48, 64, 128, 256];

// 2) AppX-required (or commonly referenced) PNGs
//   At minimum, Square44x44Logo.png and Square150x150Logo.png.
//   StoreLogo.png is still referenced by many templates; include it.
//   The others are optional but nice to have.
const appxLogos = [
  { name: "Square44x44Logo.png",  size: 44 },
  { name: "Square150x150Logo.png", size: 150 },
  { name: "StoreLogo.png",         size: 50 },   // classic Store logo
  // Optional but recommended:
  { name: "Square71x71Logo.png",   size: 71 },
  { name: "Wide310x150Logo.png",   size: 310, height: 150 },
  { name: "Square310x310Logo.png", size: 310 },
];

async function ensureDirs() {
  await fs.mkdir(OUT_DIR_ICO, { recursive: true });
  await fs.mkdir(OUT_DIR_APPX, { recursive: true });
}

async function makeIco() {
  const bufs = await Promise.all(
    icoSizes.map((s) => sharp(SRC).resize(s, s).png().toBuffer())
  );
  const ico = await toIco(bufs);
  const icoPath = path.join(OUT_DIR_ICO, "icon.ico");
  await fs.writeFile(icoPath, ico);
  console.log(`Wrote ${icoPath}`);
}

async function makeAppxPngs() {
  for (const logo of appxLogos) {
    const outPath = path.join(OUT_DIR_APPX, logo.name);
    const pipeline = sharp(SRC).resize(
      logo.size,
      logo.height ?? logo.size, // handle Wide310x150
      { fit: "contain", background: { r: 0, g: 0, b: 0, alpha: 0 } }
    );
    await pipeline.png().toFile(outPath);
    console.log(`Wrote ${outPath}`);
  }
}

await ensureDirs();
await makeIco();
await makeAppxPngs();
console.log("✅ Windows icon + AppX assets generated.");
