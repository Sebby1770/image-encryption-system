// Image handling for end-to-end uploads: identify the format from its bytes,
// read the dimensions sealed into the envelope, and strip capture metadata
// before encryption. In end-to-end mode the server only ever sees ciphertext,
// so this is the one place GPS and camera metadata can still be removed.
//
// Stripping works on the container structure, not the pixels: chunks and
// segments that carry metadata are dropped and the image data is copied
// unchanged. Containers are walked against an allow-list of rendering
// structures, so anything unrecognised is dropped rather than kept. No DOM
// access, so it runs under `node --test` too.

export const BROWSER_FORMATS = {
  PNG: "image/png",
  JPEG: "image/jpeg",
  WEBP: "image/webp",
  GIF: "image/gif",
  BMP: "image/bmp",
};

export class ImageError extends Error {
  constructor(message) {
    super(message);
    this.name = "ImageError";
  }
}

const DAMAGED = "The image file is damaged or unreadable.";

function ascii(bytes, start, length) {
  return String.fromCharCode(...bytes.subarray(start, start + length));
}

function view(bytes) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function need(bytes, end) {
  if (end > bytes.length) throw new ImageError(DAMAGED);
}

function concat(parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function sniffFormat(bytes) {
  if (bytes.length >= 8 && bytes[0] === 0x89 && ascii(bytes, 1, 7) === "PNG\r\n\x1a\n") return "PNG";
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return "JPEG";
  if (bytes.length >= 6 && /^GIF8[79]a$/.test(ascii(bytes, 0, 6))) return "GIF";
  if (bytes.length >= 12 && ascii(bytes, 0, 4) === "RIFF" && ascii(bytes, 8, 4) === "WEBP") return "WEBP";
  if (bytes.length >= 26 && ascii(bytes, 0, 2) === "BM") return "BMP";
  if (bytes.length >= 4 && (ascii(bytes, 0, 4) === "II*\0" || ascii(bytes, 0, 4) === "MM\0*")) return "TIFF";
  return null;
}

// Identify, measure, and strip an upload. Returns the bytes to encrypt plus the
// facts sealed into the envelope context.
export function prepareImage(bytes) {
  const format = sniffFormat(bytes);
  if (format === "TIFF") {
    throw new ImageError("Browsers cannot display TIFF, so encrypt TIFF images on the server.");
  }
  if (!format) throw new ImageError("This file type is not accepted.");
  const result = STRIPPERS[format](bytes);
  if (!(result.width >= 1 && result.height >= 1)) throw new ImageError(DAMAGED);
  return { format, mime: BROWSER_FORMATS[format], orientation: 1, frames: 1, ...result };
}

// --------------------------------------------------------------------------
// PNG: keep the chunks that describe pixels; drop text, EXIF, and time chunks
// and every unknown ancillary chunk (C2PA manifests, vendor data, ...).

const PNG_KEEP = new Set([
  "IHDR", "PLTE", "IDAT", "IEND", "tRNS", "cHRM", "gAMA", "iCCP", "sBIT", "sRGB",
  "cICP", "mDCV", "cLLI", "bKGD", "hIST", "pHYs", "sPLT", "acTL", "fcTL", "fdAT",
]);

function stripPNG(bytes) {
  const data = view(bytes);
  const kept = [bytes.subarray(0, 8)];
  const removed = [];
  let offset = 8;
  let width = 0;
  let height = 0;
  let frames = 1;
  let ended = false;
  while (offset < bytes.length) {
    need(bytes, offset + 12);
    const length = data.getUint32(offset);
    const type = ascii(bytes, offset + 4, 4);
    const end = offset + 12 + length;
    need(bytes, end);
    if (offset === 8) {
      if (type !== "IHDR" || length !== 13) throw new ImageError(DAMAGED);
      width = data.getUint32(offset + 8);
      height = data.getUint32(offset + 12);
    }
    if (type === "acTL" && length >= 4) frames = Math.max(1, data.getUint32(offset + 8));
    if (PNG_KEEP.has(type)) {
      kept.push(bytes.subarray(offset, end));
    } else if (!(bytes[offset + 4] & 0x20)) {
      // Unknown *critical* chunk: dropping it would corrupt the image.
      throw new ImageError("This PNG uses a structure the vault does not recognise.");
    } else {
      removed.push(type);
    }
    offset = end;
    if (type === "IEND") {
      ended = true;
      break;
    }
  }
  if (!ended) throw new ImageError(DAMAGED);
  if (offset < bytes.length) removed.push("trailing data");
  return { bytes: concat(kept), width, height, frames, removed };
}

// --------------------------------------------------------------------------
// JPEG: walk every segment, including those between progressive scans, and
// stop at EOI so data appended after the image (motion-photo video, vendor
// blobs) is dropped too.

const SOF_MARKERS = new Set([
  0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf,
]);
// Tables and frame structure: always kept.
const JPEG_STRUCTURE = new Set([0xc4, 0xcc, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, ...SOF_MARKERS]);

function stripJPEG(bytes) {
  const data = view(bytes);
  const kept = [bytes.subarray(0, 2)];
  const removed = [];
  let offset = 2;
  let width = 0;
  let height = 0;
  let orientation = 1;
  let ended = false;
  while (offset < bytes.length) {
    if (bytes[offset] !== 0xff) throw new ImageError(DAMAGED);
    while (bytes[offset + 1] === 0xff) offset += 1; // fill bytes
    need(bytes, offset + 2);
    const marker = bytes[offset + 1];
    if (marker === 0xd9) {
      kept.push(bytes.subarray(offset, offset + 2));
      offset += 2;
      ended = true;
      break;
    }
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      kept.push(bytes.subarray(offset, offset + 2));
      offset += 2;
      continue;
    }
    if (marker === 0xd8 || marker === 0x00) throw new ImageError(DAMAGED);
    need(bytes, offset + 4);
    const length = data.getUint16(offset + 2);
    if (length < 2) throw new ImageError(DAMAGED);
    const end = offset + 2 + length;
    need(bytes, end);
    const segment = bytes.subarray(offset, end);
    const payload = bytes.subarray(offset + 4, end);

    if (SOF_MARKERS.has(marker)) {
      need(bytes, offset + 9);
      height = data.getUint16(offset + 5);
      width = data.getUint16(offset + 7);
    }
    if (marker === 0xda) {
      // Start of scan: copy the header and its entropy-coded data, which runs
      // until a marker that is neither byte stuffing (FF00) nor a restart.
      let scan = end;
      while (scan < bytes.length) {
        if (bytes[scan] === 0xff) {
          const next = bytes[scan + 1];
          if (next !== 0x00 && !(next >= 0xd0 && next <= 0xd7)) break;
        }
        scan += 1;
      }
      kept.push(bytes.subarray(offset, scan));
      offset = scan;
      continue;
    }
    if (JPEG_STRUCTURE.has(marker)) {
      kept.push(segment);
    } else if (marker === 0xe0) {
      const jfif = keepJFIF(payload);
      if (jfif) kept.push(jfif);
      else removed.push("APP0");
    } else if (marker === 0xe2 && ascii(payload, 0, 12) === "ICC_PROFILE\0") {
      kept.push(segment);
    } else if (marker === 0xee && ascii(payload, 0, 5) === "Adobe") {
      kept.push(segment); // colour transform: needed to decode CMYK/YCCK
    } else if (marker === 0xe1 && ascii(payload, 0, 6) === "Exif\0\0") {
      orientation = exifOrientation(payload.subarray(6));
      removed.push("EXIF");
    } else if (marker >= 0xe0 && marker <= 0xef) {
      removed.push(`APP${marker - 0xe0}`);
    } else if (marker === 0xfe) {
      removed.push("COM");
    } else {
      throw new ImageError("This JPEG uses a structure the vault does not recognise.");
    }
    offset = end;
  }
  if (!ended) throw new ImageError(DAMAGED);
  if (offset < bytes.length) removed.push("trailing data");
  return { bytes: concat(kept), width, height, orientation, removed };
}

// Keep a JFIF header but never its embedded thumbnail, which is a second copy
// of the picture. JFXX extension segments only carry thumbnails, so they go.
function keepJFIF(payload) {
  if (payload.length < 14 || ascii(payload, 0, 5) !== "JFIF\0") return null;
  const out = new Uint8Array(18);
  out.set([0xff, 0xe0, 0x00, 0x10]);
  out.set(payload.subarray(0, 12), 4);
  return out; // thumbnail width and height left at zero
}

function exifOrientation(tiff) {
  try {
    if (tiff.length < 8) return 1;
    const little = ascii(tiff, 0, 2) === "II";
    if (!little && ascii(tiff, 0, 2) !== "MM") return 1;
    const data = view(tiff);
    const ifd = data.getUint32(4, little);
    const count = data.getUint16(ifd, little);
    for (let i = 0; i < count; i += 1) {
      const entry = ifd + 2 + i * 12;
      if (data.getUint16(entry, little) === 0x0112) {
        const value = data.getUint16(entry + 8, little);
        return value >= 1 && value <= 8 ? value : 1;
      }
    }
  } catch {
    // A malformed EXIF block is dropped either way; assume upright.
  }
  return 1;
}

// --------------------------------------------------------------------------
// WebP: a RIFF container. Drop EXIF, XMP, and unknown chunks; clear their flags
// in the VP8X header and rewrite the RIFF size.

const WEBP_KEEP = new Set(["VP8 ", "VP8L", "VP8X", "ALPH", "ANIM", "ANMF", "ICCP"]);

function stripWEBP(bytes) {
  const data = view(bytes);
  const riffEnd = 8 + data.getUint32(4, true);
  need(bytes, riffEnd);
  const chunks = [];
  const removed = [];
  let offset = 12;
  let width = 0;
  let height = 0;
  let frames = 0;
  let animated = false;
  while (offset + 8 <= riffEnd) {
    const type = ascii(bytes, offset, 4);
    const size = data.getUint32(offset + 4, true);
    const end = offset + 8 + size + (size & 1);
    if (offset + 8 + size > riffEnd) throw new ImageError(DAMAGED);
    const payload = bytes.subarray(offset + 8, offset + 8 + size);
    let chunk = bytes.subarray(offset, Math.min(end, riffEnd));
    if (type === "VP8X") {
      if (size < 10) throw new ImageError(DAMAGED);
      chunk = chunk.slice();
      chunk[8] &= ~(0x08 | 0x04); // EXIF and XMP present flags
      animated = Boolean(payload[0] & 0x02);
      width = 1 + (payload[4] | (payload[5] << 8) | (payload[6] << 16));
      height = 1 + (payload[7] | (payload[8] << 8) | (payload[9] << 16));
    } else if (type === "VP8L" && !width) {
      if (size < 5 || payload[0] !== 0x2f) throw new ImageError(DAMAGED);
      const bits = view(payload).getUint32(1, true);
      width = (bits & 0x3fff) + 1;
      height = ((bits >>> 14) & 0x3fff) + 1;
    } else if (type === "VP8 " && !width) {
      if (size < 10 || payload[3] !== 0x9d || payload[4] !== 0x01 || payload[5] !== 0x2a) {
        throw new ImageError(DAMAGED);
      }
      width = view(payload).getUint16(6, true) & 0x3fff;
      height = view(payload).getUint16(8, true) & 0x3fff;
    }
    if (type === "ANMF") frames += 1;
    if (WEBP_KEEP.has(type)) chunks.push(padded(chunk, size));
    else removed.push(type.trim());
    offset = end;
  }
  if (riffEnd < bytes.length) removed.push("trailing data");
  const body = concat(chunks);
  const header = new Uint8Array(12);
  header.set([0x52, 0x49, 0x46, 0x46]); // RIFF
  view(header).setUint32(4, 4 + body.length, true);
  header.set([0x57, 0x45, 0x42, 0x50], 8); // WEBP
  return { bytes: concat([header, body]), width, height, frames: animated ? Math.max(1, frames) : 1, removed };
}

function padded(chunk, size) {
  const wanted = 8 + size + (size & 1);
  if (chunk.length === wanted) return chunk;
  const out = new Uint8Array(wanted);
  out.set(chunk.subarray(0, Math.min(chunk.length, wanted)));
  return out;
}

// --------------------------------------------------------------------------
// GIF: keep frames, graphic control, looping and ICC application blocks; drop
// comments and every other application extension (XMP lives in one).

const GIF_APPS = new Set(["NETSCAPE2.0", "ANIMEXTS1.0", "ICCRGBG1012"]);

function skipSubBlocks(bytes, offset) {
  for (;;) {
    need(bytes, offset + 1);
    const size = bytes[offset];
    offset += 1;
    if (size === 0) return offset;
    offset += size;
  }
}

function stripGIF(bytes) {
  need(bytes, 13);
  const data = view(bytes);
  const width = data.getUint16(6, true);
  const height = data.getUint16(8, true);
  const packed = bytes[10];
  let offset = 13 + (packed & 0x80 ? 3 * 2 ** ((packed & 7) + 1) : 0);
  need(bytes, offset);
  const kept = [bytes.subarray(0, offset)];
  const removed = [];
  let frames = 0;
  let ended = false;
  while (offset < bytes.length) {
    const introducer = bytes[offset];
    if (introducer === 0x3b) {
      kept.push(bytes.subarray(offset, offset + 1));
      offset += 1;
      ended = true;
      break;
    }
    if (introducer === 0x2c) {
      need(bytes, offset + 11);
      const local = bytes[offset + 9];
      const start = offset;
      offset += 10 + (local & 0x80 ? 3 * 2 ** ((local & 7) + 1) : 0) + 1; // + LZW min code size
      offset = skipSubBlocks(bytes, offset);
      kept.push(bytes.subarray(start, offset));
      frames += 1;
      continue;
    }
    if (introducer !== 0x21) throw new ImageError(DAMAGED);
    need(bytes, offset + 2);
    const label = bytes[offset + 1];
    const start = offset;
    const app = label === 0xff && bytes[offset + 2] === 11 ? ascii(bytes, offset + 3, 11) : null;
    offset = skipSubBlocks(bytes, offset + 2);
    if (label === 0xf9 || label === 0x01 || (app && GIF_APPS.has(app))) {
      kept.push(bytes.subarray(start, offset));
    } else {
      removed.push(label === 0xfe ? "comment" : app ? `application ${app.trim()}` : "extension");
    }
  }
  if (!ended || frames === 0) throw new ImageError(DAMAGED);
  if (offset < bytes.length) removed.push("trailing data");
  return { bytes: concat(kept), width, height, frames, removed };
}

// --------------------------------------------------------------------------
// BMP has no capture-metadata container (a V5 header's ICC profile only
// describes colour), so it is measured and passed through.

function stripBMP(bytes) {
  const data = view(bytes);
  const headerSize = data.getUint32(14, true);
  let width;
  let height;
  if (headerSize === 12) {
    width = data.getUint16(18, true);
    height = data.getUint16(20, true);
  } else if (headerSize >= 40) {
    width = Math.abs(data.getInt32(18, true));
    height = Math.abs(data.getInt32(22, true));
  } else {
    throw new ImageError(DAMAGED);
  }
  return { bytes, width, height, removed: [] };
}

const STRIPPERS = { PNG: stripPNG, JPEG: stripJPEG, WEBP: stripWEBP, GIF: stripGIF, BMP: stripBMP };
