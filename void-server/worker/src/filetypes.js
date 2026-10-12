// What operators may upload (op.js), and a check of each finished upload's
// first bytes: an extension proves nothing, so a renamed program is deleted.
// Files in void-incoming are never served, so this keeps junk out of the
// review queue; the real safety is the review itself.

// extension -> group (the group picks the content check)
export const ALLOWED = {
  mp4: "isobmff", m4v: "isobmff", mov: "isobmff", "3gp": "isobmff", m4a: "isobmff",
  mkv: "ebml", webm: "ebml",
  avi: "avi", wmv: "asf", wma: "asf", flv: "flv",
  mpg: "mpeg", mpeg: "mpeg", ts: "ts",
  ogv: "ogg", ogg: "ogg", opus: "ogg",
  mp3: "mp3", aac: "aac", flac: "flac", wav: "wav",
  jpg: "jpeg", jpeg: "jpeg", png: "png", gif: "gif", webp: "webp", bmp: "bmp", tga: "tga",
  dm_66: "demo", dm_67: "demo", dm_68: "demo", dm_73: "demo", dm_90: "demo", dm_91: "demo",
  zip: "zip", pk3: "zip", "7z": "7z", rar: "rar", tar: "tar", gz: "gz",
  pdf: "pdf",
  txt: "text", nfo: "text", md: "text",
};

export const TEXT_MAX = 1024 * 1024; // txt/nfo/md
export const SNIFF_BYTES = 4096;

export function extensionOf(name) {
  const dot = name.lastIndexOf(".");
  return dot > 0 ? name.slice(dot + 1).toLowerCase() : "";
}

const ascii = (b, at, s) => {
  if (b.length < at + s.length) return false;
  for (let i = 0; i < s.length; i++) if (b[at + i] !== s.charCodeAt(i)) return false;
  return true;
};
const bytes = (b, at, list) => list.every((v, i) => b[at + i] === v);

// Programs and pages, whatever the name says
function isExecutable(b) {
  return (
    ascii(b, 0, "MZ") ||                      // Windows exe/dll
    bytes(b, 0, [0x7f, 0x45, 0x4c, 0x46]) ||  // ELF
    ascii(b, 0, "#!") ||                      // script
    bytes(b, 0, [0xfe, 0xed, 0xfa, 0xce]) || bytes(b, 0, [0xfe, 0xed, 0xfa, 0xcf]) ||
    bytes(b, 0, [0xce, 0xfa, 0xed, 0xfe]) || bytes(b, 0, [0xcf, 0xfa, 0xed, 0xfe]) ||
    bytes(b, 0, [0xca, 0xfe, 0xba, 0xbe])     // Mach-O / Java class
  );
}

const MP4_BOXES = ["ftyp", "moov", "mdat", "wide", "free", "skip", "pnot"];

const CHECKS = {
  isobmff: (b) => MP4_BOXES.some((box) => ascii(b, 4, box)),
  ebml: (b) => bytes(b, 0, [0x1a, 0x45, 0xdf, 0xa3]),
  avi: (b) => ascii(b, 0, "RIFF") && ascii(b, 8, "AVI "),
  wav: (b) => ascii(b, 0, "RIFF") && ascii(b, 8, "WAVE"),
  webp: (b) => ascii(b, 0, "RIFF") && ascii(b, 8, "WEBP"),
  asf: (b) => bytes(b, 0, [0x30, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11]),
  flv: (b) => ascii(b, 0, "FLV"),
  mpeg: (b) => bytes(b, 0, [0, 0, 1]) && (b[3] === 0xba || b[3] === 0xb3),
  ts: (b) => (b[0] === 0x47 && b[188] === 0x47) || (b[4] === 0x47 && b[196] === 0x47),
  ogg: (b) => ascii(b, 0, "OggS"),
  mp3: (b) => ascii(b, 0, "ID3") || (b[0] === 0xff && (b[1] & 0xe0) === 0xe0),
  aac: (b) => ascii(b, 0, "ID3") || ascii(b, 0, "ADIF") || (b[0] === 0xff && (b[1] & 0xf6) === 0xf0),
  flac: (b) => ascii(b, 0, "fLaC") || ascii(b, 0, "ID3"),
  jpeg: (b) => bytes(b, 0, [0xff, 0xd8, 0xff]),
  png: (b) => bytes(b, 0, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  gif: (b) => ascii(b, 0, "GIF87a") || ascii(b, 0, "GIF89a"),
  bmp: (b) => ascii(b, 0, "BM"),
  // no magic number: colour-map type 0/1 and a known image type
  tga: (b) => b[1] <= 1 && [0, 1, 2, 3, 9, 10, 11, 32, 33].includes(b[2]),
  // no magic number either: int32 sequence, then int32 message length <= MAX_MSGLEN (16384), or -1 at the end
  demo: (b) => {
    if (b.length < 8) return false;
    const len = new DataView(b.buffer, b.byteOffset, b.length).getInt32(4, true);
    return len === -1 || (len >= 0 && len <= 16384);
  },
  zip: (b) => bytes(b, 0, [0x50, 0x4b, 0x03, 0x04]) || bytes(b, 0, [0x50, 0x4b, 0x05, 0x06]),
  "7z": (b) => bytes(b, 0, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]),
  rar: (b) => ascii(b, 0, "Rar!\x1a\x07"),
  tar: (b) => ascii(b, 257, "ustar"),
  gz: (b) => bytes(b, 0, [0x1f, 0x8b]),
  // "%PDF-" within the first KiB (some writers put junk before it)
  pdf: (b) => {
    for (let i = 0; i <= Math.min(1024, b.length - 5); i++) if (ascii(b, i, "%PDF-")) return true;
    return false;
  },
  // nfo files are classic code page 437 art, so no UTF-8 check: just no NUL bytes
  text: (b) => !b.includes(0),
};

// true = the first bytes (`b`, up to SNIFF_BYTES) fit the file's extension
export function contentMatches(ext, b) {
  const group = ALLOWED[ext];
  if (!group || isExecutable(b)) return false;
  return CHECKS[group](b);
}
