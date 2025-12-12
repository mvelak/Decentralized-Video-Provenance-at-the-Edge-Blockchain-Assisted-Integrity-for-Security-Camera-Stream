import { NextResponse } from "next/server";

export const runtime = "nodejs";

type PinataPinResponse = {
  IpfsHash: string;
  PinSize: number;
  Timestamp: string;
  isDuplicate?: boolean;
};

export async function POST(req: Request) {
  let jwt = (process.env.PINATA_JWT ?? "").trim();
  if (!jwt) {
    return NextResponse.json(
      { error: "Server missing PINATA_JWT. Set it to enable /api/ipfs uploads." },
      { status: 501 }
    );
  }

  // Common mistakes: including `Bearer ` prefix or wrapping the token in quotes.
  jwt = jwt.replace(/^Bearer\s+/i, "").trim();
  jwt = jwt.replace(/^['"](.+)['"]$/, "$1").trim();

  // JWT must have exactly 3 dot-separated segments.
  if (jwt.split(".").length !== 3) {
    return NextResponse.json(
      {
        error:
          "PINATA_JWT is not a valid JWT (expected 3 dot-separated segments). Paste the raw JWT from Pinata (usually starts with eyJ...) and do not include 'Bearer '.",
      },
      { status: 500 }
    );
  }

  let file: File | null = null;
  try {
    const incoming = await req.formData();
    const maybeFile = incoming.get("file");
    file = maybeFile instanceof File ? maybeFile : null;
  } catch {
    // ignore; handled below
  }

  if (!file) {
    return NextResponse.json({ error: "Expected multipart/form-data with a 'file' field." }, { status: 400 });
  }

  const body = new FormData();
  body.append("file", file, file.name || "upload.bin");

  const pinataRes = await fetch("https://api.pinata.cloud/pinning/pinFileToIPFS", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${jwt}`,
    },
    body,
  });

  const text = await pinataRes.text();
  if (!pinataRes.ok) {
    return NextResponse.json(
      { error: "Pinata upload failed", status: pinataRes.status, details: text },
      { status: 502 }
    );
  }

  let parsed: PinataPinResponse | null = null;
  try {
    parsed = JSON.parse(text) as PinataPinResponse;
  } catch {
    parsed = null;
  }

  if (!parsed?.IpfsHash) {
    return NextResponse.json({ error: "Unexpected Pinata response", details: text }, { status: 502 });
  }

  return NextResponse.json({ cid: parsed.IpfsHash });
}

