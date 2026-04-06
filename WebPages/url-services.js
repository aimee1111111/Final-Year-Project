import {
  GOOGLE_API_KEY,
  VIRUSTOTAL_API_KEY,
} from "./config.js";

export async function checkGoogleSafeBrowsing(url) {
  try {
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "threatcheck", clientVersion: "1.0" },
          threatInfo: {
            threatTypes: [
              "MALWARE",
              "SOCIAL_ENGINEERING",
              "UNWANTED_SOFTWARE",
              "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }]
          }
        })
      }
    );

    if (!response.ok) {
      console.error(`Google Safe Browsing HTTP error: ${response.status}`);
      return {
        service: "Google Safe Browsing",
        error: true,
        details: `HTTP ${response.status}`
      };
    }

    const data = await response.json();

    return {
      service: "Google Safe Browsing",
      safe: !data.matches || data.matches.length === 0,
      threats: data.matches ? data.matches.map((m) => m.threatType) : [],
      matches: data.matches || null
    };
  } catch (err) {
    console.error("Google Safe Browsing error:", err);
    return {
      service: "Google Safe Browsing",
      error: true,
      details: err.message
    };
  }
}

export async function checkVirusTotal(url) {
  try {
    const submitResponse = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: `url=${encodeURIComponent(url)}`
    });

    if (!submitResponse.ok) {
      throw new Error(`VirusTotal API error: ${submitResponse.status}`);
    }

    const submitData = await submitResponse.json();
    const analysisId = submitData?.data?.id;

    const analysisResponse = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        headers: { "x-apikey": VIRUSTOTAL_API_KEY }
      }
    );

    if (!analysisResponse.ok) {
      throw new Error(`VirusTotal analysis error: ${analysisResponse.status}`);
    }

    const analysisData = await analysisResponse.json();
    const stats = analysisData?.data?.attributes?.stats || {};

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;

    return {
      service: "VirusTotal",
      safe: malicious === 0 && suspicious === 0,
      malicious,
      suspicious,
      undetected: stats.undetected || 0,
      harmless: stats.harmless || 0,
      timeout: stats.timeout || 0,
      failure: stats.failure || 0,
      typeUnsupported: stats.type_unsupported || 0,
      totalEngines: Object.values(stats)
        .filter((v) => typeof v === "number")
        .reduce((a, b) => a + b, 0)
    };
  } catch (err) {
    console.error("VirusTotal error:", err);
    return {
      service: "VirusTotal",
      error: true,
      details: err.message
    };
  }
}

export async function checkPhishAPIBackend(url) {
  try {
    const response = await fetch("http://127.0.0.1:5000/api/checkphish", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      throw new Error(`CheckPhish backend error: ${response.status}`);
    }

    return await response.json();
  } catch (err) {
    console.error("CheckPhish backend error:", err);
    return {
      service: "CheckPhish",
      error: true,
      details: err.message
    };
  }
}

export async function checkPhishStats(url) {
  try {
    const response = await fetch(
      `http://127.0.0.1:5000/api/phishstats?url=${encodeURIComponent(url)}`
    );

    if (!response.ok) {
      throw new Error(`PhishStats backend error: ${response.status}`);
    }

    return await response.json();
  } catch (err) {
    console.error("PhishStats error:", err);
    return {
      service: "PhishStats",
      error: true,
      details: err.message
    };
  }
}

export async function checkDnsHealth(url) {
  try {
    const host = new URL(url).hostname;

    async function dohCF(type) {
      const res = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`,
        { headers: { Accept: "application/dns-json" } }
      );
      if (!res.ok) throw new Error(`CF DoH ${type} HTTP ${res.status}`);
      return res.json();
    }

    async function dohGoogle(type) {
      const res = await fetch(
        `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=${type}`
      );
      if (!res.ok) throw new Error(`Google DoH ${type} HTTP ${res.status}`);
      return res.json();
    }

    async function doh(type) {
      try {
        return await dohCF(type);
      } catch {
        return await dohGoogle(type);
      }
    }

    const [a, aaaa, mx] = await Promise.allSettled([
      doh("A"),
      doh("AAAA"),
      doh("MX")
    ]);

    const getAnswers = (r) =>
      r.status === "fulfilled" && Array.isArray(r.value?.Answer)
        ? r.value.Answer
        : [];

    const A_records = getAnswers(a);
    const AAAA_records = getAnswers(aaaa);
    const MX_records = getAnswers(mx);

    const A = A_records.map((x) => x.data);
    const AAAA = AAAA_records.map((x) => x.data);
    const MX = MX_records.map((x) => x.data.split(" ").pop());

    return {
      service: "DNS (DoH)",
      safe: A.length + AAAA.length > 0,
      hasA: A.length > 0,
      hasAAAA: AAAA.length > 0,
      hasMX: MX.length > 0,
      ips: [...A, ...AAAA].slice(0, 5),
      details: `A:${A.length} AAAA:${AAAA.length} MX:${MX.length}`,
      rawA: A_records.length ? A_records : null,
      rawAAAA: AAAA_records.length ? AAAA_records : null,
      rawMX: MX_records.length ? MX_records : null,
      host
    };
  } catch (e) {
    console.error("DoH error:", e);
    return {
      service: "DNS (DoH)",
      error: true,
      details: e.message
    };
  }
}