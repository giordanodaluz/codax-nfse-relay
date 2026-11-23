// Serviço de transmissão da CODAX para a NFS-e Nacional (API gratuita do governo).
// Roda fora da hospedagem do site porque a emissão exige conexão autenticada
// com o certificado A1 da empresa (mTLS), que o ambiente do site não suporta.
//
// Variáveis de ambiente obrigatórias:
//   CODAX_APP_URL                      endereço do site CODAX (ex.: https://pronto-launchpad-starter.lovable.app)
//   CODAX_RELAY_KEY                    chave compartilhada com a rota /api/public/nfse/relay do site
//   CODAX_CERTIFICATE_ENCRYPTION_KEY   mesma chave do cofre de certificados do site
//   NFSE_AMBIENTE                      "homologacao" (produção restrita) ou "producao"

const http = require("node:http");
const https = require("node:https");
const crypto = require("node:crypto");
const zlib = require("node:zlib");
const forge = require("node-forge");
const { DOMParser } = require("@xmldom/xmldom");
const { SignedXml } = require("xml-crypto");

const PORT = process.env.PORT || 3000;
const APP_URL = (process.env.CODAX_APP_URL || "").replace(/\/$/, "");
const RELAY_KEY = process.env.CODAX_RELAY_KEY || "";
const CERT_KEY = process.env.CODAX_CERTIFICATE_ENCRYPTION_KEY || "";
const AMBIENTE = process.env.NFSE_AMBIENTE === "producao" ? "producao" : "homologacao";

// Endpoints da Sefin Nacional NFS-e (recepção síncrona da DPS).
// Homologação = "produção restrita": emite notas de teste sem valor fiscal.
const SEFIN_BASE = {
  homologacao: "https://sefin.producaorestrita.nfse.gov.br/SefinNacional",
  producao: "https://sefin.nfse.gov.br/SefinNacional",
}[AMBIENTE];

function assertConfig() {
  if (!APP_URL || !RELAY_KEY || !CERT_KEY) {
    throw new Error("Configure CODAX_APP_URL, CODAX_RELAY_KEY e CODAX_CERTIFICATE_ENCRYPTION_KEY.");
  }
}

// --- Cofre: abre o certificado selado pelo site (AES-256-GCM, AAD = company_id) ---
function openSealedCertificate(sealedJson, companyId) {
  const sealed = JSON.parse(sealedJson);
  const key = crypto.createHash("sha256").update(CERT_KEY, "utf8").digest();
  const iv = Buffer.from(sealed.iv, "base64");
  const data = Buffer.from(sealed.ciphertext, "base64");
  const tag = data.subarray(data.length - 16);
  const ciphertext = data.subarray(0, data.length - 16);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(Buffer.from(companyId, "utf8"));
  decipher.setAuthTag(tag);
  const payload = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  return JSON.parse(payload); // { name, pfx (base64), password }
}

// --- Comunicação com o site CODAX ---
async function fetchDraft(draftId) {
  const res = await fetch(`${APP_URL}/api/public/nfse/relay?draftId=${encodeURIComponent(draftId)}`, {
    headers: { "x-relay-key": RELAY_KEY },
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `Falha ao buscar rascunho (${res.status})`);
  return body;
}

async function reportResult(draftId, result) {
  await fetch(`${APP_URL}/api/public/nfse/relay`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-relay-key": RELAY_KEY },
    body: JSON.stringify({ draftId, ...result }),
  }).catch((e) => console.error("Falha ao reportar resultado:", e.message));
}

// --- Monta a DPS (Declaração de Prestação de Serviços) no padrão nacional ---
function buildDpsXml(draft, company) {
  const cnpj = String(company.cnpj || "").replace(/\D/g, "");
  const cMun = String(draft.municipality_ibge || company.municipality_ibge || "").replace(/\D/g, "");
  // Horário de Brasília, sem milissegundos, 1 minuto no passado (o governo recusa data futura).
  const br = new Date(Date.now() - 60000 - 3 * 3600000).toISOString().slice(0, 19);
  const dhEmi = `${br}-03:00`;
  const serie = "1";
  const nDPS = String(Math.floor(Date.now() / 1000));
  const id = `DPS${cMun}2${cnpj}${serie.padStart(5, "0")}${nDPS.padStart(15, "0")}`;
  const valor = Number(draft.amount).toFixed(2);
  const docTomador = String(draft.client_doc || "").replace(/\D/g, "");
  const tomadorTag = docTomador.length === 14 ? "CNPJ" : "CPF";
  const lc = String(draft.lc116_service_code || "").replace(/\D/g, "").padStart(4, "0");
  const cTribNac = lc.length >= 6 ? lc.slice(0, 6) : `${lc}01`;
  const opSimpNac = process.env.NFSE_OP_SIMPLES || "3"; // 1 não optante, 2 MEI, 3 ME/EPP
  const regTrib = `<regTrib><opSimpNac>${opSimpNac}</opSimpNac>` +
    (opSimpNac === "3" ? `<regApTribSN>1</regApTribSN>` : "") +
    `<regEspTrib>0</regEspTrib></regTrib>`;
  return (
    `<DPS xmlns="http://www.sped.fazenda.gov.br/nfse" versao="1.00">` +
    `<infDPS Id="${id}">` +
    `<tpAmb>${AMBIENTE === "producao" ? "1" : "2"}</tpAmb>` +
    `<dhEmi>${dhEmi}</dhEmi>` +
    `<verAplic>CODAX1.0</verAplic>` +
    `<serie>${serie}</serie>` +
    `<nDPS>${nDPS}</nDPS>` +
    `<dCompet>${br.slice(0, 10)}</dCompet>` +
    `<tpEmit>1</tpEmit>` +
    `<cLocEmi>${cMun}</cLocEmi>` +
    `<prest><CNPJ>${cnpj}</CNPJ>` +
    (process.env.NFSE_SEND_IM === "1" && company.municipal_registration ? `<IM>${company.municipal_registration}</IM>` : "") +
    regTrib + `</prest>` +
    `<toma><${tomadorTag}>${docTomador}</${tomadorTag}><xNome>${escapeXml(draft.client_name)}</xNome></toma>` +
    `<serv><locPrest><cLocPrestacao>${cMun}</cLocPrestacao></locPrest>` +
    `<cServ><cTribNac>${cTribNac}</cTribNac><xDescServ>${escapeXml(draft.description)}</xDescServ></cServ></serv>` +
    `<valores><vServPrest><vServ>${valor}</vServ></vServPrest>` +
    `<trib><tribMun><tribISSQN>1</tribISSQN><tpRetISSQN>1</tpRetISSQN></tribMun>` +
    `<totTrib>${opSimpNac === "3" ? `<pTotTribSN>${draft.sn_rate != null ? Number(draft.sn_rate).toFixed(2) : (process.env.NFSE_ALIQ_SN || "6.00")}</pTotTribSN>` : `<indTotTrib>0</indTotTrib>`}</totTrib></trib></valores>` +
    `</infDPS></DPS>`
  );
}

function escapeXml(text) {
  return String(text || "").replace(/[<>&'"]/g, (c) => ({
    "<": "&lt;", ">": "&gt;", "&": "&amp;", "'": "&apos;", '"': "&quot;",
  })[c]);
}

// --- Assina a DPS com a chave privada do certificado A1 ---
function signDps(xml, pfxBase64, password) {
  const p12 = forge.pkcs12.pkcs12FromAsn1(
    forge.asn1.fromDer(forge.util.decode64(pfxBase64)),
    password,
  );
  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
  const privateKey = Object.values(keyBags).flat().find((b) => b && b.key)?.key;
  const certificate = Object.values(certBags).flat().find((b) => b && b.cert)?.cert;
  if (!privateKey || !certificate) throw new Error("Certificado sem chave privada.");
  const certPem = forge.pki.certificateToPem(certificate);
  const keyPem = forge.pki.privateKeyToPem(privateKey);
  const certDerB64 = certPem.replace(/-----(BEGIN|END) CERTIFICATE-----|\s/g, "");

  const sig = new SignedXml({
    privateKey: keyPem,
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    canonicalizationAlgorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    publicCert: certPem,
    getKeyInfoContent: () => `<X509Data><X509Certificate>${certDerB64}</X509Certificate></X509Data>`,
  });
  sig.addReference({
    xpath: "//*[local-name(.)='infDPS']",
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    ],
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    uri: `#${xml.match(/Id="([^"]+)"/)[1]}`,
  });
  sig.computeSignature(xml, {
    location: { reference: "//*[local-name(.)='DPS']", action: "append" },
  });
  return `<?xml version="1.0" encoding="UTF-8"?>${sig.getSignedXml()}`;
}

// --- Envia à Sefin Nacional com conexão autenticada pelo certificado (mTLS) ---
function transmitToSefin(signedXml, pfxBase64, password) {
  const gzipB64 = zlib.gzipSync(Buffer.from(signedXml, "utf8")).toString("base64");
  const agent = new https.Agent({
    pfx: Buffer.from(pfxBase64, "base64"),
    passphrase: password,
    rejectUnauthorized: true,
  });
  const body = JSON.stringify({ dpsXmlGZipB64: gzipB64 });
  const url = new URL(`${SEFIN_BASE}/nfse`);
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: url.hostname,
        path: url.pathname,
        method: "POST",
        agent,
        headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) },
        timeout: 60000,
      },
      (res) => {
        let raw = "";
        res.on("data", (chunk) => (raw += chunk));
        res.on("end", () => resolve({ status: res.statusCode, body: raw }));
      },
    );
    req.on("timeout", () => req.destroy(new Error("Tempo esgotado na conexão com o governo.")));
    req.on("error", reject);
    req.end(body);
  });
}

function extractAuthorizedNumber(xml) {
  const doc = new DOMParser().parseFromString(xml, "text/xml");
  const nodes = doc.getElementsByTagName("nNFSe");
  return nodes.length > 0 ? nodes[0].textContent : null;
}

// --- Fluxo completo de emissão ---
async function emitir(draftId) {
  const { draft, company, sealedCertificate } = await fetchDraft(draftId);
  const cert = openSealedCertificate(sealedCertificate, company.id);
  const dps = buildDpsXml(draft, company);
  const signed = signDps(dps, cert.pfx, cert.password);
  const res = await transmitToSefin(signed, cert.pfx, cert.password);
  if (res.status >= 200 && res.status < 300) {
    const parsed = JSON.parse(res.body);
    // A Sefin devolve a NFS-e autorizada compactada (gzip + base64).
    const nfseXml = parsed.nfseXmlGZipB64
      ? zlib.gunzipSync(Buffer.from(parsed.nfseXmlGZipB64, "base64")).toString("utf8")
      : "";
    const number = extractAuthorizedNumber(nfseXml) || parsed.nNFSe || null;
    await reportResult(draftId, {
      status: "authorized",
      number,
      accessKey: parsed.chaveAcesso || "",
    });
    await baixarDanfse(draftId).catch((e) => console.error("DANFSe:", e.message));
    return { ok: true, number, chaveAcesso: parsed.chaveAcesso || null };
  }
  await reportResult(draftId, { status: "rejected", message: res.body.slice(0, 500) });
  return { ok: false, status: res.status, body: res.body.slice(0, 500) };
}

// --- DANFSe: PDF oficial da nota, baixado do ADN com o certificado (mTLS) ---
const ADN_BASE = {
  homologacao: "https://adn.producaorestrita.nfse.gov.br",
  producao: "https://adn.nfse.gov.br",
}[AMBIENTE];

function getWithCert(urlStr, pfxBase64, password) {
  const agent = new https.Agent({ pfx: Buffer.from(pfxBase64, "base64"), passphrase: password });
  const url = new URL(urlStr);
  return new Promise((resolve, reject) => {
    const req = https.request(
      { hostname: url.hostname, path: url.pathname, method: "GET", agent, headers: { accept: "*/*" }, timeout: 60000 },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
      },
    );
    req.on("timeout", () => req.destroy(new Error("Tempo esgotado ao baixar o DANFSe.")));
    req.on("error", reject);
    req.end();
  });
}

async function infoNota(draftId) {
  const res = await fetch(`${APP_URL}/api/public/nfse/relay?draftId=${encodeURIComponent(draftId)}&purpose=danfse`, {
    headers: { "x-relay-key": RELAY_KEY },
  });
  const info = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(info.error || `Falha ao buscar nota (${res.status})`);
  return { info, cert: openSealedCertificate(info.sealedCertificate, info.company.id) };
}

// XML oficial da NFS-e autorizada, consultado na Sefin Nacional pela chave.
async function baixarXml(draftId) {
  const { info, cert } = await infoNota(draftId);
  const r = await getWithCert(`${SEFIN_BASE}/nfse/${info.accessKey}`, cert.pfx, cert.password);
  if (r.status !== 200) throw new Error(`Consulta da nota falhou (${r.status}): ${r.body.subarray(0, 200)}`);
  const j = JSON.parse(r.body.toString("utf8"));
  return zlib.gunzipSync(Buffer.from(j.nfseXmlGZipB64, "base64")).toString("utf8");
}

// --- DANFSe gerado pela CODAX a partir do XML oficial (a API do governo foi suspensa pela NT 008) ---
function gerarDanfsePdf(xml) {
  const PDFDocument = require("pdfkit");
  const doc0 = new DOMParser().parseFromString(xml, "text/xml");
  const first = (root, tag) => { const n = root.getElementsByTagName(tag); return n.length ? n[0].textContent : ""; };
  const inf = doc0.getElementsByTagName("infNFSe")[0];
  const emit = doc0.getElementsByTagName("emit")[0];
  const toma = doc0.getElementsByTagName("toma")[0];
  const chave = (inf.getAttribute("Id") || "").replace(/^NFS/, "");
  const fmtDoc = (d) => d.length === 14 ? d.replace(/(\d{2})(\d{3})(\d{3})(\d{4})(\d{2})/, "$1.$2.$3/$4-$5")
    : d.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, "$1.$2.$3-$4");
  const brl = (v) => "R$ " + Number(v || 0).toFixed(2).replace(".", ",");
  const dt = (v) => v ? v.slice(8, 10) + "/" + v.slice(5, 7) + "/" + v.slice(0, 4) + (v.length > 10 ? " " + v.slice(11, 16) : "") : "";
  const end = emit.getElementsByTagName("enderNac")[0];
  const endereco = end ? `${first(end, "xLgr")}, ${first(end, "nro")} - ${first(end, "xBairro")} - ${first(inf, "xLocEmi")}/${first(end, "UF")} - CEP ${first(end, "CEP")}` : "";
  return new Promise((resolve) => {
    const doc = new PDFDocument({ size: "A4", margin: 40 });
    const chunks = [];
    doc.on("data", (c) => chunks.push(c));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    const W = 515;
    const box = (title, rows) => {
      const y = doc.y;
      doc.fontSize(8).font("Helvetica-Bold").fillColor("#333").text(title.toUpperCase(), 46, y + 6);
      doc.font("Helvetica").fontSize(9).fillColor("#000");
      rows.forEach(([k, v]) => { doc.font("Helvetica-Bold").text(k + ": ", 46, doc.y + 2, { continued: true, width: W - 12 }).font("Helvetica").text(v || "-"); });
      const h = doc.y - y + 6;
      doc.rect(40, y, W, h).stroke("#999");
      doc.y = y + h + 6;
    };
    doc.font("Helvetica-Bold").fontSize(14).text("DANFSe - Documento Auxiliar da NFS-e", { align: "center" });
    doc.font("Helvetica").fontSize(9).text("Nota Fiscal de Serviço Eletrônica - Padrão Nacional", { align: "center" }).moveDown(0.8);
    box("Identificação", [
      ["Número da NFS-e", first(inf, "nNFSe")], ["Competência", dt(first(inf, "dCompet"))],
      ["Emissão da DPS", dt(first(inf, "dhEmi"))], ["Autorização", dt(first(inf, "dhProc"))],
      ["Série / Nº DPS", `${first(inf, "serie")} / ${first(inf, "nDPS")}`], ["Chave de acesso", chave],
    ]);
    box("Prestador", [
      ["Razão social", first(emit, "xNome")], ["CNPJ", fmtDoc(first(emit, "CNPJ"))],
      ["Endereço", endereco], ["E-mail", first(emit, "email")], ["Telefone", first(emit, "fone")],
    ]);
    box("Tomador", [
      ["Nome", toma ? first(toma, "xNome") : ""], ["CPF/CNPJ", toma ? fmtDoc(first(toma, "CPF") || first(toma, "CNPJ")) : ""],
    ]);
    box("Serviço", [
      ["Código de tributação nacional", `${first(inf, "cTribNac")} - ${first(inf, "xTribNac")}`],
      ["Local da prestação", first(inf, "xLocPrestacao")], ["Município de incidência", first(inf, "xLocIncid")],
      ["Descrição", first(inf, "xDescServ")],
    ]);
    box("Valores", [
      ["Valor do serviço", brl(first(inf, "vServ"))], ["Valor líquido", brl(first(inf, "vLiq"))],
      ["Tributos aproximados (Simples Nacional)", first(inf, "pTotTribSN") ? first(inf, "pTotTribSN") + "%" : "-"],
    ]);
    doc.moveDown(0.5).fontSize(8).fillColor("#333").text(
      "Consulte a autenticidade em https://www.nfse.gov.br/ConsultaPublica informando a chave de acesso acima.", { align: "center" });
    doc.end();
  });
}

async function baixarDanfse(draftId) {
  const xml = await baixarXml(draftId);
  const pdf = { body: await gerarDanfsePdf(xml) };
  const up = await fetch(`${APP_URL}/api/public/nfse/relay`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-relay-key": RELAY_KEY },
    body: JSON.stringify({ draftId, pdfBase64: pdf.body.toString("base64") }),
  });
  if (!up.ok) throw new Error(`Falha ao guardar PDF (${up.status})`);
  return { ok: true };
}

// --- HTTP ---
// Consulta na Sefin Nacional se há evento de cancelamento (101101) ou cancelamento por substituição (105102).
async function consultarSituacao(draftId) {
  const { info, cert } = await infoNota(draftId);
  for (const tipo of ["101101", "105102"]) {
    const r = await getWithCert(`${SEFIN_BASE}/nfse/${info.accessKey}/eventos/${tipo}/1`, cert.pfx, cert.password);
    if (r.status === 200) {
      await reportResult(draftId, { status: "cancelled", accessKey: info.accessKey });
      return { situacao: "cancelada", evento: tipo };
    }
    if (r.status !== 404) throw new Error(`Consulta de eventos falhou (${r.status}): ${r.body.subarray(0, 200)}`);
  }
  return { situacao: "valida" };
}

const server = http.createServer(async (req, res) => {
  const send = (code, obj) => {
    res.writeHead(code, { "content-type": "application/json" });
    res.end(JSON.stringify(obj));
  };
  try {
    assertConfig();
    if (req.method === "GET" && req.url === "/saude") {
      return send(200, { ok: true, ambiente: AMBIENTE, sefin: SEFIN_BASE });
    }
    if (req.method === "POST" && req.url === "/emitir") {
      if (req.headers["x-relay-key"] !== RELAY_KEY) return send(401, { error: "Não autorizado" });
      let raw = "";
      for await (const chunk of req) raw += chunk;
      const { draftId } = JSON.parse(raw || "{}");
      if (!draftId) return send(400, { error: "draftId ausente" });
      const result = await emitir(draftId);
      return send(result.ok ? 200 : 502, result);
    }
    if (req.method === "POST" && req.url === "/xml") {
      if (req.headers["x-relay-key"] !== RELAY_KEY) return send(401, { error: "Não autorizado" });
      let raw = "";
      for await (const chunk of req) raw += chunk;
      const { draftId } = JSON.parse(raw || "{}");
      return send(200, { xml: await baixarXml(draftId) });
    }
    if (req.method === "POST" && req.url === "/situacao") {
      if (req.headers["x-relay-key"] !== RELAY_KEY) return send(401, { error: "Não autorizado" });
      let raw = "";
      for await (const chunk of req) raw += chunk;
      const { draftId } = JSON.parse(raw || "{}");
      if (!draftId) return send(400, { error: "draftId ausente" });
      return send(200, await consultarSituacao(draftId));
    }
    if (req.method === "POST" && req.url === "/danfse") {
      if (req.headers["x-relay-key"] !== RELAY_KEY) return send(401, { error: "Não autorizado" });
      let raw = "";
      for await (const chunk of req) raw += chunk;
      const { draftId } = JSON.parse(raw || "{}");
      if (!draftId) return send(400, { error: "draftId ausente" });
      return send(200, await baixarDanfse(draftId));
    }
    return send(404, { error: "Rota inexistente" });
  } catch (e) {
    console.error(e);
    return send(500, { error: e.message });
  }
});

server.listen(PORT, () => console.log(`codax-nfse-relay ouvindo na porta ${PORT} (${AMBIENTE})`));
