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

// --- Integra Contador (Serpro): procurações e DAS do Simples Nacional ---
// O contratante é o escritório (G L Negócios); a autenticação usa o e-CNPJ dele (mTLS).
const SERPRO_AUTH = "https://autenticacao.sapi.serpro.gov.br/authenticate";
const SERPRO_API = "https://gateway.apiserpro.serpro.gov.br/integra-contador/v1";
let serproToken = null; // { access, jwt, until }

function requestWithCert(urlStr, { method = "POST", headers = {}, body = "" }, pfxBase64, password) {
  const agent = new https.Agent({ pfx: Buffer.from(pfxBase64, "base64"), passphrase: password });
  const url = new URL(urlStr);
  return new Promise((resolve, reject) => {
    const req = https.request({ hostname: url.hostname, path: url.pathname + url.search, method, agent, headers: { ...headers, "content-length": Buffer.byteLength(body) }, timeout: 60000 }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("timeout", () => req.destroy(new Error("Tempo esgotado no Serpro.")));
    req.on("error", reject);
    req.end(body);
  });
}

async function serproContext() {
  const res = await fetch(`${APP_URL}/api/public/nfse/relay?purpose=serpro`, { headers: { "x-relay-key": RELAY_KEY } });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `Falha ao buscar credenciais (${res.status})`);
  const cert = openSealedCertificate(body.sealedCertificate, body.officeCompanyId);
  return { ...body, cert };
}

async function serproAuth(ctx) {
  if (serproToken && serproToken.until > Date.now() + 60000) return serproToken;
  const basic = Buffer.from(`${ctx.consumerKey}:${ctx.consumerSecret}`).toString("base64");
  const r = await requestWithCert(SERPRO_AUTH, {
    headers: { authorization: `Basic ${basic}`, "role-type": "TERCEIROS", "content-type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials",
  }, ctx.cert.pfx, ctx.cert.password);
  if (r.status !== 200) throw new Error(`Serpro recusou a autenticação [${r.status}]: ${r.text.slice(0, 300)}`);
  const j = JSON.parse(r.text);
  serproToken = { access: j.access_token, jwt: j.jwt_token, until: Date.now() + Number(j.expires_in || 2000) * 1000 };
  return serproToken;
}

async function serproCall(ctx, rota, contribuinte, idSistema, idServico, dados) {
  const tok = await serproAuth(ctx);
  const office = { numero: ctx.officeCnpj, tipo: 2 };
  const doc = String(contribuinte).replace(/\D/g, "");
  const payload = {
    contratante: office, autorPedidoDados: office,
    contribuinte: { numero: doc, tipo: doc.length === 11 ? 1 : 2 },
    pedidoDados: { idSistema, idServico, versaoSistema: "1.0", dados: JSON.stringify(dados) },
  };
  const r = await requestWithCert(`${SERPRO_API}/${rota}`, {
    headers: { authorization: `Bearer ${tok.access}`, jwt_token: tok.jwt, "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(payload),
  }, ctx.cert.pfx, ctx.cert.password);
  let j = {};
  try { j = JSON.parse(r.text); } catch { j = { raw: r.text.slice(0, 500) }; }
  return { status: r.status, body: j };
}

async function serpro(op, contribuinte, periodo, dados) {
  const ctx = await serproContext();
  if (op === "procuracao") {
    const doc = String(contribuinte).replace(/\D/g, "");
    const r = await serproCall(ctx, "Consultar", contribuinte, "PROCURACOES", "OBTERPROCURACAO41",
      { outorgante: doc, tipoOutorgante: doc.length === 11 ? "1" : "2", outorgado: ctx.officeCnpj, tipoOutorgado: "2" });
    let lista = [];
    try { lista = JSON.parse(r.body.dados || "[]"); } catch {}
    const pgdas = (Array.isArray(lista) ? lista : []).find((p) => (p.sistemas || []).some((s) => /PGDAS/i.test(s)));
    return { ok: r.status === 200, status: r.status, authorized: Boolean(pgdas), expira: pgdas?.dtexpiracao || null, mensagens: r.body.mensagens || [] };
  }
  if (op === "das") {
    const r = await serproCall(ctx, "Emitir", contribuinte, "PGDASD", "GERARDAS12", { periodoApuracao: periodo });
    let dados = null;
    try { dados = JSON.parse(r.body.dados || "null"); } catch {}
    const item = Array.isArray(dados) ? dados[0] : dados;
    const det = item?.detalhamento?.[0] || item?.detalhamento || {};
    return {
      ok: r.status === 200 && Boolean(item?.pdf), status: r.status, pdf: item?.pdf || null,
      total: det?.valores?.total ?? null, vencimento: det?.dataVencimento || det?.dataLimiteAcolhimento || null,
      mensagens: r.body.mensagens || [],
    };
  }
  if (op === "pgdas") {
    // Declaração mensal (TRANSDECLARACAO11); indicadorTransmissao=false só calcula.
    const r = await serproCall(ctx, "Declarar", contribuinte, "PGDASD", "TRANSDECLARACAO11", dados);
    let out = null;
    try { out = JSON.parse(r.body.dados || "null"); } catch {}
    return { ok: r.status === 200, status: r.status, dados: out, mensagens: r.body.mensagens || [] };
  }
  throw new Error("Operação inválida");
}


// --- eSocial (lote assíncrono, SOAP + mTLS, assinatura do escritório como procurador) ---
const ESOCIAL_HOST = process.env.ESOCIAL_AMBIENTE === "producao" ? "https://webservices.esocial.gov.br" : "https://webservices.producaorestrita.esocial.gov.br";
function signEsocialEvent(xml, cert) {
  const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(forge.util.decode64(cert.pfx)), cert.password);
  const key = Object.values(p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })).flat().find((b) => b && b.key)?.key;
  const crt = Object.values(p12.getBags({ bagType: forge.pki.oids.certBag })).flat().find((b) => b && b.cert)?.cert;
  const certPem = forge.pki.certificateToPem(crt);
  const der = certPem.replace(/-----(BEGIN|END) CERTIFICATE-----|\s/g, "");
  const sig = new SignedXml({
    privateKey: forge.pki.privateKeyToPem(key), publicCert: certPem,
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    canonicalizationAlgorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    getKeyInfoContent: () => `<X509Data><X509Certificate>${der}</X509Certificate></X509Data>`,
  });
  sig.addReference({ xpath: "/*", uri: "", isEmptyUri: true, digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"] });
  sig.computeSignature(xml, { location: { reference: "/*", action: "append" } });
  return sig.getSignedXml();
}
function soap(action, inner) {
  return `<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header/><soapenv:Body>${inner}</soapenv:Body></soapenv:Envelope>`;
}
const tag = (xml, name) => { const m = xml.match(new RegExp(`<(?:\\w+:)?${name}[^>]*>([\\s\\S]*?)</(?:\\w+:)?${name}>`)); return m ? m[1] : null; };

// eSocial (IIS) pede o certificado por renegociação TLS 1.2 e exige a cadeia completa.
function esocialRequest(urlStr, headers, body, cert, method = "POST") {
  const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(forge.util.decode64(cert.pfx)), cert.password);
  const key = Object.values(p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })).flat().find((b) => b && b.key)?.key;
  const certs = Object.values(p12.getBags({ bagType: forge.pki.oids.certBag })).flat().filter((b) => b && b.cert).map((b) => b.cert);
  const leaf = certs.find((c) => !c.isIssuer(c) && !certs.some((o) => o !== c && c.isIssuer(o))) || certs[0];
  const chain = [leaf, ...certs.filter((c) => c !== leaf)].map((c) => forge.pki.certificateToPem(c)).join("");
  const agent = new https.Agent({ key: forge.pki.privateKeyToPem(key), cert: chain, maxVersion: "TLSv1.2", keepAlive: false });
  const url = new URL(urlStr);
  return new Promise((resolve, reject) => {
    const req = https.request({ hostname: url.hostname, path: url.pathname + url.search, method, agent, headers: { ...headers, "content-length": Buffer.byteLength(body) }, timeout: 90000 }, (res) => {
      const chunks = []; res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("timeout", () => req.destroy(new Error("Tempo esgotado no eSocial.")));
    req.on("error", reject); req.end(body);
  });
}
async function esocial(op, empregador, eventos, protocolo) {
  const ctx = await serproContext();
  const office = String(ctx.officeCnpj).replace(/\D/g, "");
  if (op === "diag") {
    const out = {};
    for (const [n, u] of Object.entries({ envio: `${ESOCIAL_HOST}/servicos/empregador/enviarloteeventos/WsEnviarLoteEventos.svc?singleWsdl`, consulta: `${ESOCIAL_HOST}/servicos/empregador/consultarloteeventos/WsConsultarLoteEventos.svc?singleWsdl` })) {
      const r = await esocialRequest(u, {}, "", ctx.cert, "GET").catch((e) => ({ status: 0, text: e.message }));
      out[n] = { status: r.status, head: r.text.slice(0, 200) };
    }
    const ip = await fetch("https://ipinfo.io/json").then((r) => r.json()).catch(() => ({}));
    out.origem = ip.country;
    return out;
  }
  if (op === "enviar") {
    const ev = eventos.map((e) => `<evento Id="${e.id}">${signEsocialEvent(e.xml, ctx.cert)}</evento>`).join("");
    const body = soap("", `<v1:EnviarLoteEventos xmlns:v1="http://www.esocial.gov.br/servicos/empregador/lote/eventos/envio/v1_1_0"><v1:loteEventos><eSocial xmlns="http://www.esocial.gov.br/schema/lote/eventos/envio/v1_1_1"><envioLoteEventos grupo="${eventos[0].grupo || 1}"><ideEmpregador><tpInsc>1</tpInsc><nrInsc>${empregador.slice(0, 8)}</nrInsc></ideEmpregador><ideTransmissor><tpInsc>1</tpInsc><nrInsc>${office}</nrInsc></ideTransmissor><eventos>${ev}</eventos></envioLoteEventos></eSocial></v1:loteEventos></v1:EnviarLoteEventos>`);
    const r = await esocialRequest(`${ESOCIAL_HOST}/servicos/empregador/enviarloteeventos/WsEnviarLoteEventos.svc`,  { "content-type": "text/xml; charset=utf-8", soapaction: "http://www.esocial.gov.br/servicos/empregador/lote/eventos/envio/v1_1_0/ServicoEnviarLoteEventos/EnviarLoteEventos" }, body, ctx.cert);
    return { status: r.status, cdResposta: tag(r.text, "cdResposta"), descResposta: tag(r.text, "descResposta"), protocolo: tag(r.text, "protocoloEnvio"), raw: r.text.slice(0, 3000) };
  }
  if (op === "consultar") {
    const body = soap("", `<v1:ConsultarLoteEventos xmlns:v1="http://www.esocial.gov.br/servicos/empregador/lote/eventos/envio/consulta/retornoProcessamento/v1_0_0"><v1:consulta><eSocial xmlns="http://www.esocial.gov.br/schema/lote/eventos/envio/consulta/retornoProcessamento/v1_0_0"><consultaLoteEventos><protocoloEnvio>${String(protocolo).replace(/[^\d.]/g, "")}</protocoloEnvio></consultaLoteEventos></eSocial></v1:consulta></v1:ConsultarLoteEventos>`);
    const r = await esocialRequest(`${ESOCIAL_HOST}/servicos/empregador/consultarloteeventos/WsConsultarLoteEventos.svc`,  { "content-type": "text/xml; charset=utf-8", soapaction: "http://www.esocial.gov.br/servicos/empregador/lote/eventos/envio/consulta/retornoProcessamento/v1_0_0/ServicoConsultarLoteEventos/ConsultarLoteEventos" }, body, ctx.cert);
    const t = r.text.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"');
    const eventosRet = [...t.matchAll(/<evento Id="([^"]+)"[\s\S]*?<\/evento>/g)].map((m) => ({
      id: m[1], cdResposta: tag(m[0], "cdResposta"), descResposta: tag(m[0], "descResposta"), recibo: tag(m[0], "nrRecibo"),
      ocorrencias: [...m[0].matchAll(/<ocorrencia>([\s\S]*?)<\/ocorrencia>/g)].map((o) => `${tag(o[1], "codigo")}: ${tag(o[1], "descricao")} ${tag(o[1], "localizacao") || ""}`.trim()),
    }));
    return { status: r.status, cdResposta: tag(t, "cdResposta"), descResposta: tag(t, "descResposta"), eventos: eventosRet, raw: eventosRet.length ? undefined : t.slice(0, 3000) };
  }
  throw new Error("Operação inválida");
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
    if (req.method === "POST" && req.url === "/serpro") {
      if (req.headers["x-relay-key"] !== RELAY_KEY) return send(401, { error: "Não autorizado" });
      let raw = "";
      for await (const chunk of req) raw += chunk;
      const { op, contribuinte, periodo, dados } = JSON.parse(raw || "{}");
      if (!contribuinte) return send(400, { error: "contribuinte ausente" });
      if (op === "das" && !/^\d{6}$/.test(String(periodo))) return send(400, { error: "periodo AAAAMM" });
      if (op === "pgdas" && (!dados || typeof dados !== "object")) return send(400, { error: "dados ausentes" });
      return send(200, await serpro(op, contribuinte, periodo, dados));
    }
    if (req.method === "POST" && req.url === "/esocial") {
      if (req.headers["x-relay-key"] !== RELAY_KEY) return send(401, { error: "Não autorizado" });
      let raw = "";
      for await (const chunk of req) raw += chunk;
      const { op, empregador, eventos, protocolo } = JSON.parse(raw || "{}");
      const emp = String(empregador || "").replace(/\D/g, "");
      if (emp.length !== 14) return send(400, { error: "empregador CNPJ" });
      if (op === "enviar" && (!Array.isArray(eventos) || !eventos.length || eventos.length > 50 || eventos.some((e) => !/^ID\d{34}$/.test(e.id) || typeof e.xml !== "string"))) return send(400, { error: "eventos inválidos" });
      return send(200, await esocial(op, emp, eventos, protocolo));
    }
    return send(404, { error: "Rota inexistente" });
  } catch (e) {
    console.error(e);
    return send(500, { error: e.message });
  }
});

server.listen(PORT, () => console.log(`codax-nfse-relay ouvindo na porta ${PORT} (${AMBIENTE})`));
