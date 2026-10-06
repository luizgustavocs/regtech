import type { OwaspId } from "./types.ts";

export interface OwaspCategory {
  id: OwaspId;
  name: string;
  plain: string;
  /** Whether an external, unauthenticated look at the site can say anything about it. */
  externallyVisible: "sim" | "parcial" | "nao";
}

/** OWASP Top 10:2025, explained for people who never read the OWASP site. */
export const OWASP: Record<OwaspId, OwaspCategory> = {
  A01: {
    id: "A01",
    name: "Broken Access Control",
    plain: "Gente acessando o que não deveria: dados de outros usuários, páginas de admin, tabelas abertas.",
    externallyVisible: "parcial",
  },
  A02: {
    id: "A02",
    name: "Security Misconfiguration",
    plain: "Configurações esquecidas: arquivos secretos públicos, proteções do navegador desligadas, mensagens de erro reveladoras.",
    externallyVisible: "sim",
  },
  A03: {
    id: "A03",
    name: "Software Supply Chain Failures",
    plain: "Bibliotecas e pacotes de terceiros desatualizados ou carregados sem verificação.",
    externallyVisible: "parcial",
  },
  A04: {
    id: "A04",
    name: "Cryptographic Failures",
    plain: "Dados trafegando sem criptografia (sem HTTPS) ou protegidos de forma fraca.",
    externallyVisible: "sim",
  },
  A05: {
    id: "A05",
    name: "Injection",
    plain: "Alguém digita um código malicioso num campo e o seu sistema executa (SQL injection, XSS).",
    externallyVisible: "parcial",
  },
  A06: {
    id: "A06",
    name: "Insecure Design",
    plain: "Falhas na lógica do produto, como permitir resetar senha sem verificação. Só dá para ver olhando o código.",
    externallyVisible: "nao",
  },
  A07: {
    id: "A07",
    name: "Authentication Failures",
    plain: "Login fraco, sessões mal protegidas, senhas e chaves de API vazadas.",
    externallyVisible: "parcial",
  },
  A08: {
    id: "A08",
    name: "Software or Data Integrity Failures",
    plain: "Código ou dados que o seu site confia sem checar se foram adulterados.",
    externallyVisible: "parcial",
  },
  A09: {
    id: "A09",
    name: "Security Logging & Alerting Failures",
    plain: "Ninguém fica sabendo quando algo dá errado: sem logs, sem alertas.",
    externallyVisible: "nao",
  },
  A10: {
    id: "A10",
    name: "Mishandling of Exceptional Conditions",
    plain: "Quando algo quebra, o sistema mostra detalhes internos ou falha de um jeito inseguro.",
    externallyVisible: "parcial",
  },
};

export const OWASP_IDS = Object.keys(OWASP) as OwaspId[];

/** CWE → OWASP 2025, used to classify ZAP alerts that have no dedicated explanation. */
const CWE_TO_OWASP: Record<string, OwaspId> = {
  "22": "A01", "23": "A01", "35": "A01", "59": "A01", "200": "A01", "201": "A01", "219": "A01",
  "264": "A01", "275": "A01", "284": "A01", "285": "A01", "352": "A01", "359": "A01", "425": "A01",
  "441": "A01", "497": "A01", "538": "A01", "540": "A01", "548": "A01", "552": "A01", "566": "A01",
  "601": "A01", "639": "A01", "651": "A01", "668": "A01", "706": "A01", "862": "A01", "863": "A01",
  "913": "A01", "918": "A01", "922": "A01", "1275": "A01",
  "2": "A02", "11": "A02", "13": "A02", "15": "A02", "16": "A02", "260": "A02", "315": "A02",
  "520": "A02", "525": "A02", "526": "A02", "537": "A02", "541": "A02", "547": "A02", "611": "A02",
  "614": "A02", "693": "A02", "756": "A02", "776": "A02", "942": "A02", "1004": "A02", "1021": "A02",
  "1032": "A02", "1173": "A02", "615": "A02",
  "937": "A03", "1035": "A03", "1104": "A03", "1395": "A03", "1357": "A03", "477": "A03",
  "261": "A04", "296": "A04", "310": "A04", "311": "A04", "319": "A04", "321": "A04", "322": "A04",
  "323": "A04", "324": "A04", "325": "A04", "326": "A04", "327": "A04", "328": "A04", "329": "A04",
  "330": "A04", "331": "A04", "335": "A04", "336": "A04", "337": "A04", "338": "A04", "340": "A04",
  "347": "A04", "523": "A04", "720": "A04", "757": "A04", "759": "A04", "760": "A04", "780": "A04",
  "818": "A04", "916": "A04",
  "20": "A05", "74": "A05", "75": "A05", "77": "A05", "78": "A05", "79": "A05", "80": "A05",
  "83": "A05", "87": "A05", "88": "A05", "89": "A05", "90": "A05", "91": "A05", "93": "A05",
  "94": "A05", "95": "A05", "96": "A05", "97": "A05", "98": "A05", "99": "A05", "113": "A05",
  "116": "A05", "138": "A05", "184": "A05", "470": "A05", "471": "A05", "564": "A05", "610": "A05",
  "643": "A05", "644": "A05", "652": "A05", "917": "A05",
  "73": "A06", "183": "A06", "209": "A10", "213": "A06", "235": "A06", "256": "A06", "257": "A06",
  "266": "A06", "269": "A06", "280": "A06", "312": "A06", "313": "A06", "316": "A06",
  "419": "A06", "430": "A06", "434": "A06", "444": "A06", "451": "A06", "472": "A06", "501": "A06",
  "522": "A06", "539": "A06", "579": "A06", "598": "A06", "602": "A06", "642": "A06",
  "646": "A06", "650": "A06", "653": "A06", "656": "A06", "657": "A06", "799": "A06", "807": "A06",
  "840": "A06", "841": "A06", "927": "A06",
  "255": "A07", "259": "A07", "287": "A07", "288": "A07", "290": "A07", "294": "A07", "295": "A07",
  "297": "A07", "300": "A07", "302": "A07", "304": "A07", "306": "A07", "307": "A07", "346": "A07",
  "384": "A07", "521": "A07", "613": "A07", "620": "A07", "640": "A07", "798": "A07", "940": "A07",
  "1216": "A07",
  "345": "A08", "353": "A08", "426": "A08", "494": "A08", "502": "A08", "565": "A08", "784": "A08",
  "829": "A08", "830": "A08", "915": "A08",
  "117": "A09", "223": "A09", "532": "A09", "778": "A09",
  "248": "A10", "252": "A10", "390": "A10", "391": "A10", "394": "A10", "396": "A10", "397": "A10",
  "460": "A10", "476": "A10", "550": "A10", "636": "A10", "703": "A10", "754": "A10", "755": "A10",
};

export function owaspForCwe(cwe: string | number | undefined): OwaspId | undefined {
  if (cwe === undefined || cwe === null) return undefined;
  return CWE_TO_OWASP[String(cwe).trim()];
}
