export type TierId = "founding_pilot" | "pilot" | "starter" | "production_founding" | "production" | "enterprise";
export type DeployId = "managed" | "vpc" | "onprem";
export type VolumeId = "50k" | "250k" | "1m" | "5m";

export const FOUNDING_COHORT = {
  totalSpots: 5,
  claimedSpots: 1, // Spot #1 reserved for P2 Transportation Solutions
  remainingSpots: 4,
  listValueUsd: 4800,
  foundingDiscountPct: 25,
} as const;

export type Engagement = {
  id: string;
  at: string;
  org: string;
  email: string;
  role: string;
  note: string;
  tier: TierId;
  deploy: DeployId;
  volume: VolumeId;
  addons: string[];
  amount: number;
  cadence: string;
};

export const TIERS: Array<{
  id: TierId;
  name: string;
  cadence: string;
  once: boolean;
  base: number;
  listBase?: number;
  badge?: string;
  blurb: string;
  includes: string[];
}> = [
  {
    id: "founding_pilot",
    name: "Founding Partner Pilot",
    cadence: "30 days",
    once: true,
    base: 0,
    listBase: 4800,
    badge: `${FOUNDING_COHORT.remainingSpots} of ${FOUNDING_COHORT.totalSpots} Free Spots Left`,
    blurb: "Complimentary 30-day shadow pilot ($4,800 value waived) for our first 5 fleet & consulting partners in exchange for structured feedback.",
    includes: [
      "Up to 25,000 guardrail checks / 30 days",
      "Isolated X-API-Key with automatic 30-day expiry",
      "FMCSA HOS, weight/permit, BOL injection & PII scrubbing",
      "Locks in 25% off Production Gateway ($1,350/mo) for Year 1",
    ],
  },
  {
    id: "pilot",
    name: "Standard Shadow Pilot",
    cadence: "30 days",
    once: true,
    base: 4800,
    badge: "Spot 6+ (100% Credited to Annual)",
    blurb: "The standard 30-day non-production evaluation once the 5 Founding Partner spots are filled. 100% credited toward an annual plan.",
    includes: [
      "Gateway mirrored beside dispatch or LLM workflow",
      "Weekly SHA-256 ledger & artifact review",
      "Custom PII & FMCSA rule tuning",
      "Production cutover notes for your team",
    ],
  },
  {
    id: "starter",
    name: "Fleet Starter",
    cadence: "month",
    once: false,
    base: 599,
    blurb: "Built for single regional fleets and boutique safety consultants running deterministic guardrails on dispatch & BOL workflows.",
    includes: [
      "10,000 deterministic checks / month ($5 per 1k overage)",
      "FMCSA shift + 60/70h cycle & 80k lb weight guardrails",
      "Context-aware CDL/SSN/Phone PII redaction",
      "Persistent SHA-256 audit ledger & CSV export",
    ],
  },
  {
    id: "production_founding",
    name: "Production Gateway (Founding Lock)",
    cadence: "month",
    once: false,
    base: 1350,
    listBase: 1800,
    badge: "25% Off Yr 1 — Founding Partners Only",
    blurb: "Full production gateway at a locked Year 1 rate for converting Founding Partners — saving $5,400 over 12 months.",
    includes: [
      "100,000 deterministic checks / month",
      "All 4 security & logistics vectors + fail-closed auth",
      "Monthly executive compliance & PDF/CSV artifact pack",
      "Priority founder & operator support",
    ],
  },
  {
    id: "production",
    name: "Production Gateway",
    cadence: "month",
    once: false,
    base: 1800,
    blurb: "The full deterministic gateway on the live path customers and dispatchers hit, with a monthly compliance pack.",
    includes: [
      "100,000 deterministic checks / month",
      "Fail-closed multi-tenant keys & sliding-window limits",
      "Monthly compliance pack (PDF + SHA-256 CSV ledger)",
      "Business-hours operator support",
    ],
  },
  {
    id: "enterprise",
    name: "Enterprise Defense",
    cadence: "month",
    once: false,
    base: 6400,
    blurb: "Dedicated VPC or on-prem placement, scheduled red-team vectors, and a named operator for high-volume carriers.",
    includes: [
      "1,000,000+ checks / month",
      "VPC or on-prem placement with Managed Postgres + Redis",
      "Scheduled red-team vectors & custom regulatory rules",
      "EU AI Act & ISO/IEC 42001 compliance binder",
    ],
  },
];

export const DEPLOYS: Array<{ id: DeployId; name: string; factor: number; note: string }> = [
  { id: "managed", name: "Managed", factor: 1, note: "Lucid Truth hosts the gateway." },
  { id: "vpc", name: "Your VPC", factor: 1.25, note: "Deployed into your cloud account." },
  { id: "onprem", name: "On-prem", factor: 1.6, note: "Private datacenter or air gap." },
];

export const VOLUMES: Array<{ id: VolumeId; label: string; factor: number }> = [
  { id: "50k", label: "50k req / mo", factor: 1 },
  { id: "250k", label: "250k req / mo", factor: 1.35 },
  { id: "1m", label: "1M req / mo", factor: 1.8 },
  { id: "5m", label: "5M req / mo", factor: 2.6 },
];

export const ADDONS: Array<{ id: string; name: string; price: number; note: string }> = [
  { id: "pii", name: "PII residency", price: 600, note: "Redact or block, with counts on every artifact." },
  { id: "redteam", name: "Red-team suite", price: 900, note: "The vector pack, run on a schedule against your gates." },
  { id: "binder", name: "Compliance binder", price: 750, note: "Art. 9 / 12 / 15 and ISO 42001 index for the ledger." },
];

export type Quote = {
  amount: number;
  listAmount: number;
  cadence: string;
  lines: Array<{ label: string; amount: number }>;
  tierName: string;
  deployName: string;
  volumeLabel: string;
  isFoundingOffer: boolean;
};

export function quote(input: {
  tier: TierId;
  deploy: DeployId;
  volume: VolumeId;
  addons: string[];
}): Quote {
  const tier = TIERS.find((item) => item.id === input.tier) ?? TIERS[0];
  const deploy = DEPLOYS.find((item) => item.id === input.deploy) ?? DEPLOYS[0];
  const volume = VOLUMES.find((item) => item.id === input.volume) ?? VOLUMES[0];
  const picked = ADDONS.filter((item) => input.addons.includes(item.id));
  const volumeFactor = tier.once ? 1 : volume.factor;
  const base = Math.round(tier.base * deploy.factor * volumeFactor);
  const listBase = Math.round((tier.listBase ?? tier.base) * deploy.factor * volumeFactor);
  const lines = [
    { label: `${tier.name} · ${deploy.name}`, amount: base },
    ...picked.map((item) => ({ label: item.name, amount: item.price })),
  ];
  const addonsTotal = picked.reduce((sum, item) => sum + item.price, 0);
  return {
    amount: base + addonsTotal,
    listAmount: listBase + addonsTotal,
    cadence: tier.once ? "for 30 days" : "per month",
    lines,
    tierName: tier.name,
    deployName: deploy.name,
    volumeLabel: tier.once ? "Up to 25,000 pilot checks included" : volume.label,
    isFoundingOffer: tier.id === "founding_pilot" || tier.id === "production_founding",
  };
}

export function money(amount: number): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0,
  }).format(amount);
}

export function briefMarkdown(engagement: Engagement, priced: Quote): string {
  const addons = engagement.addons.length ? engagement.addons.join(", ") : "none";
  const savingsLine =
    priced.listAmount > priced.amount
      ? `Founding Partner savings: ${money(priced.listAmount - priced.amount)} waived (List: ${money(priced.listAmount)})`
      : "";
  return [
    "# Lucid Truth Audit — Engagement Brief",
    "",
    `Organization: ${engagement.org}`,
    `Contact: ${engagement.email}`,
    engagement.role ? `Role: ${engagement.role}` : "",
    `Prepared: ${engagement.at}`,
    "",
    `Offer: ${priced.tierName}`,
    `Placement: ${priced.deployName}`,
    `Volume: ${priced.volumeLabel}`,
    `Add-ons: ${addons}`,
    `Offer estimate: ${money(priced.amount)} ${priced.cadence}`,
    savingsLine,
    "",
    engagement.note ? `Note: ${engagement.note}` : "",
    "",
    "Founding Partner Cohort: Strictly limited to 5 organizations. Keys expire automatically after 30 days.",
    "This brief is a non-binding pilot request and not an invoice.",
    "Control labels map gateway behavior to FMCSA 49 CFR § 395.3, EU AI Act (EU) 2024/1689, and ISO/IEC 42001 themes.",
  ]
    .filter((line) => line !== "")
    .join("\n");
}