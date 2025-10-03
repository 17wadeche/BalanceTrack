import React, { useEffect, useMemo, useState } from "react";
import {
  AreaChart, Area, Line, CartesianGrid, Tooltip, XAxis, YAxis, Legend,
  ResponsiveContainer, PieChart, Pie, Cell, ReferenceLine, Brush
} from "recharts";
const uid = () => Math.random().toString(36).slice(2, 10);
const C = (v: number, ccy: string) =>
  new Intl.NumberFormat(undefined, { style: "currency", currency: ccy }).format(v);
const todayISO = () => new Date().toISOString().slice(0, 10);
const monthKey = (iso: string) => iso.slice(0, 7);
const clamp = (n: number, min = 0, max = 100) => Math.max(min, Math.min(max, n));
const addDays = (iso: string, days: number) => {
  const [y, m, d] = iso.split("-").map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d + days));
  return dt.toISOString().slice(0, 10);
};
const startOfMonth = (iso: string) => iso.slice(0,7) + "-01";
const nextMonth = (iso: string) => addMonths(startOfMonth(iso), 1);
const inRange = (d: string, from: string, toExclusive: string) => d >= from && d < toExclusive;
const addMonths = (iso: string, months: number) => {
  const [y, m, d] = iso.split("-").map(Number);
  const dt = new Date(Date.UTC(y, m - 1 + months, d));
  return dt.toISOString().slice(0, 10);
};
const GOAL_COLORS = [ "#22c55e", "#3b82f6", "#f59e0b", "#ef4444", "#8b5cf6", "#14b8a6", "#f97316", "#84cc16", "#06b6d4", "#e11d48"];
const CAT_COLORS = [
  "#2563eb", "#ef4444", "#10b981", "#f59e0b", "#8b5cf6",
  "#06b6d4", "#84cc16", "#f97316", "#14b8a6", "#e11d48",
  "#0ea5e9", "#a855f7", "#22c55e", "#f43f5e", "#64748b"
];
type Account = { id: string; name: string; currency: string; isBusiness: boolean };
type Txn = {
  id: string; date: string; description: string; category: string; amount: number;
  account: string; isBusiness: boolean; tags?: string[]; note?: string; transferTo?: string;
};
type Budget = { id: string; category: string; monthlyLimit: number; isBusiness: boolean };
type Rule = {
  id: string; type: "contains" | "regex";
  pattern: string; thenCategory: string; isBusiness: boolean;
  minAmount?: number; maxAmount?: number;
};
type Recurring = {
  id: string;
  description: string;
  category: string;
  amount: number;
  account: string;
  everyUnit: "day"|"week"|"month"|"year";
  everyN: number;
  nextDate: string;
  isBusiness: boolean;
};type Goal = { id: string; name: string; target: number; current: number; isBusiness: boolean };
type Rates = Record<string, number>;
type Scenario = {
  id: string; name: string;
  savings?: { start: string; current: number; target: number; base: number; apyPct: number; inflationPct: number; taxPct: number; pattern: string };
  debts?: { strategy: "snowball" | "avalanche"; items: DebtItem[]; extra: number; start: string };
};
type DebtItem = { id: string; name: string; balance: number; aprPct: number; minPayment: number };
const STORAGE_KEY = "balancetrack:pro:v3";
type Persisted = any;
const isEncrypted = (raw: string) => raw.startsWith("enc:");
const getPassphrase = () => sessionStorage.getItem("wf_passphrase") || "";
const setPassphrase = (p: string) => sessionStorage.setItem("wf_passphrase", p);
const getBytes = (len: number) => {
  const a = new Uint8Array(len);
  (window.crypto || self.crypto).getRandomValues(a);
  return a;
};
async function deriveKey(pass: string, saltBytes: Uint8Array) {
  const encPass = new TextEncoder().encode(pass);
  const subtle = (window.crypto || self.crypto).subtle;
  const baseKey = await subtle.importKey(
    "raw",
    encPass as unknown as BufferSource,
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes as unknown as BufferSource, iterations: 150000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
async function encryptJSON(obj: any, pass: string) {
  const subtle = (window.crypto || self.crypto).subtle;
  const iv = getBytes(12);
  const salt = getBytes(16);
  const key = await deriveKey(pass, salt);
  const data = new TextEncoder().encode(JSON.stringify(obj));
  const ctBuf = await subtle.encrypt(
    { name: "AES-GCM", iv: iv as unknown as BufferSource },
    key,
    data as unknown as BufferSource
  );
  const ct = new Uint8Array(ctBuf);
  const packed = new Uint8Array(salt.length + iv.length + ct.length);
  packed.set(salt, 0);
  packed.set(iv, salt.length);
  packed.set(ct, salt.length + iv.length);
  return "enc:" + btoa(String.fromCharCode(...packed));
}
async function decryptJSON(raw: string, pass: string) {
  const subtle = (window.crypto || self.crypto).subtle;
  const bytes = Uint8Array.from(atob(raw.slice(4)), c => c.charCodeAt(0));
  const salt = bytes.slice(0, 16);
  const iv = bytes.slice(16, 28);
  const ct = bytes.slice(28);
  const key = await deriveKey(pass, salt);
  const plainBuf = await subtle.decrypt(
    { name: "AES-GCM", iv: iv as unknown as BufferSource },
    key,
    ct as unknown as BufferSource
  );
  return JSON.parse(new TextDecoder().decode(new Uint8Array(plainBuf)));
}
async function loadPersisted(): Promise<{state: Persisted|null; locked: boolean}> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { state: null, locked: false };
    if (isEncrypted(raw)) {
      const pass = getPassphrase();
      if (!pass) return { state: null, locked: true };
      try { const state = await decryptJSON(raw, pass); return { state, locked: false }; }
      catch { return { state: null, locked: true }; }
    } else {
      return { state: JSON.parse(raw), locked: false };
    }
  } catch { return { state: null, locked: false }; }
}
async function savePersisted(state: Persisted, useEncryption: boolean, pass: string) {
  try {
    if (useEncryption && pass) {
      const enc = await encryptJSON(state, pass);
      localStorage.setItem(STORAGE_KEY, enc);
    } else {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    }
  } catch { }
}
const seed = (() => {
  const personal = { id: uid(), name: "Personal Checking", currency: "USD", isBusiness: false } as Account;
  const biz = { id: uid(), name: "Business Card", currency: "USD", isBusiness: true } as Account;
  return {
    baseCurrency: "USD",
    dark: false,
    encryptLocal: false,
    rates: { USD: 1, EUR: 1.07, GBP: 1.26, JPY: 0.0064, CAD: 0.73, AUD: 0.67 } as Rates,
    accounts: [personal, biz] as Account[],
    txns: [
      { id: uid(), date: todayISO(), description: "Starting balance", category: "Income", amount: 1500, account: personal.id, isBusiness: false },
      { id: uid(), date: todayISO(), description: "Software subscription", category: "Software", amount: -25, account: biz.id, isBusiness: true }
    ] as Txn[],
    budgets: [
      { id: uid(), category: "Food", monthlyLimit: 400, isBusiness: false },
      { id: uid(), category: "Software", monthlyLimit: 120, isBusiness: true }
    ] as Budget[],
    rules: [
      { id: uid(), type:"contains", pattern: "uber", thenCategory: "Transport", isBusiness: false },
      { id: uid(), type:"regex", pattern: "aws|cloudfront", thenCategory: "Software", isBusiness: true }
    ] as Rule[],
    recurrings: [
      { id: uid(), description: "Gym membership", category: "Entertainment", amount: -30, account: personal.id, everyUnit: "month", everyN: 1, nextDate: todayISO(), isBusiness: false }
    ] as Recurring[],
    goals: [
      { id: uid(), name: "Emergency Fund", target: 2000, current: 300, isBusiness: false }
    ] as Goal[],
    scenarios: [] as Scenario[],
    categories: ["Income","Rent/Mortgage","Utilities","Food","Transport","Software","Supplies","Marketing","Entertainment","Taxes","Other"]
  };
})();
function txnsToCSV(txns: Txn[], accounts: Account[]) {
  const nameById: Record<string, string> = {}; accounts.forEach(a => nameById[a.id] = a.name);
  const headers = ["date","description","category","amount","account","scope","tags","note"];
  const rows = txns.map(t => [
    t.date, t.description, t.category, t.amount,
    nameById[t.account] || t.account, t.isBusiness ? "business" : "personal",
    (t.tags || []).join("|"), (t.note || "").replace(/\n/g, " ")
  ]);
  return [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
}
function parseCSV(text: string, accounts: Account[], scopeBusiness: boolean, rules: Rule[]): Txn[] {
  const lines = text.trim().split(/\r?\n/);
  const header = (lines.shift() || "").split(",").map(s => s.trim().toLowerCase());
  const idx = (k: string) => header.indexOf(k);
  const idByName: Record<string, string> = {}; accounts.forEach(a => idByName[a.name.toLowerCase()] = a.id);
  return lines.map(line => {
    const cells = line.split(",");
    const desc = cells[idx("description")] || "Imported";
    const autoCat = applyRules(desc, parseFloat(cells[idx("amount")]||"0"), rules.filter(r => true));
    return {
      id: uid(),
      date: cells[idx("date")] || todayISO(),
      description: desc,
      category: cells[idx("category")] || autoCat || "Other",
      amount: parseFloat(cells[idx("amount")] || "0"),
      account: idByName[(cells[idx("account")] || "").toLowerCase()] || accounts.find(a => a.isBusiness === scopeBusiness)?.id || "",
      isBusiness: scopeBusiness,
      tags: (cells[idx("tags")] || "").split("|").filter(Boolean),
      note: cells[idx("note")] || ""
    } as Txn;
  });
}
function applyRules(text: string, amount: number, rules: Rule[]) {
  const t = text.toLowerCase();
  for (const r of rules) {
    if (r.minAmount != null && amount < r.minAmount) continue;
    if (r.maxAmount != null && amount > r.maxAmount) continue;
    if (r.type === "contains" && t.includes(r.pattern.toLowerCase())) return r.thenCategory;
    if (r.type === "regex") {
      try { if (new RegExp(r.pattern, "i").test(text)) return r.thenCategory; } catch {}
    }
  }
  return "";
}
function materializeRecurrings(recs: Recurring[], pushTxn: (t: Txn) => void) {
  for (const r of recs) {
    let d = r.nextDate;
    const step = (iso: string) => {
      switch (r.everyUnit) {
        case "day":   return addDays(iso, 1 * (r.everyN || 1));
        case "week":  return addDays(iso, 7 * (r.everyN || 1));
        case "month": return addMonths(iso, 1 * (r.everyN || 1));
        case "year":  return addMonths(iso, 12 * (r.everyN || 1));
        default:      return addMonths(iso, 1);
      }
    };
    while (d <= todayISO()) {
      pushTxn({ id: uid(), date: d, description: r.description, category: r.category, amount: r.amount, account: r.account, isBusiness: r.isBusiness });
      d = step(d);
    }
    r.nextDate = d;
  }
}
export default function App() {
  const [categoriesList, setCategoriesList] = useState<string[]>(seed.categories);
  const [booted, setBooted] = useState(false);
  const [locked, setLocked] = useState(false);
  const [baseCurrency, setBaseCurrency] = useState(seed.baseCurrency);
  const [dark, setDark] = useState(seed.dark);
  const [encryptLocal, setEncryptLocal] = useState(seed.encryptLocal);
  const [rates, setRates] = useState<Rates>(seed.rates);
  const [accounts, setAccounts] = useState<Account[]>(seed.accounts);
  const [txns, setTxns] = useState<Txn[]>(seed.txns);
  const [budgets, setBudgets] = useState<Budget[]>(seed.budgets);
  const [rules, setRules] = useState<Rule[]>(seed.rules);
  const [recurrings, setRecurrings] = useState<Recurring[]>(seed.recurrings);
  const [goals, setGoals] = useState<Goal[]>(seed.goals);
  const [scenarios, setScenarios] = useState<Scenario[]>(seed.scenarios);
  const [sortBy, setSortBy] = useState<"date"|"amount"|"description"|"category">("date");
  const [sortDir, setSortDir] = useState<"asc"|"desc">("desc");
  const [catFilter, setCatFilter] = useState<string>("");
  const [scopeBusiness, setScopeBusiness] = useState(false);
  const [tab, setTab] = useState<"overview"|"transactions"|"budgets"|"recurring"|"accounts"|"goals"|"settings"|"planner">("overview");
  const [filterText, setFilterText] = useState("");
  const [accountFilter, setAccountFilter] = useState<string>("");
  const rc = useMemo(() => ({
    axis:  dark ? "#94a3b8" : "#64748b",   // tick/axis lines
    grid:  dark ? "#1f2937" : "#e5e7eb",   // grid lines
    text:  dark ? "#e5e7eb" : "#0f172a",   // tick/legend/tooltip text
    tipBg: dark ? "#0f172a" : "#ffffff",   // tooltip background
    tipBd: dark ? "#334155" : "#e5e7eb",   // tooltip border
  }), [dark]);
  const catColorMap = useMemo(() => {
    const m: Record<string, string> = {};
    categoriesList.forEach((c, i) => { m[c] = CAT_COLORS[i % CAT_COLORS.length]; });
    return m;
  }, [categoriesList]);
  type RangeKey = "week"|"month"|"3m"|"year";
  const startOfWeek = (iso: string) => {
    const d = new Date(iso);
    const wk = new Date(d);
    const day = (wk.getDay() + 6) % 7;
    wk.setDate(wk.getDate() - day);
    return wk.toISOString().slice(0,10);
  };
  const addYears = (iso: string, years: number) => {
    const d = new Date(iso); d.setFullYear(d.getFullYear()+years); return d.toISOString().slice(0,10);
  };
  const rangeWindow = (key: RangeKey) => {
    const today = todayISO();
    if (key === "week") return { from: startOfWeek(today), to: addDays(startOfWeek(today), 7) };
    if (key === "month") {
      const from = startOfMonth(today); return { from, to: nextMonth(from) };
    }
    if (key === "3m") {
      const from = startOfMonth(addMonths(today, -2)); 
      return { from, to: nextMonth(startOfMonth(today)) };
    }
    const from = startOfMonth(addMonths(today, -11));
    return { from, to: nextMonth(startOfMonth(today)) };
  };
  const [overviewRange, setOverviewRange] = useState<RangeKey>("month");
  const { from: ovFrom, to: ovTo } = rangeWindow(overviewRange);
  useEffect(() => {
    (async () => {
      const { state, locked } = await loadPersisted();
      if (state) {
        setBaseCurrency(state.baseCurrency ?? seed.baseCurrency);
        setDark(!!state.dark);
        setEncryptLocal(!!state.encryptLocal);
        setRates(state.rates ?? seed.rates);
        setAccounts(state.accounts ?? seed.accounts);
        setTxns(state.txns ?? seed.txns);
        setBudgets(state.budgets ?? seed.budgets);
        setRules(state.rules ?? seed.rules);
        setRecurrings(state.recurrings ?? seed.recurrings);
        setGoals(state.goals ?? seed.goals);
        setScenarios(state.scenarios ?? []);
        setCategoriesList(state.categories ?? seed.categories);
      }
      setLocked(locked);
      setBooted(true);
    })();
  }, []);
  useEffect(() => {
    if (!booted || locked) return;
    const snapshot = { baseCurrency, dark, encryptLocal, rates, accounts, txns, budgets, rules, recurrings, goals, scenarios, categories: categoriesList };
    savePersisted(snapshot, encryptLocal, getPassphrase());
  }, [booted, locked, baseCurrency, dark, encryptLocal, rates, accounts, txns, budgets, rules, recurrings, goals, scenarios, categoriesList]);
  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    document.documentElement.style.colorScheme = dark ? "dark" : "light";
  }, [dark]);
  useEffect(() => {
    setRecurrings(prev => {
      const copy = prev.map(r => ({ ...r }));
      const scope = copy.filter(r => r.isBusiness === scopeBusiness);
      const pushed: Txn[] = [];
      materializeRecurrings(scope, (t) => pushed.push(t));
      if (pushed.length) setTxns(s => [...pushed, ...s]);
      return copy;
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scopeBusiness]);
  const scopedAccounts = useMemo(() => accounts.filter(a => a.isBusiness === scopeBusiness), [accounts, scopeBusiness]);
  const scopedTxns = useMemo(() => txns.filter(t => t.isBusiness === scopeBusiness), [txns, scopeBusiness]);
  const filteredTxns = useMemo(
    () => (accountFilter ? scopedTxns.filter(t => t.account === accountFilter) : scopedTxns),
    [scopedTxns, accountFilter]
  );
  const visibleTxns = useMemo(() => {
    let list = (accountFilter ? scopedTxns.filter(t => t.account === accountFilter) : scopedTxns)
      .filter(t => !catFilter || t.category === catFilter);
    const f = filterText.trim().toLowerCase();
    if (f) {
      list = list.filter(t => {
        const acct = accounts.find(a => a.id === t.account)?.name || "";
        const tags = (t.tags || []).join(",");
        return [t.description, t.category, acct, tags, t.note || ""].some(s => String(s).toLowerCase().includes(f));
      });
    }
    const dir = sortDir === "asc" ? 1 : -1;
    list = [...list].sort((a, b) => {
      switch (sortBy) {
        case "date":        return (a.date.localeCompare(b.date)) * dir;
        case "amount":      return (a.amount - b.amount) * dir;
        case "description": return (a.description.localeCompare(b.description)) * dir;
        case "category":    return (a.category.localeCompare(b.category)) * dir;
        default:            return 0;
      }
    });
    return list;
  }, [scopedTxns, accountFilter, catFilter, filterText, accounts, sortBy, sortDir]);
  const currencyForAccount = (id: string) => accounts.find(a => a.id === id)?.currency || baseCurrency;
  const toBase = (amount: number, ccy: string) => amount * (rates[ccy] ?? 1) / (rates[baseCurrency] ?? 1);
  const monthStr = todayISO().slice(0, 7);
  const balanceByAccount = useMemo(() => {
    const map: Record<string, number> = {};
    for (const t of scopedTxns) {
      const v = toBase(t.amount, currencyForAccount(t.account));
      map[t.account] = (map[t.account] || 0) + v;
    }
    return map;
  }, [scopedTxns, rates, baseCurrency]);
  const totalBalance = useMemo(() => Object.values(balanceByAccount).reduce((a, b) => a + b, 0), [balanceByAccount]);
  const incomeThisMonth = useMemo(() =>
    filteredTxns
      .filter(t => t.amount > 0 && inRange(t.date, ovFrom, ovTo))
      .reduce((a,b)=> a + toBase(b.amount, currencyForAccount(b.account)), 0),
    [filteredTxns, ovFrom, ovTo, rates, baseCurrency]
  );
  const expenseThisMonth = useMemo(() =>
    Math.abs(
      filteredTxns
        .filter(t => t.amount < 0 && inRange(t.date, ovFrom, ovTo) && !(t.tags||[]).includes("__transfer"))
        .reduce((a,b)=> a + toBase(b.amount, currencyForAccount(b.account)), 0)
    ),
    [filteredTxns, ovFrom, ovTo, rates, baseCurrency]
  );
  const monthlySeries = useMemo(() => {
    const map: Record<string, { income: number; expense: number }> = {};
    for (const t of filteredTxns) {
      if (!inRange(t.date, ovFrom, ovTo)) continue;
      const k = monthKey(t.date);
      if (!map[k]) map[k] = { income: 0, expense: 0 };
      const v = toBase(t.amount, currencyForAccount(t.account));
      if (t.amount >= 0) map[k].income += v; else map[k].expense += Math.abs(v);
    }
    return monthsBetween(ovFrom, ovTo).map(m => {
      const v = map[m] || { income: 0, expense: 0 };
      return { month: m, ...v, net: v.income - v.expense };
    });
  }, [filteredTxns, ovFrom, ovTo, rates, baseCurrency]);
  const categories = useMemo(() => {
    const m: Record<string, number> = {};
    for (const t of filteredTxns) {
      if (t.amount >= 0) continue;
      if (!inRange(t.date, ovFrom, ovTo)) continue;
      if ((t.tags || []).includes("__transfer")) continue;
      m[t.category] = (m[t.category] || 0) + Math.abs(toBase(t.amount, currencyForAccount(t.account)));
    }
    return Object.entries(m).map(([name, value]) => ({ name, value }));
  }, [filteredTxns, ovFrom, ovTo, rates, baseCurrency]);
  const usedVsBudget = useMemo(() => {
    const monthStart = startOfMonth(todayISO());
    const monthEnd = nextMonth(monthStart);
    const usedByCat: Record<string, number> = {};
    for (const t of filteredTxns) {
      if (t.amount >= 0) continue;
      if (!inRange(t.date, monthStart, monthEnd)) continue;
      if ((t.tags || []).includes("__transfer")) continue;
      const v = Math.abs(toBase(t.amount, currencyForAccount(t.account)));
      usedByCat[t.category] = (usedByCat[t.category] || 0) + v;
    }
    return budgets
      .filter(b => b.isBusiness === scopeBusiness)
      .map(b => {
        const used = usedByCat[b.category] || 0;
        return { ...b, used, pct: clamp(Math.round((used / Math.max(1, b.monthlyLimit)) * 100)) };
      });
  }, [budgets, filteredTxns, rates, baseCurrency, scopeBusiness]);
  const forecast = useMemo(() => {
    const start = todayISO();
    const recs = recurrings
      .filter(r => r.isBusiness === scopeBusiness && (!accountFilter || r.account === accountFilter))
      .map(r => ({ ...r }));
    const { avgDailyIncome, avgDailyExpense } = (() => {
      const last90 = filteredTxns.filter(
        t => t.date >= addDays(start, -90) && !(t.tags || []).includes("__transfer")
      );
      const inc = last90
        .filter(t => t.amount > 0)
        .reduce((a, b) => a + toBase(b.amount, currencyForAccount(b.account)), 0) / 90;
      const exp = last90
        .filter(t => t.amount < 0)
        .reduce((a, b) => a + Math.abs(toBase(b.amount, currencyForAccount(b.account))), 0) / 90;
      return { avgDailyIncome: inc, avgDailyExpense: exp };
    })();
    let day = start, running = 0;
    const out: { day: string; cum: number }[] = [];
    for (let i = 0; i < 90; i++) {
      let income = avgDailyIncome, expense = avgDailyExpense;
      for (const r of recs) {
        if (r.nextDate <= day) {
          const v = toBase(r.amount, currencyForAccount(r.account));
          if (v >= 0) income += v; else expense += Math.abs(v);
          r.nextDate = (() => {
            switch (r.everyUnit) {
              case "day":   return addDays(r.nextDate, 1 * (r.everyN || 1));
              case "week":  return addDays(r.nextDate, 7 * (r.everyN || 1));
              case "month": return addMonths(r.nextDate, 1 * (r.everyN || 1));
              case "year":  return addMonths(r.nextDate, 12 * (r.everyN || 1));
              default:      return addMonths(r.nextDate, 1);
            }
          })();
        }
      }
      running += (income - expense);
      out.push({ day, cum: running });
      day = addDays(day, 1);
    }
    return out;
  }, [recurrings, filteredTxns, scopeBusiness, rates, baseCurrency, accountFilter]);
  function updateBudget(id: string, patch: Partial<Budget>) {
    setBudgets(bs => bs.map(b => b.id === id ? { ...b, ...patch } : b));
  }
  function deleteBudgetById(id: string) {
    setBudgets(bs => bs.filter(b => b.id !== id));
  }
  function addAccount(name: string, currency: string) {
    setAccounts(a => [...a, { id: uid(), name, currency: currency.toUpperCase(), isBusiness: scopeBusiness }]);
  }
  function addTxnForm(p: Partial<Txn>) {
    const desc = p.description || "";
    const auto = applyRules(desc, Number(p.amount || 0), rules);
    const t: Txn = {
      id: uid(), date: p.date || todayISO(), description: desc,
      category: p.category || auto || "Other", amount: Number(p.amount || 0),
      account: p.account || (scopedAccounts[0]?.id || ""), isBusiness: scopeBusiness,
      tags: (p.tags || []), note: p.note || ""
    };
    if (p.transferTo) {
      const to = String(p.transferTo);
      const tagXfer = "__transfer";
      setTxns(s => [
        { ...t, tags: [...(t.tags||[]), tagXfer] },
        { ...t, id: uid(), account: to, amount: -t.amount, tags: [...(t.tags||[]), tagXfer] },
        ...s
      ]);
    } else {
      setTxns(s => [t, ...s]);
    }
  }
  function renameCategory(oldName: string, newName: string) {
    if (!newName.trim() || oldName === newName) return;
    setTxns(ts => ts.map(t => t.category === oldName ? { ...t, category: newName } : t));
    setBudgets(bs => bs.map(b => b.category === oldName ? { ...b, category: newName } : b));
    setRecurrings(rs => rs.map(r => r.category === oldName ? { ...r, category: newName } : r));
    setRules(rs => rs.map(r => r.thenCategory === oldName ? { ...r, thenCategory: newName } : r));
    setCategoriesList(list => list.map(c => c === oldName ? newName : c));
  }
  function deleteCategoryEverywhere(cat: string, fallback = "Other") {
    if (!categoriesList.includes(fallback)) setCategoriesList(list => [...list, fallback]);
    setTxns(ts => ts.map(t => t.category === cat ? { ...t, category: fallback } : t));
    setBudgets(bs => bs.filter(b => b.category !== cat));
    setRecurrings(rs => rs.map(r => r.category === cat ? { ...r, category: fallback } : r));
    setRules(rs => rs.map(r => r.thenCategory === cat ? { ...r, thenCategory: fallback } : r));
    setCategoriesList(list => list.filter(c => c !== cat));
  }
  function deleteAccount(id: string) {
    const hasTxns = txns.some(t => t.account === id);
    if (hasTxns) {
      const ok = confirm(
        "This account has transactions. Deleting it will also delete those transactions. Continue?"
      );
      if (!ok) return;
    }
    setAccounts(list => list.filter(a => a.id !== id));
    if (hasTxns) setTxns(list => list.filter(t => t.account !== id));
  }
  function deleteGoal(id: string) {
      const ok = confirm("Delete this goal?");
      if (!ok) return;
      setGoals(list => list.filter(g => g.id !== id));
  }
  function updateTxn(id: string, patch: Partial<Txn>) {
    setTxns(list => list.map(t => (t.id === id ? { ...t, ...patch } : t)));
  }
  const deleteTxn = (id: string) => setTxns(s => s.filter(t => t.id !== id));
  const [editingId, setEditingId] = useState<string | null>(null);
  const addBudget = (category: string, limit: number) => setBudgets(b => [{ id: uid(), category, monthlyLimit: limit, isBusiness: scopeBusiness }, ...b]);
  const addRule = (rule: Omit<Rule,"id"|"isBusiness">) => setRules(r => [{ id: uid(), isBusiness: scopeBusiness, ...rule }, ...r]);
  const addRecurring = (p: Omit<Recurring, "id" | "isBusiness">) => setRecurrings(r => [{ id: uid(), isBusiness: scopeBusiness, ...p }, ...r]);
  const exportCSVScope = () => { const csv = txnsToCSV(scopedTxns, accounts); const b = new Blob([csv], { type: "text/csv" }); const url = URL.createObjectURL(b); const a = document.createElement("a"); a.href = url; a.download = `balancetrack_${scopeBusiness ? "business" : "personal"}.csv`; a.click(); URL.revokeObjectURL(url); };
  const importCSVFile = (file: File) => { const r = new FileReader(); r.onload = e => { const text = String(e.target?.result || ""); const imported = parseCSV(text, accounts, scopeBusiness, rules); setTxns(s => [...imported, ...s]); }; r.readAsText(file); };
  function exportJSON() { const blob = new Blob([JSON.stringify({ baseCurrency, dark, encryptLocal, rates, accounts, txns, budgets, rules, recurrings, goals, scenarios }, null, 2)], { type: "application/json" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = "balancetrack_backup.json"; a.click(); URL.revokeObjectURL(url); }
  function importJSON(file: File) { const r = new FileReader(); r.onload = e => { try { const o = JSON.parse(String(e.target?.result || "{}")); if (o.accounts) setAccounts(o.accounts); if (o.txns) setTxns(o.txns); if (o.budgets) setBudgets(o.budgets); if (o.rules) setRules(o.rules); if (o.recurrings) setRecurrings(o.recurrings); if (o.goals) setGoals(o.goals); if (o.baseCurrency) setBaseCurrency(o.baseCurrency); if (o.rates) setRates(o.rates); if (o.scenarios) setScenarios(o.scenarios); if (typeof o.dark === "boolean") setDark(o.dark); if (typeof o.encryptLocal === "boolean") setEncryptLocal(o.encryptLocal); } catch { alert("Invalid JSON"); } }; r.readAsText(file); }
  const TabBtn = ({ id, label }: { id: typeof tab; label: string }) => (
    <button aria-current={tab === id} onClick={() => setTab(id)} className={`px-3 py-2 rounded-xl border transition ${tab === id ? "bg-slate-900 text-white border-slate-900 dark:bg-white dark:text-slate-900" : "hover:bg-slate-50 dark:hover:bg-slate-800"}`}>{label}</button>
  );
  return (
    <div className={`min-h-screen ${dark ? "bg-slate-900 text-slate-100" : "bg-slate-50 text-slate-900"}`}>
      <style>{`
        .dark input, .dark select, .dark textarea {
          background-color: #0f172a;
          color: #e5e7eb;
          border-color: #334155;
        }
        .dark option { background-color: #0f172a; color: #e5e7eb; }
        :root:not(.dark) input,
        :root:not(.dark) select,
        :root:not(.dark) textarea {
          background-color: #ffffff;
          color: #0f172a;
          border-color: #cbd5e1;
        }
      `}</style>
      {locked && (
        <div className="bg-amber-100 text-amber-900 dark:bg-amber-900 dark:text-amber-100 px-4 py-2 text-sm">
          Data is encrypted. Enter passphrase in <b>Settings → Encryption</b> to unlock.
        </div>
      )}
      <header className={`sticky top-0 z-10 backdrop-blur border-b ${dark ? "bg-slate-900/60 border-slate-800" : "bg-white/70 border-slate-200"}`}>
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div aria-label="BalanceTrack logo" className={`w-9 h-9 rounded-2xl grid place-items-center font-bold ${dark ? "bg-white text-slate-900" : "bg-slate-900 text-white"}`}>BT</div>
            <div><h1 className="text-xl font-semibold leading-tight">BalanceTrack</h1><p className={`text-xs ${dark ? "text-slate-400" : "text-slate-500"}`}>Modern finance tracking for personal & business</p></div>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 text-xs"><label htmlFor="scope-switch">Personal</label><input id="scope-switch" type="checkbox" checked={scopeBusiness} onChange={(e) => setScopeBusiness(e.target.checked)} className="w-10 h-5 accent-slate-900" /><span>Business</span></div>
            <div className="flex items-center gap-1 text-xs"><label htmlFor="base-ccy" className="sr-only">Base currency</label><select id="base-ccy" value={baseCurrency} onChange={(e) => setBaseCurrency(e.target.value)} className="border rounded-xl px-2 py-1 text-sm">{Object.keys(rates).map(c => <option key={c} value={c}>{c}</option>)}</select></div>
            <button aria-label="Toggle dark mode" onClick={() => setDark(v => !v)} className="px-3 py-1.5 rounded-xl border">{dark ? "Light" : "Dark"} mode</button>
          </div>
        </div>
      </header>
      <main className="max-w-7xl mx-auto px-4 py-6 space-y-6">
        <nav aria-label="Sections" className="flex flex-wrap gap-2">
          <TabBtn id="overview" label="Overview" />
          <TabBtn id="transactions" label="Transactions" />
          <TabBtn id="budgets" label="Budgets" />
          <TabBtn id="recurring" label="Recurring" />
          <TabBtn id="accounts" label="Accounts" />
          <TabBtn id="goals" label="Goals" />
          <TabBtn id="planner" label="Planner" />
          <TabBtn id="settings" label="Settings" />
        </nav>
        {tab === "overview" && (
          <section className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 space-y-6">
              <div className="flex items-center gap-2 justify-end text-xs -mb-2">
                <span className="opacity-70">Range:</span>
                <button className={`border rounded-xl px-2 py-1 ${overviewRange==="week"?"bg-slate-900 text-white dark:bg-white dark:text-slate-900":""}`} onClick={()=>setOverviewRange("week")}>This week</button>
                <button className={`border rounded-xl px-2 py-1 ${overviewRange==="month"?"bg-slate-900 text-white dark:bg-white dark:text-slate-900":""}`} onClick={()=>setOverviewRange("month")}>This month</button>
                <button className={`border rounded-xl px-2 py-1 ${overviewRange==="3m"?"bg-slate-900 text-white dark:bg-white dark:text-slate-900":""}`} onClick={()=>setOverviewRange("3m")}>Last 3 months</button>
                <button className={`border rounded-xl px-2 py-1 ${overviewRange==="year"?"bg-slate-900 text-white dark:bg-white dark:text-slate-900":""}`} onClick={()=>setOverviewRange("year")}>Year</button>
                <span className="opacity-70 ml-2">Account:</span>
                <select
                  value={accountFilter}
                  onChange={(e)=>setAccountFilter(e.target.value)}
                  className="border rounded-xl px-2 py-1 text-xs dark:bg-slate-900 dark:text-slate-100 dark:border-slate-700"
                  aria-label="Filter overview by account"
                >
                  <option value="">All accounts</option>
                  {scopedAccounts.map(a => <option key={a.id} value={a.id}>{a.name}</option>)}
                </select>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <KPI title="Total balance (base)" value={C(
                  (accountFilter ? (balanceByAccount[accountFilter] || 0) : totalBalance), baseCurrency)} />
                <KPI title="This month income" value={C(incomeThisMonth, baseCurrency)} />
                <KPI title="This month spent" value={C(expenseThisMonth, baseCurrency)} />
                <KPI title="Transactions" value={String(filteredTxns.length)} />
              </div>
              <Card title="Cash Flow by Month" badge={scopeBusiness ? "Business" : "Personal"}>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={monthlySeries} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                    <defs>
                      <linearGradient id="inc" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopOpacity={0.35} stopColor="#16a34a" />
                        <stop offset="95%" stopOpacity={0} stopColor="#16a34a" />
                      </linearGradient>
                      <linearGradient id="exp" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopOpacity={0.35} stopColor="#ef4444" />
                        <stop offset="95%" stopOpacity={0} stopColor="#ef4444" />
                      </linearGradient>
                    </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke={rc.grid} />
                      <XAxis
                        dataKey="month"
                        type="category"
                        allowDuplicatedCategory={false}
                        minTickGap={8}
                        tickFormatter={fmtMonth}
                        tick={{ fill: rc.text }}
                        axisLine={{ stroke: rc.axis }}
                        tickLine={{ stroke: rc.axis }}
                      />
                      <YAxis
                        tickFormatter={(v)=>C(v,baseCurrency)}
                        width={90}
                        tick={{ fill: rc.text }}
                        axisLine={{ stroke: rc.axis }}
                        tickLine={{ stroke: rc.axis }}
                      />
                      <Tooltip
                        formatter={(v:number)=>C(v, baseCurrency)}
                        contentStyle={{ backgroundColor: rc.tipBg, borderColor: rc.tipBd, color: rc.text }}
                        itemStyle={{ color: rc.text }}
                        labelStyle={{ color: rc.text }}
                      />
                      <Legend wrapperStyle={{ color: rc.text }} />
                      <Area type="monotone" dataKey="income" stroke="#16a34a" fillOpacity={1} fill="url(#inc)" name="Income" />
                      <Area type="monotone" dataKey="expense" stroke="#ef4444" fillOpacity={1} fill="url(#exp)" name="Expenses" />
                      <Line type="monotone" dataKey="net" stroke={dark ? "#fff" : "#0f172a"} name="Net" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </Card>
              <Card title="90-Day Forecast (cumulative net)">
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={forecast} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke={rc.grid} />
                      <XAxis
                        dataKey="day"
                        tickFormatter={(d) => new Date(d).toLocaleDateString(undefined, { month: "short", day: "numeric" })}
                        tick={{ fill: rc.text }}
                        axisLine={{ stroke: rc.axis }}
                        tickLine={{ stroke: rc.axis }}
                      />
                      <YAxis tickFormatter={(v) => C(v, baseCurrency)} width={90}
                        tick={{ fill: rc.text }} axisLine={{ stroke: rc.axis }} tickLine={{ stroke: rc.axis }} />
                      <Tooltip
                        formatter={(v: number) => C(v, baseCurrency)}
                        contentStyle={{ backgroundColor: rc.tipBg, borderColor: rc.tipBd, color: rc.text }}
                        itemStyle={{ color: rc.text }}
                        labelStyle={{ color: rc.text }}
                      />
                      <Area type="monotone" dataKey="cum" stroke="#6366f1" fillOpacity={0.3} />
                      <Brush dataKey="day" height={20} travellerWidth={10} tickFormatter={() => ""} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </Card>
            </div>
            <div className="space-y-6">
              <Card title="Category Breakdown (Expenses)">
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={categories} dataKey="value" nameKey="name" innerRadius={50} outerRadius={90}>
                        {categories.map((slice, i) => (
                          <Cell key={i} fill={catColorMap[slice.name] || CAT_COLORS[i % CAT_COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip
                        formatter={(v:number)=>C(v,baseCurrency)}
                        contentStyle={{ backgroundColor: rc.tipBg, borderColor: rc.tipBd, color: rc.text }}
                        itemStyle={{ color: rc.text }}
                        labelStyle={{ color: rc.text }}
                      />
                      <Legend wrapperStyle={{ color: rc.text }} />
                    </PieChart>                  
                  </ResponsiveContainer>
                </div>
              </Card>
              <Card title="Budgets (this month)">
                <div className="space-y-2">
                  {usedVsBudget.map(b=>(
                    <div key={b.id} className="p-3 rounded-xl border">
                      <div className="flex justify-between text-sm">
                        <div>{b.category}</div>
                        <div>
                          {C(b.used, baseCurrency)} / {C(b.monthlyLimit, baseCurrency)}
                          <span className="ml-2 opacity-70">• {b.pct}%</span>
                        </div>
                      </div>
                      <div className="h-2 bg-slate-200 dark:bg-slate-800 rounded-full mt-2 overflow-hidden">
                        <div
                          className="h-full"
                          style={{ width: `${b.pct}%`, backgroundColor: catColorMap[b.category] || "#22c55e" }}
                          title={`${b.pct}%`}
                          role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={b.pct} aria-label={`${b.category} budget used`}
                        />
                      </div>
                    </div>
                  ))}
                  {usedVsBudget.length===0 && <div className="text-sm opacity-70">No budgets set for this scope.</div>}
                </div>
              </Card>
            </div>
          </section>
        )}
        {tab === "transactions" && (
          <section className="space-y-4">
            <Card title="Add transaction">
              <TxnForm accounts={scopedAccounts} categories={categoriesList} onSubmit={addTxnForm} />
            </Card>
            <Card title="Transactions">
              <div className="flex gap-2 mb-3">
                <label htmlFor="search" className="sr-only">Search</label>
                <input id="search" className="border rounded-xl px-3 py-2 flex-1" placeholder="Search description, category, account, tags…" value={filterText} onChange={(e) => setFilterText(e.target.value)} />
                <select
                  value={accountFilter}
                  onChange={(e)=>setAccountFilter(e.target.value)}
                  className="border rounded-xl px-2 py-2 text-sm dark:bg-slate-900 dark:text-slate-100 dark:border-slate-700"
                  aria-label="Filter transactions by account"
                >
                  <option value="">All accounts</option>
                  {scopedAccounts.map(a => <option key={a.id} value={a.id}>{a.name}</option>)}
                </select>
                <button onClick={exportCSVScope} className="rounded-2xl px-3 py-2 border" aria-label="Export CSV">Export CSV</button>
                <label className="rounded-2xl px-3 py-2 border cursor-pointer" aria-label="Import CSV">
                  Import CSV
                  <input type="file" accept=".csv" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; if (f) importCSVFile(f); }} />
                </label>
              </div>
              <div className="overflow-auto rounded-xl border border-slate-200 dark:border-slate-700">
                <table className="w-full text-sm">
                  <thead className="bg-slate-50 dark:bg-slate-800 text-slate-700 dark:text-slate-200">
                    <tr>
                      {[
                        { key: "date", label: "Date" },
                        { key: "description", label: "Description" },
                        { key: "category", label: "Category" },
                        { key: "account", label: "Account" },
                        { key: "tags", label: "Tags", noSort: true },
                        { key: "amount", label: "Amount", alignRight: true },
                        { key: "_", label: "", noSort: true },
                      ].map(col => {
                        if (col.noSort) {
                          return (
                            <th key={col.key} className={`px-3 py-2 ${col.alignRight ? "text-right" : "text-left"}`}>
                              {col.label}
                            </th>
                          );
                        }
                        const isActive = sortBy === (col.key as any);
                        const dirArrow = isActive ? (sortDir === "asc" ? "▲" : "▼") : "";
                        return (
                          <th
                            key={col.key}
                            role="button"
                            aria-sort={isActive ? (sortDir === "asc" ? "ascending" : "descending") : "none"}
                            onClick={() => {
                              setSortBy(col.key as any);
                              setSortDir(prev => (isActive ? (prev === "asc" ? "desc" : "asc") : "asc"));
                            }}
                            className={`px-3 py-2 ${col.alignRight ? "text-right" : "text-left"} select-none cursor-pointer`}
                            title="Click to sort"
                          >
                            <span className="inline-flex items-center gap-1">
                              {col.label} <span className="opacity-60">{dirArrow}</span>
                            </span>
                          </th>
                        );
                      })}
                    </tr>
                  </thead>
                  <tbody>
                    {visibleTxns.map(t => (
                      <tr key={t.id} className="border-t border-slate-200 dark:border-slate-700">
                        <td className="px-3 py-2 whitespace-nowrap">{t.date}</td>
                        <td className="px-3 py-2">{t.description}</td>
                        <td className="px-3 py-2">{t.category}</td>
                        <td className="px-3 py-2">{accounts.find(a => a.id === t.account)?.name || "?"}</td>
                        <td className="px-3 py-2">
                          {(t.tags || []).map(x => (
                            <span key={x} className="px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 mr-1">
                              {x}
                            </span>
                          ))}
                        </td>
                        <td
                          className={`px-3 py-2 text-right font-medium ${
                            t.amount >= 0 ? "text-emerald-600" : "text-rose-500"
                          }`}
                        >
                          {t.amount >= 0 ? "+" : "-"}
                          {C(Math.abs(t.amount), currencyForAccount(t.account))}
                        </td>
                        <td className="px-3 py-2 text-right flex gap-2">
                          <button className="underline" onClick={() => setEditingId(t.id)}>
                            Edit
                          </button>
                          <button
                            className="text-rose-500 underline"
                            aria-label="Delete transaction"
                            onClick={() => deleteTxn(t.id)}
                          >
                            Delete
                          </button>
                          <SplitButton
                            txn={t}
                            categories={categoriesList}
                            onSplit={(parts) => {
                              const sum = parts.reduce((a, b) => a + b.amount, 0);
                              if (Math.round(sum * 100) !== Math.round(t.amount * 100)) {
                                alert("Split amounts must sum to the original amount.");
                                return;
                              }
                              setTxns((all) => [
                                ...parts.map((p) => ({
                                  id: uid(),
                                  date: t.date,
                                  description: `${t.description} (split)`,
                                  category: p.category,
                                  amount: p.amount,
                                  account: t.account,
                                  isBusiness: t.isBusiness,
                                })),
                                ...all.filter((x) => x.id !== t.id),
                              ]);
                            }}
                          />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {editingId && (
                  <EditTxnModal
                    open={true}
                    onClose={()=>setEditingId(null)}
                    txn={txns.find(x => x.id === editingId)!}
                    accounts={scopedAccounts}
                    categories={categoriesList}
                    onSave={(patch)=> updateTxn(editingId, patch)}
                  />
                )}
              </div>
            </Card>
          </section>
        )}
        {tab === "budgets" && (
          <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card title="Add budget">
              <BudgetForm categories={categoriesList} onAdd={addBudget} />
            </Card>
            <Card title="Budgets">
              <ul className="space-y-2">
                {budgets.filter(b => b.isBusiness === scopeBusiness).map(b => (
                  <li key={b.id} className="p-3 rounded-xl border grid grid-cols-12 gap-2 items-center">
                    <select
                      className="border rounded-xl px-2 py-1 col-span-6"
                      value={b.category}
                      onChange={(e)=> updateBudget(b.id, { category: e.target.value })}
                    >
                      {categoriesList.filter(c => c !== "Income").map(c => <option key={c} value={c}>{c}</option>)}
                    </select>
                    <input
                      className="border rounded-xl px-2 py-1 col-span-4"
                      type="number"
                      step="1"
                      value={b.monthlyLimit}
                      onChange={(e)=> updateBudget(b.id, { monthlyLimit: Number(e.target.value) })}
                    />
                    <button
                      className="text-rose-500 underline col-span-2 justify-self-end"
                      aria-label={`Delete ${b.category} budget`}
                      onClick={()=> deleteBudgetById(b.id)}
                    >
                      Delete
                    </button>
                  </li>
                ))}
                {budgets.filter(b => b.isBusiness === scopeBusiness).length === 0 && <li className="text-sm opacity-70">No budgets yet.</li>}
              </ul>
            </Card>
          </section>
        )}
        {tab === "recurring" && (
          <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card title="Add recurring"><RecurringForm accounts={scopedAccounts} categories={categoriesList} onAdd={addRecurring} /></Card>
            <Card title="Auto-categorization rules">
              <RuleForm categories={categoriesList} onAdd={addRule} />
              <ul className="mt-3 space-y-1 text-sm">
                {rules.filter(r=>r.isBusiness===scopeBusiness || true).map(r=>(
                  <li key={r.id} className="p-2 border rounded-xl">
                    {r.type==="regex" ? "RegEx" : "Contains"}: “{r.pattern}” → <b>{r.thenCategory}</b>
                    {(r.minAmount!=null || r.maxAmount!=null) && <span className="opacity-70"> (amount {r.minAmount ?? "-∞"}…{r.maxAmount ?? "∞"})</span>}
                  </li>
                ))}
                {rules.length===0 && <li className="opacity-70">No rules yet.</li>}
              </ul>
            </Card>
          </section>
        )}
        {tab === "accounts" && (
          <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card title="Add account"><AccountForm onAdd={addAccount} /></Card>
            <Card title="Accounts & balances (in base)">
              <ul className="space-y-2">
                {scopedAccounts.map(a => {
                  const bal = balanceByAccount[a.id] || 0;
                  return (
                    <li key={a.id} className="p-3 rounded-xl border flex items-center justify-between gap-3">
                      <div>
                        <div className="font-medium">{a.name}</div>
                        <div className="text-xs opacity-70">{a.currency}</div>
                      </div>
                      <div className="flex items-center gap-3">
                        <div className={bal >= 0 ? "text-emerald-600" : "text-rose-500"}>
                          {C(bal, baseCurrency)}
                        </div>
                        <button
                          className="text-rose-500 underline"
                          aria-label={`Delete ${a.name}`}
                          onClick={() => deleteAccount(a.id)}
                        >
                          Delete
                        </button>
                      </div>
                    </li>
                  );
                })}
                {scopedAccounts.length===0 && <li className="text-sm opacity-70">No accounts yet. Add one.</li>}
              </ul>
            </Card>
          </section>
        )}
        {tab === "goals" && (
          <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card title="Add goal"><GoalForm onAdd={(name: string, target: number) => setGoals(g => [{ id: uid(), name, target, current: 0, isBusiness: scopeBusiness }, ...g])} /></Card>
            <Card title="Goals">
              <div className="space-y-3">
                {goals.filter(g => g.isBusiness === scopeBusiness).map((g, i) => {
                  const pct = clamp(Math.round((g.current / Math.max(1, g.target)) * 100));
                  const color = GOAL_COLORS[i % GOAL_COLORS.length];
                  return (
                    <div key={g.id} className="p-3 rounded-xl border">
                      <div className="flex justify-between items-baseline">
                        <div className="font-medium">{g.name}</div>
                        <div className="flex items-center gap-3 text-sm">
                          <div>{C(g.current, baseCurrency)} / {C(g.target, baseCurrency)} <span className="ml-2 opacity-70">• {pct}%</span></div>
                          <button
                            className="text-rose-500 underline"
                            aria-label={`Delete ${g.name}`}
                            onClick={() => deleteGoal(g.id)}
                          >
                            Delete
                          </button>
                        </div>
                      </div>
                      <div
                        className="h-2 bg-slate-200 dark:bg-slate-800 rounded-full mt-2 overflow-hidden"
                        role="progressbar"
                        aria-label={`${g.name} progress`}
                        aria-valuemin={0}
                        aria-valuemax={100}
                        aria-valuenow={pct}
                        aria-valuetext={`${pct}%`}
                      >
                        <div
                          className="h-full"
                          style={{ width: `${pct}%`, backgroundColor: color }}
                          title={`${pct}%`}
                        />
                      </div>
                      <GoalQuickAdd
                        idSuffix={g.id}
                        onAdd={(amt) =>
                          setGoals(all =>
                            all.map(x => x.id === g.id ? { ...x, current: x.current + amt } : x)
                          )
                        }
                      />
                    </div>
                  );
                })}
                {goals.filter(g => g.isBusiness === scopeBusiness).length === 0 && (
                  <div className="text-sm opacity-70">No goals yet.</div>
                )}
              </div>
            </Card>
          </section>
        )}
        {tab === "planner" && (
          <PlannerTab baseCurrency={baseCurrency} scenarios={scenarios} setScenarios={setScenarios} />
        )}
        {tab === "settings" && (
          <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card title="Backup / Restore">
              <div className="flex gap-2">
                <button className="rounded-2xl px-3 py-2 border" onClick={exportJSON} aria-label="Export JSON">Export JSON</button>
                <label className="rounded-2xl px-3 py-2 border cursor-pointer" aria-label="Import JSON">
                  Import JSON <input type="file" accept="application/json" className="hidden" onChange={(e)=>{ const f = e.target.files?.[0]; if(f) importJSON(f); }} />
                </label>
              </div>
            </Card>
            <Card title="Currencies (manual rates to base)">
              <div className="space-y-2 text-sm">
                <p className="opacity-70">Rates are relative to <b>{baseCurrency}</b>.</p>
                {Object.keys(rates).map(ccy=>(
                  <div key={ccy} className="flex items-center gap-2">
                    <div className="w-24">{ccy}</div>
                    <label className="sr-only" htmlFor={`rate-${ccy}`}>Rate for {ccy}</label>
                    <input id={`rate-${ccy}`} type="number" step="0.0001" value={rates[ccy]} onChange={(e)=> setRates(r=>({...r, [ccy]: Number(e.target.value)}))} className="border rounded-xl px-2 py-1 w-32"/>
                    {ccy!==baseCurrency && <button className="text-rose-500 underline" onClick={()=>{ const {[ccy]:_, ...rest}=rates; setRates(rest as Rates); }}>remove</button>}
                  </div>
                ))}
                <div className="flex gap-2 mt-2">
                  <label className="sr-only" htmlFor="new-ccy">New currency code</label>
                  <input id="new-ccy" placeholder="Add currency (e.g., MXN)" className="border rounded-xl px-2 py-1 w-40"/>
                  <button className="rounded-2xl px-3 py-1.5 border" onClick={()=>{ const el = document.getElementById("new-ccy") as HTMLInputElement; const code = (el.value||"").toUpperCase().slice(0,3); if(code && !rates[code]) setRates(r=>({...r, [code]: 1})); el.value=""; }}>Add currency</button>
                </div>
              </div>
            </Card>
            <Card title="Categories">
              <div className="space-y-2 text-sm">
                <div className="flex gap-2">
                  <input id="new-cat" placeholder="Add category…" className="border rounded-xl px-2 py-1"/>
                  <button className="rounded-2xl px-3 py-1.5 border"
                    onClick={() => {
                      const el = document.getElementById("new-cat") as HTMLInputElement;
                      const name = (el.value||"").trim();
                      if (name && !categoriesList.includes(name)) setCategoriesList(l=>[...l, name]);
                      el.value="";
                    }}>Add</button>
                </div>
                <ul className="space-y-1">
                  {categoriesList.map(cat=>(
                    <li key={cat} className="flex items-center gap-2">
                      <input
                        defaultValue={cat}
                        className="border rounded-xl px-2 py-1 flex-1"
                        onBlur={(e)=> renameCategory(cat, e.target.value.trim())}
                      />
                      <button className="text-rose-500 underline" onClick={()=> deleteCategoryEverywhere(cat)}>delete</button>
                    </li>
                  ))}
                </ul>
                <p className="opacity-70">Editing a name updates all places; deleting reassigns to “Other”.</p>
              </div>
            </Card>
            <Card title="Encryption (local data)">
              <EncryptionPanel encryptLocal={encryptLocal} setEncryptLocal={setEncryptLocal} locked={locked} setLocked={setLocked} />
            </Card>
          </section>
        )}
      </main>
    </div>
  );
}
function KPI({ title, value }: { title: string; value: string }) { return <div className="shadow-sm border rounded-xl p-4"><div className="text-xs opacity-70">{title}</div><div className="text-lg font-semibold">{value}</div></div>; }
function Card({ title, children, badge }: { title: string; children: React.ReactNode; badge?: string }) { return <section className="shadow-sm border rounded-xl p-4"><div className="flex items-center justify-between mb-2"><h2 className="font-semibold">{title}</h2>{badge && <span className="text-xs border rounded-full px-2 py-0.5">{badge}</span>}</div>{children}</section>; }
function TxnForm({ accounts, categories, onSubmit }: { accounts: { id: string; name: string; currency: string }[]; categories: string[]; onSubmit: (p: Partial<Txn>) => void }) {
  const [date, setDate] = useState<string>(todayISO());
  const [description, setDescription] = useState("");
  const [category, setCategory] = useState("Other");
  const [amount, setAmount] = useState<string>("0");
  const [account, setAccount] = useState<string>(accounts[0]?.id || "");
  const [tags, setTags] = useState<string>("");
  const [note, setNote] = useState<string>("");
  const [isTransfer, setIsTransfer] = useState(false);
  const [toAccount, setToAccount] = useState<string>("");
  useEffect(() => { if (accounts.length && !account) setAccount(accounts[0].id); }, [accounts, account]);
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
      <div>
        <label htmlFor="txn-date" className="text-xs opacity-70">Date</label>
        <input id="txn-date" type="date" value={date} onChange={(e) => setDate(e.target.value)} className="border rounded-xl px-2 py-1 w-full" />
      </div>
      <div>
        <label htmlFor="txn-amount" className="text-xs opacity-70">Amount</label>
        <input id="txn-amount" type="number" step="0.01" value={amount} onChange={(e) => setAmount(e.target.value)} className="border rounded-xl px-2 py-1 w-full" />
        <p className="text-xs opacity-60 mt-1">Positive = income, negative = expense.</p>
      </div>
      <div className="md:col-span-2">
        <label htmlFor="txn-desc" className="text-xs opacity-70">Description</label>
        <input id="txn-desc" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="e.g., Client payment, Lunch…" className="border rounded-xl px-2 py-1 w-full" />
      </div>
      <div>
        <label htmlFor="txn-cat" className="text-xs opacity-70">Category</label>
        <select id="txn-cat" value={category} onChange={(e) => setCategory(e.target.value)} className="border rounded-xl px-2 py-1 w-full">
          {categories.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
      </div>
      <div>
        <label htmlFor="txn-acct" className="text-xs opacity-70">Account</label>
        <select id="txn-acct" value={account} onChange={(e) => setAccount(e.target.value)} className="border rounded-xl px-2 py-1 w-full">
          {accounts.map(a => <option key={a.id} value={a.id}>{a.name} ({a.currency})</option>)}
        </select>
      </div>
      <div>
        <label htmlFor="txn-tags" className="text-xs opacity-70">Tags (comma)</label>
        <input id="txn-tags" value={tags} onChange={(e) => setTags(e.target.value)} className="border rounded-xl px-2 py-1 w-full" />
      </div>
      <div>
        <label htmlFor="txn-note" className="text-xs opacity-70">Note</label>
        <input id="txn-note" value={note} onChange={(e) => setNote(e.target.value)} className="border rounded-xl px-2 py-1 w-full" />
      </div>
      <div className="md:col-span-2">
        <label htmlFor="txn-transfer" className="inline-flex items-center gap-2 text-sm">
          <input id="txn-transfer" type="checkbox" checked={isTransfer} onChange={(e) => setIsTransfer(e.target.checked)} /> Transfer between accounts
        </label>
        {isTransfer && (
          <div className="mt-2">
            <label htmlFor="txn-to" className="sr-only">Destination account</label>
            <select id="txn-to" value={toAccount} onChange={(e) => setToAccount(e.target.value)} className="border rounded-xl px-2 py-1">
              <option value="">Select destination account</option>
              {accounts.filter(a => a.id !== account).map(a => <option key={a.id} value={a.id}>{a.name} ({a.currency})</option>)}
            </select>
          </div>
        )}
      </div>
      <div className="md:col-span-2 flex justify-end">
        <button aria-label="Add transaction" className="rounded-2xl px-3 py-2 bg-slate-900 text-white dark:bg-white dark:text-slate-900"
          onClick={() => onSubmit({
            date, description, category, amount: Number(amount), account,
            tags: tags.split(",").map(s => s.trim()).filter(Boolean), note,
            transferTo: isTransfer ? toAccount : undefined
          })}>Add</button>
      </div>
    </div>
  );
}
function BudgetForm({ categories, onAdd }: { categories: string[]; onAdd: (cat: string, limit: number) => void }) {
  const [cat, setCat] = useState("Food"); const [limit, setLimit] = useState("200");
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
      <div>
        <label htmlFor="budget-cat" className="text-xs opacity-70">Category</label>
        <select id="budget-cat" value={cat} onChange={(e) => setCat(e.target.value)} className="border rounded-xl px-2 py-1 w-full">
          {categories.filter(c => c !== "Income").map(c => <option key={c} value={c}>{c}</option>)}
        </select>
      </div>
      <div>
        <label htmlFor="budget-limit" className="text-xs opacity-70">Monthly limit (base)</label>
        <input id="budget-limit" type="number" step="1" value={limit} onChange={(e) => setLimit(e.target.value)} className="border rounded-xl px-2 py-1 w-full" />
      </div>
      <div className="md:col-span-2 flex justify-end">
        <button className="rounded-2xl px-3 py-2 border" onClick={() => onAdd(cat, Number(limit))}>Add budget</button>
      </div>
    </div>
  );
}
function AccountForm({ onAdd }: { onAdd: (name: string, currency: string) => void }) {
  const [name, setName] = useState(""); const [currency, setCurrency] = useState("USD");
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
      <div>
        <label htmlFor="acct-name" className="text-xs opacity-70">Account name</label>
        <input id="acct-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g., Personal Checking" className="border rounded-xl px-2 py-1 w-full" />
      </div>
      <div>
        <label htmlFor="acct-ccy" className="text-xs opacity-70">Currency</label>
        <input id="acct-ccy" value={currency} onChange={(e) => setCurrency(e.target.value.toUpperCase())} className="border rounded-xl px-2 py-1 w-full" />
      </div>
      <div className="md:col-span-2 flex justify-end">
        <button className="rounded-2xl px-3 py-2 border" onClick={() => { if (name.trim()) onAdd(name.trim(), currency.toUpperCase()); setName(""); }}>Add account</button>
      </div>
    </div>
  );
}
function RecurringForm({ accounts, categories, onAdd }: { accounts: { id: string; name: string; currency: string }[]; categories: string[]; onAdd: (p: Omit<Recurring, "id" | "isBusiness">) => void }) {
  const [description, setDescription] = useState(""); const [category, setCategory] = useState("Software");
  const [amount, setAmount] = useState("-10"); const [account, setAccount] = useState<string>(accounts[0]?.id || "");
  const [everyUnit, setEveryUnit] = useState<"day" | "week" | "month" | "year">("month");  
  const [everyN, setEveryN] = useState<string>("1");
  const [nextDate, setNextDate] = useState(todayISO());
  useEffect(() => { if (accounts.length && !account) setAccount(accounts[0].id); }, [accounts, account]);
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
      <div>
        <label htmlFor="rec-desc" className="text-xs opacity-70">Description</label>
        <input id="rec-desc" value={description} onChange={(e) => setDescription(e.target.value)} className="border rounded-xl px-2 py-1 w-full" />
      </div>
      <div>
        <label htmlFor="rec-amt" className="text-xs opacity-70">Amount</label>
        <input id="rec-amt" type="number" step="0.01" value={amount} onChange={(e) => setAmount(e.target.value)} className="border rounded-xl px-2 py-1 w-full" />
      </div>
      <div>
        <label htmlFor="rec-cat" className="text-xs opacity-70">Category</label>
        <select id="rec-cat" value={category} onChange={(e) => setCategory(e.target.value)} className="border rounded-xl px-2 py-1 w-full">
          {categories.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
      </div>
      <div>
        <label htmlFor="rec-acct" className="text-xs opacity-70">Account</label>
        <select id="rec-acct" value={account} onChange={(e) => setAccount(e.target.value)} className="border rounded-xl px-2 py-1 w-full">
          {accounts.map(a => <option key={a.id} value={a.id}>{a.name} ({a.currency})</option>)}
        </select>
      </div>
      <div>
        <label className="text-xs opacity-70">Every</label>
        <div className="flex gap-2">
          <input aria-label="Every N" type="number" min={1} value={everyN} onChange={(e)=>setEveryN(e.target.value)} className="border rounded-xl px-2 py-1 w-20" />
          <select aria-label="Unit" value={everyUnit} onChange={(e)=>setEveryUnit(e.target.value as any)} className="border rounded-xl px-2 py-1 w-full">
            <option value="day">day(s)</option>
            <option value="week">week(s)</option>
            <option value="month">month(s)</option>
            <option value="year">year(s)</option>
          </select>
        </div>
        <div className="text-[11px] opacity-60 mt-1">Examples: biweekly = every 2 weeks; quarterly = every 3 months.</div>
      </div>
      <div>
        <label htmlFor="rec-next" className="text-xs opacity-70">Next date</label>
        <input id="rec-next" type="date" value={nextDate} onChange={(e) => setNextDate(e.target.value)} className="border rounded-xl px-2 py-1 w-full" />
      </div>
      <div className="md:col-span-2 flex justify-end">
        <button className="rounded-2xl px-3 py-2 border" onClick={() => { onAdd({ description, category, amount: Number(amount), account, everyUnit, everyN: Math.max(1, Number(everyN) || 1), nextDate }); setDescription(""); }}>Add recurring</button>
      </div>
    </div>
  );
}
function Field({ label, children, span=false }: { label: string; children: React.ReactNode; span?: boolean }) {
  return (
    <label className={`${span ? "md:col-span-2" : ""} block`}>
      <span className="text-xs opacity-70 block mb-1">{label}</span>
      {children}
    </label>
  );
}
function RuleForm({ categories, onAdd }: { categories: string[]; onAdd: (r: Omit<Rule,"id"|"isBusiness">) => void }) {
  const [type, setType] = useState<"contains"|"regex">("contains");
  const [pattern, setPattern] = useState(""); const [thenCategory, setThenCategory] = useState("Other");
  const [minA, setMinA] = useState(""); const [maxA, setMaxA] = useState("");
  const [testText, setTestText] = useState(""); const [testAmt, setTestAmt] = useState("");
  const testHit = useMemo(()=>{
    const temp: Rule = { id:"0", isBusiness: false, type, pattern, thenCategory, minAmount: minA===""?undefined:Number(minA), maxAmount: maxA===""?undefined:Number(maxA) };
    const cat = applyRules(testText, Number(testAmt||0), [temp]);
    return cat ? `→ ${cat}` : "no match";
  }, [type, pattern, thenCategory, minA, maxA, testText, testAmt]);
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
      <Field label="Rule type">
        <select value={type} onChange={(e)=>setType(e.target.value as any)} className="border rounded-xl px-2 py-1 w-full">
          <option value="contains">Contains</option><option value="regex">Regex</option>
        </select>
      </Field>
      <Field label={type==="regex"?"Pattern (RegEx)":"Text"}>
        <input value={pattern} onChange={(e)=>setPattern(e.target.value)} className="border rounded-xl px-2 py-1 w-full"/>
      </Field>
      <Field label="Then category"><select value={thenCategory} onChange={(e)=>setThenCategory(e.target.value)} className="border rounded-xl px-2 py-1 w-full">{categories.map(c=> <option key={c} value={c}>{c}</option>)}</select></Field>
      <Field label="Amount range (optional)">
        <div className="flex gap-2"><input placeholder="min" type="number" value={minA} onChange={(e)=>setMinA(e.target.value)} className="border rounded-xl px-2 py-1 w-32"/><input placeholder="max" type="number" value={maxA} onChange={(e)=>setMaxA(e.target.value)} className="border rounded-xl px-2 py-1 w-32"/></div>
      </Field>
      <Field label="Test: description"><input value={testText} onChange={(e)=>setTestText(e.target.value)} className="border rounded-xl px-2 py-1 w-full"/></Field>
      <Field label="Test: amount"><input value={testAmt} type="number" onChange={(e)=>setTestAmt(e.target.value)} className="border rounded-xl px-2 py-1 w-full"/></Field>
      <div className="md:col-span-2 flex items-center justify-between">
        <div className="text-sm opacity-70">Test result: <b>{testHit}</b></div>
        <button className="rounded-2xl px-3 py-2 border" onClick={()=> onAdd({ type, pattern, thenCategory, minAmount: minA===""?undefined:Number(minA), maxAmount: maxA===""?undefined:Number(maxA) })}>Add rule</button>
      </div>
    </div>
  );
}
function SplitButton({ txn, categories, onSplit }: { txn: Txn; categories: string[]; onSplit: (parts: { category: string; amount: number }[]) => void }) {
  const [open, setOpen] = useState(false);
  const [rows, setRows] = useState([{ id: uid(), category: txn.category, amount: txn.amount }]);
  return (
    <>
      <button className="underline" onClick={()=>setOpen(true)}>Split</button>
      {open && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm grid place-items-center p-4 z-50" role="dialog" aria-modal="true">
          <div className="bg-white dark:bg-slate-900 w-full max-w-lg rounded-2xl p-4 border border-slate-200 dark:border-slate-700 text-slate-900 dark:text-slate-100 shadow-2xl ring-1 ring-black/5">
            <div className="flex items-center justify-between mb-2"><h3 className="font-semibold">Split transaction</h3><button onClick={()=>setOpen(false)}>✕</button></div>
            <div className="text-xs opacity-70 mb-2">Original amount: {txn.amount}</div>
            <div className="space-y-2 max-h-64 overflow-auto">
              {rows.map((r,i)=>(
                <div key={r.id} className="grid grid-cols-3 gap-2">
                  <select value={r.category} onChange={(e)=> setRows(rs=> rs.map(x=> x.id===r.id? {...x, category:e.target.value}:x))} className="border rounded-xl px-2 py-1 col-span-2">{categories.map(c=> <option key={c} value={c}>{c}</option>)}</select>
                  <input type="number" step="0.01" value={r.amount} onChange={(e)=> setRows(rs=> rs.map(x=> x.id===r.id? {...x, amount: Number(e.target.value)}:x))} className="border rounded-xl px-2 py-1"/>
                </div>
              ))}
            </div>
            <div className="flex items-center justify-between mt-3">
              <button className="rounded-xl px-3 py-1 border" onClick={()=> setRows(rs=> [...rs, { id: uid(), category: "Other", amount: 0 }])}>+ Add part</button>
              <div className="flex gap-2">
                <button className="rounded-xl px-3 py-1 border" onClick={()=>setOpen(false)}>Cancel</button>
                <button className="rounded-xl px-3 py-1 bg-slate-900 text-white dark:bg-white dark:text-slate-900" onClick={()=>{ onSplit(rows.map(({category,amount})=>({category,amount}))); setOpen(false); }}>Apply</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
function EditTxnModal({
  open, onClose, txn, accounts, categories, onSave
}: {
  open: boolean; onClose: () => void;
  txn: Txn; accounts: Account[]; categories: string[];
  onSave: (patch: Partial<Txn>) => void;
}) {
  const [date, setDate] = useState(txn.date);
  const [description, setDescription] = useState(txn.description);
  const [category, setCategory] = useState(txn.category);
  const [amount, setAmount] = useState(String(txn.amount));
  const [account, setAccount] = useState(txn.account);
  const [tags, setTags] = useState((txn.tags || []).join(", "));
  const [note, setNote] = useState(txn.note || "");
  useEffect(() => {
    if (!open) return;
    setDate(txn.date);
    setDescription(txn.description);
    setCategory(txn.category);
    setAmount(String(txn.amount));
    setAccount(txn.account);
    setTags((txn.tags || []).join(", "));
    setNote(txn.note || "");
  }, [open, txn]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm grid place-items-center p-4 z-50" role="dialog" aria-modal="true">
      <div className="bg-white dark:bg-slate-900 w-full max-w-lg rounded-2xl p-4 border border-slate-200 dark:border-slate-700 text-slate-900 dark:text-slate-100 shadow-2xl ring-1 ring-black/5">
        <div className="flex items-center justify-between mb-2">
          <h3 className="font-semibold">Edit transaction</h3>
          <button onClick={onClose}>✕</button>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <label className="text-xs opacity-70">Date
            <input type="date" value={date} onChange={e=>setDate(e.target.value)} className="border rounded-xl px-2 py-1 w-full"/>
          </label>
          <label className="text-xs opacity-70">Amount
            <input type="number" step="0.01" value={amount} onChange={e=>setAmount(e.target.value)} className="border rounded-xl px-2 py-1 w-full"/>
          </label>
          <label className="text-xs opacity-70 md:col-span-2">Description
            <input value={description} onChange={e=>setDescription(e.target.value)} className="border rounded-xl px-2 py-1 w-full"/>
          </label>
          <label className="text-xs opacity-70">Category
            <select value={category} onChange={e=>setCategory(e.target.value)} className="border rounded-xl px-2 py-1 w-full">
              {categories.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
          </label>
          <label className="text-xs opacity-70">Account
            <select value={account} onChange={e=>setAccount(e.target.value)} className="border rounded-xl px-2 py-1 w-full">
              {accounts.map(a => <option key={a.id} value={a.id}>{a.name} ({a.currency})</option>)}
            </select>
          </label>
          <label className="text-xs opacity-70">Tags (comma)
            <input value={tags} onChange={e=>setTags(e.target.value)} className="border rounded-xl px-2 py-1 w-full"/>
          </label>
          <label className="text-xs opacity-70">Note
            <input value={note} onChange={e=>setNote(e.target.value)} className="border rounded-xl px-2 py-1 w-full"/>
          </label>
        </div>
        <div className="flex justify-end gap-2 mt-3">
          <button className="rounded-xl px-3 py-1 border" onClick={onClose}>Cancel</button>
          <button
            className="rounded-xl px-3 py-1 bg-slate-900 text-white dark:bg-white dark:text-slate-900"
            onClick={()=>{
              onSave({
                date, description, category,
                amount: Number(amount), account,
                tags: tags.split(",").map(s=>s.trim()).filter(Boolean),
                note
              });
              onClose();
            }}
          >Save</button>
        </div>
      </div>
    </div>
  );
}
function GoalForm({ onAdd }: { onAdd: (name: string, target: number) => void }) {
  const [name, setName] = useState(""); const [target, setTarget] = useState("1000");
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
      <div>
        <label htmlFor="goal-name" className="text-xs opacity-70">Goal name</label>
        <input id="goal-name" value={name} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setName(e.target.value)} placeholder="e.g., Emergency Fund" className="border rounded-xl px-2 py-1 w-full" />
      </div>
      <div>
        <label htmlFor="goal-target" className="text-xs opacity-70">Target amount</label>
        <input id="goal-target" type="number" step="1" value={target} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setTarget(e.target.value)} className="border rounded-xl px-2 py-1 w-full" />
      </div>
      <div className="md:col-span-2 flex justify-end">
        <button className="rounded-2xl px-3 py-2 border" onClick={() => { const t = Number(target); if (name.trim() && !isNaN(t)) onAdd(name.trim(), t); }}>Add goal</button>
      </div>
    </div>
  );
}
function GoalQuickAdd({ idSuffix, onAdd }: { idSuffix: string; onAdd: (amount: number) => void }) {
  const inputId = `goal-add-${idSuffix}`;
  return (
    <div className="flex gap-2 mt-2">
      <label htmlFor={inputId} className="sr-only">Add amount</label>
      <input id={inputId} type="number" step="1" placeholder="Add amount" className="border rounded-xl px-2 py-1 w-32" />
      <button className="rounded-2xl px-3 py-1.5 border" onClick={() => {
        const el = document.getElementById(inputId) as HTMLInputElement;
        const v = Number(el?.value || 0);
        if (!isNaN(v) && v > 0) { onAdd(v); el.value = ""; }
      }}>Add to goal</button>
    </div>
  );
}
function PlannerTab({ baseCurrency, scenarios, setScenarios }: { baseCurrency: string; scenarios: Scenario[]; setScenarios: React.Dispatch<React.SetStateAction<Scenario[]>> }) {
  const [leftId, setLeftId] = useState<string>(""); const [rightId, setRightId] = useState<string>("");
  return (
    <section className="grid grid-cols-1 xl:grid-cols-2 gap-6">
      <Card title="Savings Projection (with APY, Inflation, Tax)">
        <SavingsPlanner baseCurrency={baseCurrency} scenarios={scenarios} setScenarios={setScenarios} side="left" setChosen={setLeftId}/>
      </Card>
      <Card title="Debt Optimizer (Multi-debt, Snowball/Avalanche)">
        <DebtPlanner baseCurrency={baseCurrency} scenarios={scenarios} setScenarios={setScenarios} side="right" setChosen={setRightId}/>
      </Card>
      <Card title="Compare Scenarios">
        <ComparePanel baseCurrency={baseCurrency} scenarios={scenarios} leftId={leftId} rightId={rightId}/>
      </Card>
      <Card title="Saved Scenarios">
        {scenarios.length ? (
          <ul className="space-y-2 text-sm">
            {scenarios.map(s => (
              <li key={s.id} className="flex items-center justify-between border rounded-xl p-2">
                <div className="truncate">{s.name}</div>
                <div className="flex items-center gap-2">
                  <button
                    className="underline"
                    onClick={()=> { setLeftId(s.id); }}
                    aria-label="Use on left"
                  >Use left</button>
                  <button
                    className="underline"
                    onClick={()=> { setRightId(s.id); }}
                    aria-label="Use on right"
                  >Use right</button>
                  <button
                    className="text-rose-500 underline"
                    onClick={()=> setScenarios(list => list.filter(x => x.id !== s.id))}
                    aria-label={`Delete ${s.name}`}
                  >Delete</button>
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <div className="text-sm opacity-70">No scenarios saved yet.</div>
        )}
      </Card>
    </section>
  );
}
function parsePattern(input: string): number[] {
  return input.split(/[,\s]+/).map(x => Number(x)).filter(x => Number.isFinite(x));
}
const addMonthsISO = (iso: string, months: number) => { const d = new Date(iso); d.setMonth(d.getMonth()+months); return d.toISOString().slice(0,10); };
const fmtMonth = (ym: string) => {
  const [y, m] = ym.split("-").map(Number);
  const d = new Date(y, (m - 1), 1);
  return d.toLocaleDateString(undefined, { month: "short", year: "numeric" });
};
const addYM = (ym: string, delta: number) => {
  const [y, m] = ym.split("-").map(Number); // m = 1..12
  const total = y * 12 + (m - 1) + delta;
  const ny = Math.floor(total / 12);
  const nm = (total % 12) + 1;
  return `${ny}-${String(nm).padStart(2, "0")}`;
};
const monthsBetween = (fromIso: string, toExclusiveIso: string) => {
  const out: string[] = [];
  let cur = fromIso.slice(0, 7);
  const end = toExclusiveIso.slice(0, 7);
  while (cur < end) {
    out.push(cur);
    cur = addYM(cur, 1);
  }
  return out;
};
type SavingsPoint = { month: string; balance: number; contrib: number; interest: number; totalContrib: number };
function SavingsPlanner({ baseCurrency, scenarios, setScenarios, side, setChosen }:{
  baseCurrency: string; scenarios: Scenario[]; setScenarios: React.Dispatch<React.SetStateAction<Scenario[]>>;
  side:"left"|"right"; setChosen: (id:string)=>void;
}) {
  const [name, setName] = useState("My savings plan");
  const [startDate, setStartDate] = useState<string>(todayISO());
  const [current, setCurrent] = useState<string>("2500");
  const [target, setTarget] = useState<string>("10000");
  const [baseMonthly, setBaseMonthly] = useState<string>("300");
  const [apy, setApy] = useState<string>("4");       // APY %
  const [infl, setInfl] = useState<string>("2");     // Inflation %
  const [tax, setTax] = useState<string>("0");       // Effective tax on interest %
  const [pattern, setPattern] = useState<string>("100, 200, 50");
  const { schedule, hitIndex } = useMemo(() => {
    const c = Math.max(0, Number(current) || 0);
    const t = Math.max(0, Number(target) || 0);
    const base = Math.max(0, Number(baseMonthly) || 0);
    const apyPct = Math.max(0, Number(apy) || 0);
    const inflPct = Math.max(0, Number(infl) || 0);
    const taxPct = Math.max(0, Number(tax) || 0);
    const monthlyGross = apyPct/100/12;
    const monthlyInfl = inflPct/100/12;
    const monthlyNet = Math.max(0, monthlyGross * (1 - taxPct/100) - monthlyInfl); // real after-tax monthly rate
    const pat = parsePattern(pattern);
    const out: SavingsPoint[] = [];
    let bal = c, totalContrib = 0, hit = -1;
    for (let i=0;i<600;i++){
      const monthISO = addMonthsISO(startDate, i).slice(0,7);
      const extra = pat.length ? pat[i % pat.length] : 0;
      const contrib = base + Math.max(0, extra);
      totalContrib += contrib;
      bal += contrib;
      const interest = bal * monthlyNet;
      bal += interest;
      out.push({ month: monthISO, balance: bal, contrib, interest, totalContrib });
      if (hit===-1 && t>0 && bal>=t) hit = i;
    }
    return { schedule: out, hitIndex: hit };
  }, [startDate, current, target, baseMonthly, apy, infl, tax, pattern]);
  const hitDate = hitIndex>=0 ? addMonthsISO(startDate, hitIndex) : null;
  const [rangeMonths, setRangeMonths] = useState<number>(120);
  const [chartFrom, setChartFrom] = useState<string>(startDate);
  const [chartTo, setChartTo] = useState<string>("");
  const visibleSchedule = useMemo(() => {
    const sliced = Number.isFinite(rangeMonths) ? schedule.slice(0, rangeMonths) : schedule;
    const fromKey = (chartFrom || startDate).slice(0, 7);
    const toKey = chartTo ? chartTo.slice(0, 7) : "";
    return sliced.filter(p => p.month >= fromKey && (toKey ? p.month <= toKey : true));
  }, [schedule, rangeMonths, chartFrom, chartTo, startDate]);
  function saveScenario() {
    const sc: Scenario = {
      id: uid(), name,
      savings: { start: startDate, current: Number(current)||0, target: Number(target)||0, base: Number(baseMonthly)||0, apyPct: Number(apy)||0, inflationPct: Number(infl)||0, taxPct: Number(tax)||0, pattern }
    };
    setScenarios(s => [sc, ...s]); setChosen(sc.id);
  }
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Field label="Scenario name"><input value={name} onChange={(e)=>setName(e.target.value)} className="border rounded-xl px-2 py-1 w-full"/></Field>
        <Field label="Start date"><input type="date" value={startDate} onChange={(e)=>setStartDate(e.target.value)} className="border rounded-xl px-2 py-1 w-full"/></Field>
        <Field label="Current balance"><input type="number" value={current} onChange={(e)=>setCurrent(e.target.value)} className="border rounded-xl px-2 py-1 w-full"/></Field>
        <Field label="Target"><input type="number" value={target} onChange={(e)=>setTarget(e.target.value)} className="border rounded-xl px-2 py-1 w-full"/></Field>
        <Field label="Base monthly contribution"><input type="number" value={baseMonthly} onChange={(e)=>setBaseMonthly(e.target.value)} className="border rounded-xl px-2 py-1 w-full"/></Field>
        <Field label="APY %"><input type="number" step="0.01" value={apy} onChange={(e)=>setApy(e.target.value)} className="border rounded-xl px-2 py-1 w-full"/></Field>
        <Field label="Inflation %"><input type="number" step="0.01" value={infl} onChange={(e)=>setInfl(e.target.value)} className="border rounded-xl px-2 py-1 w-full"/></Field>
        <Field label="Tax on interest %"><input type="number" step="0.01" value={tax} onChange={(e)=>setTax(e.target.value)} className="border rounded-xl px-2 py-1 w-full"/></Field>
        <Field label="Extra pattern (repeats)"><input placeholder="e.g., 100, 200, 50" value={pattern} onChange={(e)=>setPattern(e.target.value)} className="border rounded-xl px-2 py-1 w-full"/></Field>
      </div>
      <div className="rounded-xl border p-3 text-sm">
        {hitDate ? <>You’ll hit the target around <b>{hitDate}</b>.</> : <span className="opacity-70">Target not reached within 50 years. Increase contributions or APY.</span>}
      </div>
      <div className="flex gap-2 justify-end text-xs">
        <span className="opacity-70 self-center">Range:</span>
        <button className="border rounded-xl px-2 py-1" onClick={()=>setRangeMonths(12)}>1Y</button>
        <button className="border rounded-xl px-2 py-1" onClick={()=>setRangeMonths(36)}>3Y</button>
        <button className="border rounded-xl px-2 py-1" onClick={()=>setRangeMonths(60)}>5Y</button>
        <button className="border rounded-xl px-2 py-1" onClick={()=>setRangeMonths(120)}>10Y</button>
        <button className="border rounded-xl px-2 py-1" onClick={()=>setRangeMonths(NaN)}>All</button>
        <span className="opacity-70 self-center ml-2">From</span>
        <input type="date" value={chartFrom} onChange={e=>setChartFrom(e.target.value)} className="border rounded-xl px-2 py-1" />
        <span className="opacity-70 self-center">to</span>
        <input type="date" value={chartTo} onChange={e=>setChartTo(e.target.value)} className="border rounded-xl px-2 py-1" />
      </div>
      <div className="h-56">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={visibleSchedule}>
            <CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="month" allowDuplicatedCategory={false} tickFormatter={fmtMonth}/><YAxis width={90} tickFormatter={(v)=>C(v, baseCurrency)}/>
            <Tooltip formatter={(v:number)=>C(v, baseCurrency)} />
            <Area type="monotone" dataKey="balance" name="Balance (real)" stroke="#0ea5e9" fillOpacity={0.25}/>
            <Line type="monotone" dataKey="totalContrib" name="Total Contributed" stroke="#22c55e"/>
            {hitDate && (
              <ReferenceLine
                x={hitDate.slice(0, 7)}
                stroke="#10b981"
                strokeDasharray="4 4"
                label={{ value: "Target hit", position: "insideTop" }}
              />
            )}
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <div className="flex justify-end gap-2">
        <button className="rounded-xl px-3 py-1.5 border" onClick={saveScenario}>Save scenario</button>
      </div>
    </div>
  );
}
type DebtPoint = { month: string; principal: number; payment: number; interest: number; totalInterest: number };
function DebtPlanner({ baseCurrency, scenarios, setScenarios, side, setChosen }:{
  baseCurrency: string; scenarios: Scenario[]; setScenarios: React.Dispatch<React.SetStateAction<Scenario[]>>;
  side:"left"|"right"; setChosen:(id:string)=>void;
}) {
  const [name, setName] = useState("My debt plan");
  const [startDate, setStartDate] = useState<string>(todayISO());
  const [items, setItems] = useState<DebtItem[]>([
    { id: uid(), name: "Car", balance: 12000, aprPct: 5.9, minPayment: 220 },
    { id: uid(), name: "Card", balance: 3500, aprPct: 18.9, minPayment: 75 },
  ]);
  const [strategy, setStrategy] = useState<"snowball"|"avalanche">("avalanche");
  const [extra, setExtra] = useState<string>("200");
  const [extraStart, setExtraStart] = useState<string>(startDate);
  const [rangeMonths, setRangeMonths] = useState<number>(120);
  const [chartFrom, setChartFrom] = useState<string>(startDate);
  const [chartTo, setChartTo] = useState<string>("");
  const result = useMemo(()=> runDebtPlan(items, strategy, Number(extra)||0, startDate, extraStart), [items, strategy, extra, startDate, extraStart]);
  const payoffDate = result.payoffIndex>=0 ? addMonthsISO(startDate, result.payoffIndex) : null;
  const visibleDebt = useMemo(()=> {
    const sliced = Number.isFinite(rangeMonths) ? result.schedule.slice(0, rangeMonths) : result.schedule;
    const fromKey = (chartFrom || startDate).slice(0,7);
    const toKey = chartTo ? chartTo.slice(0,7) : "";
    return sliced.filter(p => p.month >= fromKey && (toKey ? p.month <= toKey : true));
  }, [result.schedule, rangeMonths, chartFrom, chartTo, startDate]);
  function saveScenario() {
    const sc: Scenario = { id: uid(), name, debts: { strategy, items, extra: Number(extra)||0, start: startDate } };
    setScenarios(s => [sc, ...s]); setChosen(sc.id);
  }
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Field label="Scenario name"><input value={name} onChange={(e)=>setName(e.target.value)} className="border rounded-xl px-2 py-1 w-full"/></Field>
        <Field label="Start date"><input type="date" value={startDate} onChange={(e)=>setStartDate(e.target.value)} className="border rounded-xl px-2 py-1 w-full"/></Field>
      </div>
      <div className="rounded-xl border p-3 space-y-2">
        <div className="flex items-center justify-between">
          <div className="font-medium">Debts</div>
          <button className="rounded-xl px-3 py-1 border" onClick={()=> setItems(v=> [...v, { id: uid(), name:"New debt", balance: 1000, aprPct: 10, minPayment: 25 }])}>+ Add</button>
        </div>
        {items.map(d=>(
          <div key={d.id} className="grid grid-cols-5 gap-2 items-end">
            <Field label="Name">
              <input
                value={d.name}
                onChange={(e)=> setItems(v=> v.map(x=> x.id===d.id? {...x, name:e.target.value}:x))}
                className="border rounded-xl px-2 py-1 w-full"
              />
            </Field>
            <Field label="Balance">
              <input
                type="number"
                value={d.balance}
                onChange={(e)=> setItems(v=> v.map(x=> x.id===d.id? {...x, balance:Number(e.target.value)}:x))}
                className="border rounded-xl px-2 py-1 w-full"
              />
            </Field>
            <Field label="APR %">
              <input
                type="number" step="0.01"
                value={d.aprPct}
                onChange={(e)=> setItems(v=> v.map(x=> x.id===d.id? {...x, aprPct:Number(e.target.value)}:x))}
                className="border rounded-xl px-2 py-1 w-full"
              />
            </Field>
            <Field label="Min payment">
              <input
                type="number"
                value={d.minPayment}
                onChange={(e)=> setItems(v=> v.map(x=> x.id===d.id? {...x, minPayment:Number(e.target.value)}:x))}
                className="border rounded-xl px-2 py-1 w-full"
              />
            </Field>
            <div className="self-end">
              <button className="text-rose-500 underline" onClick={()=> setItems(v=> v.filter(x=> x.id!==d.id))}>
                remove
              </button>
            </div>
          </div>
        ))}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
          <Field label="Strategy"><select value={strategy} onChange={(e)=>setStrategy(e.target.value as any)} className="border rounded-xl px-2 py-1 w-full"><option value="snowball">Snowball (smallest balance)</option><option value="avalanche">Avalanche (highest APR)</option></select></Field>
          <Field label="Extra monthly budget"><input type="number" value={extra} onChange={(e)=>setExtra(e.target.value)} className="border rounded-xl px-2 py-1 w-full"/></Field>
          <Field label="Extra starts on">
            <input type="date" value={extraStart} onChange={e=>setExtraStart(e.target.value)} className="border rounded-xl px-2 py-1 w-full" />
          </Field>
        </div>
      </div>
      <div className="rounded-xl border p-3 text-sm space-y-1">
        {payoffDate ? <>Projected payoff around <b>{payoffDate}</b> ({result.payoffIndex+1} months).</> : <span className="opacity-70">Not paid off within 100 years.</span>}
        <div>Total interest: <b>{C(result.totalInterest, baseCurrency)}</b></div>
        {result.baselineMonths && <div>Months saved vs minimums only: <b>{result.baselineMonths - (result.payoffIndex+1)}</b></div>}
      </div>
      <div className="flex gap-2 justify-end text-xs">
        <span className="opacity-70 self-center">Range:</span>
        <button className="border rounded-xl px-2 py-1" onClick={()=>setRangeMonths(12)}>1Y</button>
        <button className="border rounded-xl px-2 py-1" onClick={()=>setRangeMonths(36)}>3Y</button>
        <button className="border rounded-xl px-2 py-1" onClick={()=>setRangeMonths(60)}>5Y</button>
        <button className="border rounded-xl px-2 py-1" onClick={()=>setRangeMonths(120)}>10Y</button>
        <button className="border rounded-xl px-2 py-1" onClick={()=>setRangeMonths(NaN)}>All</button>
        <span className="opacity-70 self-center ml-2">From</span>
        <input type="date" value={chartFrom} onChange={e=>setChartFrom(e.target.value)} className="border rounded-xl px-2 py-1" />
        <span className="opacity-70 self-center">to</span>
        <input type="date" value={chartTo} onChange={e=>setChartTo(e.target.value)} className="border rounded-xl px-2 py-1" />
      </div>
      <div className="h-56">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={visibleDebt}>
            <CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="month" allowDuplicatedCategory={false} tickFormatter={fmtMonth}/><YAxis width={90} tickFormatter={(v)=>C(v, baseCurrency)}/>
            <Tooltip formatter={(v:number)=>C(v, baseCurrency)} />
            <Area type="monotone" dataKey="principal" name="Remaining Principal" stroke="#ef4444" fillOpacity={0.25}/>
            <Line type="monotone" dataKey="totalInterest" name="Cumulative Interest" stroke="#0ea5e9"/>
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <div className="flex justify-end gap-2"><button className="rounded-xl px-3 py-1.5 border" onClick={saveScenario}>Save scenario</button></div>
    </div>
  );
}
function runDebtPlan(
  items: DebtItem[],
  strategy: "snowball"|"avalanche",
  extra: number,
  startDate: string,
  extraStartDate?: string
) {
  const rMonthly = (apr:number)=> apr/100/12;
  const sortBy = strategy==="snowball"
    ? (a:DebtItem,b:DebtItem)=> a.balance-b.balance
    : (a:DebtItem,b:DebtItem)=> b.aprPct-a.aprPct;
  function simulate(extraBudget:number) {
    let month = 0, totalInterest = 0;
    const out: DebtPoint[] = [];
    let debts = items.map(d=> ({...d}));
    while (debts.some(d=> d.balance>0) && month<1200) {
      debts.sort(sortBy);
      const thisMonthISO = addMonthsISO(startDate, month);
      let extraLeft = (!extraStartDate || thisMonthISO >= extraStartDate) ? extraBudget : 0;
      let interestThisMonth = 0;
      let paymentThisMonth = 0;
      for (const d of debts) {
        if (d.balance<=0) continue;
        const interest = d.balance * rMonthly(d.aprPct);
        const pay = Math.min(d.balance + interest, Math.max(d.minPayment, 0));
        d.balance = Math.max(0, d.balance + interest - pay);
        interestThisMonth += interest; paymentThisMonth += pay;
      }
      for (const d of debts) {
        if (extraLeft<=0) break;
        if (d.balance<=0) continue;
        const take = Math.min(extraLeft, d.balance);
        d.balance -= take; extraLeft -= take; paymentThisMonth += take;
      }
      totalInterest += interestThisMonth;
      const totalBal = debts.reduce((a,b)=> a + Math.max(0,b.balance), 0);
      out.push({ month: addMonthsISO(startDate, month).slice(0,7), principal: totalBal, payment: paymentThisMonth, interest: interestThisMonth, totalInterest });
      if (totalBal<=0) return { schedule: out, payoffIndex: month, totalInterest };
      month++;
    }
    return { schedule: out, payoffIndex: -1, totalInterest };
  }
  const baseline = simulate(0);
  const withExtra = simulate(extra);
  return { ...withExtra, baselineMonths: baseline.payoffIndex>=0 ? baseline.payoffIndex+1 : null };
}
function ComparePanel({ baseCurrency, scenarios, leftId, rightId }:{ baseCurrency:string; scenarios:Scenario[]; leftId:string; rightId:string }) {
  const left = scenarios.find(s=>s.id===leftId) || scenarios[0];
  const right = scenarios.find(s=>s.id===rightId) || scenarios[1];
  if (!left || !right) {
    return <div className="text-sm opacity-70">Save two scenarios from the planners above, then pick them here to compare.</div>;
  }
  const leftName = left.name, rightName = right.name;
  const leftSummary = summarizeScenario(left);
  const rightSummary = summarizeScenario(right);
  return (
    <div className="space-y-2 text-sm">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div className="rounded-xl border p-3"><div className="font-medium mb-1">{leftName}</div>{leftSummary}</div>
        <div className="rounded-xl border p-3"><div className="font-medium mb-1">{rightName}</div>{rightSummary}</div>
      </div>
    </div>
  );
  function summarizeScenario(s: Scenario) {
    if (s.savings) {
      const { start, current, target, base, apyPct, inflationPct, taxPct, pattern } = s.savings;
      let bal = current, hit=-1; const pat = parsePattern(pattern); const r = Math.max(0, (apyPct/100/12) * (1 - (taxPct/100)) - (inflationPct/100/12));
      for (let i=0;i<600;i++){ const contrib = base + (pat.length? pat[i%pat.length]:0); bal += contrib; bal += bal*r; if (hit===-1 && bal>=target) hit=i; }
      return hit>=0 ? <>Hits target in <b>{hit+1}</b> months (~{addMonthsISO(start, hit)}).</> : <>Doesn’t reach target within 50 years.</>;
    }
    if (s.debts) {
      const res = runDebtPlan(s.debts.items, s.debts.strategy, s.debts.extra, s.debts.start);
      return res.payoffIndex>=0 ? <>Pays off in <b>{res.payoffIndex+1}</b> months; interest {C(res.totalInterest, baseCurrency)}.</> : <>Not paid off within 100 years.</>;
    }
    return <>Empty scenario.</>;
  }
}
function EncryptionPanel({ encryptLocal, setEncryptLocal, locked, setLocked }:{
  encryptLocal:boolean; setEncryptLocal:(v:boolean)=>void; locked:boolean; setLocked:(v:boolean)=>void;
}) {
  const [pass, setPass] = useState(getPassphrase());
  return (
    <div className="space-y-2 text-sm">
      <div className="flex items-center gap-2"><input id="enc-toggle" type="checkbox" checked={encryptLocal} onChange={(e)=>setEncryptLocal(e.target.checked)} /><label htmlFor="enc-toggle">Encrypt local data (AES-GCM)</label></div>
      <div className="flex items-center gap-2">
        <label htmlFor="enc-pass" className="w-28">Passphrase</label>
        <input id="enc-pass" type="password" value={pass} onChange={(e)=>setPass(e.target.value)} className="border rounded-xl px-2 py-1"/>
        <button className="rounded-xl px-3 py-1 border" onClick={()=>{ setPassphrase(pass); if (locked && pass) { location.reload(); } }}>Set</button>
      </div>
      <p className="opacity-70">Stored encrypted when enabled. Passphrase is kept only for this browser session.</p>
    </div>
  );
}