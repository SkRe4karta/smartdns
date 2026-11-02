import { useEffect, useState } from "react";
import {
  Activity,
  ShieldCheck,
  Globe2,
  TriangleAlert,
  Users,
  RefreshCw,
} from "lucide-react";
import { api, date, number } from "./api";
export type Notice = (message: string, error?: boolean) => void;
type Bucket = {
  at: number;
  total: number;
  blocked: number;
  proxied: number;
  errors: number;
};
type Event = {
  id: number;
  at: number;
  username: string | null;
  client_ip: string | null;
  domain: string;
  qtype: string;
  result: string;
  rcode: string | null;
  reason: string | null;
  elapsed_ms: number;
  key_version: number | null;
  transport: string | null;
};
type Overview = {
  totals: Omit<Bucket, "at">;
  buckets: Bucket[];
  users: number;
  active_users: number;
  mean_dns_ms: number | null;
  recent_errors: Event[];
};
const reasons: Record<string, string> = {
  filtered: "Фильтрация",
  name_not_found: "Домен не существует",
  rate_limited: "Лимит запросов",
  unsupported_query: "Неподдерживаемый запрос",
  admission_unavailable: "Допуск не выдан",
  exit_unavailable: "Выход недоступен",
  admission_timeout: "Таймаут допуска",
  upstream_timeout: "Таймаут резолвера",
  upstream_network: "Ошибка сети резолвера",
  upstream_dns_error: "Ошибка ответа резолвера",
  invalid_upstream: "Некорректный ответ",
  queue_timeout: "Очередь занята",
  unknown_key: "Неизвестный ключ",
  malformed_query: "Некорректный запрос",
};
function useRemote<T>(path: string, notice: Notice, revision = 0) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let live = true;
    setLoading(true);
    api<T>(path)
      .then((x) => {
        if (live) setData(x);
      })
      .catch((e) => notice(e.message, true))
      .finally(() => {
        if (live) setLoading(false);
      });
    return () => {
      live = false;
    };
  }, [path, revision]);
  return { data, loading };
}
export function EventTable({ rows }: { rows: Event[] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Время / пользователь</th>
            <th>Домен / тип</th>
            <th>IP / протокол</th>
            <th>Результат</th>
            <th>Задержка</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td>
                {date(r.at)}
                <small className="block">
                  {r.username || "Не установлен"}
                  {r.key_version != null && ` · ключ v${r.key_version}`}
                </small>
              </td>
              <td>
                <span className="mono">{r.domain || "—"}</span>
                <small className="block">{r.qtype || "—"}</small>
              </td>
              <td>
                <span className="mono">
                  {r.client_ip || "Нет старых данных"}
                </span>
                <small className="block">
                  {r.transport?.toUpperCase() || "—"}
                </small>
              </td>
              <td>
                <span
                  className={
                    "pill " +
                    (r.result === "error"
                      ? "red"
                      : r.result === "blocked"
                        ? "amber"
                        : "green")
                  }
                >
                  {r.rcode || r.result}
                </span>
                <small className="block">
                  {r.reason
                    ? reasons[r.reason] || r.reason
                    : {
                        allowed: "Прямое разрешение",
                        proxied: "Через выход",
                        nxdomain: "Нет домена",
                      }[r.result] || r.result}
                </small>
              </td>
              <td>{number(r.elapsed_ms)} мс</td>
            </tr>
          ))}
        </tbody>
      </table>
      {!rows.length && (
        <div className="empty">За выбранный период записей нет.</div>
      )}
    </div>
  );
}
export function GlobalOverview({ notice }: { notice: Notice }) {
  const [days, setDays] = useState(1);
  const { data, loading } = useRemote<Overview>(
    "/admin/overview?days=" + days,
    notice,
  );
  if (!data)
    return (
      <div className="empty">
        {loading ? "Загрузка статистики…" : "Статистика недоступна"}
      </div>
    );
  const max = Math.max(1, ...data.buckets.map((b) => b.total));
  const first = data.buckets[0]?.at || 0;
  const last = data.buckets.at(-1)?.at || first + 1;
  const points = data.buckets
    .map(
      (b) =>
        `${((b.at - first) / Math.max(1, last - first)) * 800},${190 - (b.total / max) * 160}`,
    )
    .join(" ");
  const metrics = [
    {
      name: "DNS-запросы",
      value: number(data.totals.total),
      hint: "Все пользователи",
      icon: Activity,
    },
    {
      name: "Заблокировано",
      value: number(data.totals.blocked),
      hint: "Реклама и трекеры",
      icon: ShieldCheck,
    },
    {
      name: "Через выход",
      value: number(data.totals.proxied),
      hint: "Перенаправленные ответы",
      icon: Globe2,
    },
    {
      name: "Ошибки DNS",
      value: number(data.totals.errors),
      hint: "Ошибки обработки",
      icon: TriangleAlert,
    },
    {
      name: "Активные профили",
      value: `${data.active_users} / ${data.users}`,
      hint: "Обращались за период",
      icon: Users,
    },
    {
      name: "Средний DNS",
      value: data.mean_dns_ms == null ? "—" : `${data.mean_dns_ms} мс`,
      hint: "По журналу за 24 часа",
      icon: Activity,
    },
  ];
  return (
    <>
      <div className="section-title flex">
        <div>
          <p className="eyebrow">СОСТОЯНИЕ СЕРВИСА</p>
          <h2>Обзор SmartDNS</h2>
          <p>Запросы, фильтрация и качество соединения всех пользователей.</p>
        </div>
        <div className="segmented">
          {[1, 7].map((d) => (
            <button
              key={d}
              className={days === d ? "selected" : ""}
              onClick={() => setDays(d)}
            >
              {d === 1 ? "24 часа" : "7 дней"}
            </button>
          ))}
        </div>
      </div>
      <div className="metrics six">
        {metrics.map((m) => (
          <article className="card metric" key={m.name}>
            <div>
              <span>{m.name}</span>
              <m.icon size={16} />
            </div>
            <strong>{m.value}</strong>
            <small>{m.hint}</small>
          </article>
        ))}
      </div>
      <div className="overview-grid">
        <section className="card chart">
          <div className="card-head">
            <div>
              <h3>Активность DNS</h3>
              <p>Запросы за пятиминутные интервалы</p>
            </div>
            <span className="pill violet">
              {days === 1 ? "Сегодня" : "Неделя"}
            </span>
          </div>
          {data.buckets.length ? (
            <>
              <div className="chart-summary">
                <strong>{number(data.totals.total)}</strong>
                <span>Всего за период</span>
              </div>
              <svg
                viewBox="0 0 800 220"
                preserveAspectRatio="none"
                role="img"
                aria-label="Активность DNS всех пользователей"
              >
                <defs>
                  <linearGradient id="volume" x1="0" y1="0" x2="0" y2="1">
                    <stop stopColor="var(--accent)" stopOpacity=".18" />
                    <stop
                      offset="1"
                      stopColor="var(--accent)"
                      stopOpacity="0"
                    />
                  </linearGradient>
                </defs>
                {[30, 85, 140, 195].map((y) => (
                  <line
                    key={y}
                    x1="0"
                    x2="800"
                    y1={y}
                    y2={y}
                    stroke="var(--border)"
                  />
                ))}
                <polygon
                  points={`0,210 ${points} 800,210`}
                  fill="url(#volume)"
                />
                <polyline
                  points={points}
                  fill="none"
                  stroke="var(--accent)"
                  strokeWidth="2"
                  vectorEffect="non-scaling-stroke"
                />
              </svg>
              <div className="chart-labels">
                <span>{date(first)}</span>
                <span>{date(last)}</span>
              </div>
            </>
          ) : (
            <div className="empty">
              Подключите устройство — здесь появится график.
            </div>
          )}
        </section>
        <section className="card">
          <h3>На что обратить внимание</h3>
          <div className="insight">
            <ShieldCheck size={19} />
            <div>
              <b>Фильтрация по профилям</b>
              <p>
                Общие списки и личные исключения применяются к каждому
                пользователю.
              </p>
            </div>
          </div>
          <div className="insight">
            <TriangleAlert size={19} />
            <div>
              <b>{number(data.totals.errors)} ошибок за период</b>
              <p>Причина, IP и версия ключа доступны в диагностике.</p>
            </div>
          </div>
          <div className="insight">
            <Globe2 size={19} />
            <div>
              <b>Выборочная маршрутизация</b>
              <p>
                Домены из каталога идут через настроенный выход. Остальные
                открываются напрямую.
              </p>
            </div>
          </div>
          <small>
            DNS не определяет количество физических устройств и не измеряет
            задержку до каждого приложения.
          </small>
        </section>
      </div>
      <section className="card">
        <div className="card-head">
          <h3>Последние ошибки</h3>
          <span className="subtle">Подробности хранятся 24 часа</span>
        </div>
        <EventTable rows={data.recent_errors} />
      </section>
    </>
  );
}
export function DNSJournal({
  notice,
  accountId,
}: {
  notice: Notice;
  accountId?: string;
}) {
  const [ip, setIP] = useState("");
  const [result, setResult] = useState("error");
  const [transport, setTransport] = useState("");
  const [account, setAccount] = useState(accountId || "");
  const [cursor, setCursor] = useState<number | null>(null);
  const [revision, setRevision] = useState(0);
  const { data: users } = useRemote<{ users: { id: string; login: string }[] }>(
    "/admin/users",
    notice,
  );
  const params = new URLSearchParams({ limit: "50" });
  if (account) params.set("account_id", account);
  if (ip) params.set("ip", ip);
  if (result) params.set("result", result);
  if (transport) params.set("transport", transport);
  if (cursor) params.set("cursor", String(cursor));
  const { data, loading } = useRemote<{
    events: Event[];
    next_cursor: number | null;
  }>("/admin/dns-events?" + params, notice, revision);
  const change = (fn: () => void) => {
    setCursor(null);
    fn();
  };
  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h3>Журнал DNS</h3>
          <p>Ошибки, блокировки и фактические адреса подключения</p>
        </div>
        <button
          className="icon-button"
          aria-label="Обновить журнал"
          onClick={() => {
            setCursor(null);
            setRevision((v) => v + 1);
          }}
        >
          <RefreshCw size={17} />
        </button>
      </div>
      <div className="journal-filters">
        {!accountId && (
          <label className="field">
            <span>Пользователь</span>
            <select
              value={account}
              onChange={(e) => change(() => setAccount(e.target.value))}
            >
              <option value="">Все пользователи</option>
              {users?.users.map((u) => (
                <option key={u.id} value={u.id}>
                  {u.login}
                </option>
              ))}
            </select>
          </label>
        )}
        <label className="field">
          <span>Результат</span>
          <select
            value={result}
            onChange={(e) => change(() => setResult(e.target.value))}
          >
            {[
              ["", "Все результаты"],
              ["error", "Ошибки"],
              ["blocked", "Блокировки"],
              ["proxied", "Через выход"],
              ["allowed", "Прямое разрешение"],
              ["nxdomain", "Нет домена"],
              ["refused", "Отказ"],
            ].map(([v, t]) => (
              <option key={v} value={v}>
                {t}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Протокол</span>
          <select
            value={transport}
            onChange={(e) => change(() => setTransport(e.target.value))}
          >
            <option value="">Все</option>
            <option value="dot">DoT</option>
            <option value="doh">DoH</option>
          </select>
        </label>
        <label className="field">
          <span>IP-адрес</span>
          <input
            placeholder="IPv4 или IPv6"
            onKeyDown={(e) => {
              if (e.key === "Enter")
                change(() => setIP(e.currentTarget.value.trim()));
            }}
            onBlur={(e) => change(() => setIP(e.target.value.trim()))}
          />
        </label>
      </div>
      {loading ? (
        <div className="empty">Загрузка…</div>
      ) : (
        <EventTable rows={data?.events || []} />
      )}
      <div className="pagination">
        <button
          className="secondary"
          disabled={!cursor}
          onClick={() => setCursor(null)}
        >
          К новым
        </button>
        <button
          className="secondary"
          disabled={!data?.next_cursor}
          onClick={() => setCursor(data?.next_cursor || null)}
        >
          Более ранние
        </button>
      </div>
    </section>
  );
}
export function NetworkHistory({
  id,
  notice,
  revision,
}: {
  id: string;
  notice: Notice;
  revision: number;
}) {
  const { data } = useRemote<{
    networks: {
      ip: string;
      first_seen: number;
      last_seen: number;
      total: number;
      errors: number;
    }[];
    leases: { ip: string; expires: number; key_version: number }[];
  }>("/admin/users/" + id + "/networks?days=7", notice, revision);
  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h3>Сети пользователя</h3>
          <p>IP и счётчики за 7 дней. Подробные запросы — за 24 часа.</p>
        </div>
        <span className="pill violet">{data?.leases.length || 0} допусков</span>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>IP-адрес</th>
              <th>Первое обращение</th>
              <th>Последнее</th>
              <th>Запросы / ошибки</th>
              <th>Допуск до</th>
            </tr>
          </thead>
          <tbody>
            {data?.networks.map((n) => (
              <tr key={n.ip}>
                <td className="mono">{n.ip}</td>
                <td>{date(n.first_seen)}</td>
                <td>{date(n.last_seen)}</td>
                <td>
                  {number(n.total)} / {number(n.errors)}
                </td>
                <td>
                  {data.leases.find((l) => l.ip === n.ip)
                    ? date(data.leases.find((l) => l.ip === n.ip)!.expires)
                    : "Истёк"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!data?.networks.length && (
          <div className="empty">
            Новые обращения появятся после подключения устройства.
          </div>
        )}
      </div>
    </section>
  );
}
export function DiagnosticHealth({ notice }: { notice: Notice }) {
  const { data } = useRemote<any>("/admin/diagnostics", notice);
  return (
    <div className="metrics">
      {[
        {
          name: "DNS-шлюз",
          ready: data?.gateway?.ready,
          hint: `Соединений DoT: ${data?.gateway?.dot_connections ?? "—"}`,
        },
        {
          name: "Допуски и выход",
          ready: data?.agent?.ready,
          hint:
            data?.agent?.route?.error ||
            data?.agent?.error ||
            "Контроль маршрута",
        },
        {
          name: "Журналирование",
          ready:
            data &&
            data.gateway?.ready &&
            !data.gateway?.telemetry?.write_errors,
          hint: `Потеряно: ${data?.gateway?.telemetry?.dropped ?? "—"} · ошибок записи: ${data?.gateway?.telemetry?.write_errors ?? "—"}`,
        },
        {
          name: "Продление сертификата",
          ready:
            data &&
            data.certificate?.last_success &&
            !data.certificate?.last_error,
          hint:
            data?.certificate?.last_error ||
            date(data?.certificate?.last_success),
        },
      ].map((c) => (
        <section className="card metric" key={c.name}>
          <div>
            {c.name}
            <Activity size={16} />
          </div>
          <strong className={c.ready ? "good" : "warning"}>
            {!data ? "—" : c.ready ? "В норме" : "Проверить"}
          </strong>
          <small>{c.hint}</small>
        </section>
      ))}
    </div>
  );
}
