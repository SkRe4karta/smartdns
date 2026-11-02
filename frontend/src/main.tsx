import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  ArrowDownToLine,
  Check,
  CheckCircle2,
  ChevronRight,
  Clipboard,
  Globe2,
  LayoutDashboard,
  Leaf,
  Loader2,
  LockKeyhole,
  LogOut,
  Menu,
  Plus,
  RefreshCw,
  Search,
  Server,
  Settings2,
  ShieldCheck,
  ShieldOff,
  Users,
  Wifi,
  X,
} from "lucide-react";
import { api, APIError, setCSRF, number, date, type User } from "./api";
import "./style.css";

type Notice = (message: string, error?: boolean) => void;
type View = "overview" | "catalog" | "profile" | "users" | "system";
const nav: {
  id: View;
  label: string;
  icon: React.ElementType;
  admin?: boolean;
}[] = [
  { id: "overview", label: "Обзор", icon: LayoutDashboard },
  { id: "users", label: "Пользователи", icon: Users },
  { id: "catalog", label: "Каталог сервисов", icon: Globe2 },
  { id: "system", label: "Система", icon: Activity },
  { id: "profile", label: "Безопасность", icon: Settings2 },
];

function Brand() {
  return (
    <div className="brand">
      <span className="brand-mark">
        <Leaf size={23} />
      </span>
      <div>
        SmartDNS<span>PRIVATE DNS</span>
      </div>
    </div>
  );
}
function Spinner() {
  return (
    <div className="loading">
      <Loader2 className="spin" /> Загружаем…
    </div>
  );
}
function Pill({
  children,
  tone = "green",
}: {
  children: React.ReactNode;
  tone?: string;
}) {
  return (
    <span className={"pill " + tone}>
      <i />
      {children}
    </span>
  );
}
function Empty({ children }: { children: React.ReactNode }) {
  return <div className="empty">{children}</div>;
}
function useData<T = any>(path: string, notice: Notice, revision = 0) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let live = true;
    setLoading(true);
    api<T>(path)
      .then((d) => {
        if (live) setData(d);
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
function Copy({ value, notice }: { value: string; notice: Notice }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className="icon-button"
      aria-label="Скопировать"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setDone(true);
          setTimeout(() => setDone(false), 1800);
        } catch {
          notice("Скопируй значение вручную", true);
        }
      }}
    >
      {done ? <Check size={17} /> : <Clipboard size={17} />}
    </button>
  );
}
function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
    </label>
  );
}

function Auth({ onLogin, notice }: { onLogin: () => void; notice: Notice }) {
  const [login, setLogin] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <div className="auth-page">
      <div className="auth-card">
        <Brand />
        <h1>Панель администратора</h1>
        <p>Управление пользователями и DNS.</p>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            try {
              await api("/auth/login", "POST", { login, password });
              setPassword("");
              onLogin();
            } catch (e) {
              notice((e as Error).message, true);
            } finally {
              setBusy(false);
            }
          }}
        >
          <Field label="Логин">
            <input
              autoComplete="username"
              value={login}
              onChange={(e) => setLogin(e.target.value)}
              required
            />
          </Field>
          <Field label="Пароль">
            <input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </Field>
          <button className="primary" disabled={busy}>
            Войти
          </button>
        </form>
      </div>
    </div>
  );
}

function Overview({ notice, user }: { notice: Notice; user: User }) {
  const [days, setDays] = useState(1);
  const { data, loading } = useData("/me/stats?days=" + days, notice);
  if (loading) return <Spinner />;
  if (!data)
    return <Empty>Не удалось загрузить данные. Обнови страницу.</Empty>;
  const max = Math.max(1, ...data.buckets.map((b: any) => b.total));
  const points = data.buckets
    .map(
      (b: any, i: number) =>
        `${data.buckets.length === 1 ? 0 : (i / (data.buckets.length - 1)) * 800},${150 - (b.total / max) * 120}`,
    )
    .join(" ");
  const metrics = [
    {
      label: "DNS-запросы",
      value: data.totals.total,
      icon: Activity,
      hint: "На всех твоих устройствах",
    },
    {
      label: "Заблокировано",
      value: data.totals.blocked,
      icon: ShieldCheck,
      hint: "Реклама и нежелательные домены",
    },
    {
      label: "Через прокси",
      value: data.totals.proxied,
      icon: Globe2,
      hint: "Ответы с направлением через сервис",
    },
    {
      label: "Ошибки DNS",
      value: data.totals.errors,
      icon: Wifi,
      hint: "Нуждаются во внимании",
    },
  ];
  return (
    <>
      <div className="welcome">
        <div>
          <p className="eyebrow">ТВОЙ ИНТЕРНЕТ ПОД КОНТРОЛЕМ</p>
          <h2>
            Привет, {user.name.split(" ")[0]} <span className="wave">↗</span>
          </h2>
          <p>Общая статистика твоего личного DNS.</p>
        </div>
        <Pill tone={user.agent.ready ? "green" : "amber"}>
          {user.agent.ready ? "Сервис готов" : "Настройки применяются"}
        </Pill>
      </div>
      <div className="metrics">
        {metrics.map((m) => (
          <article className="card metric" key={m.label}>
            <div>
              <span>{m.label}</span>
              <m.icon size={18} />
            </div>
            <strong>{number(m.value)}</strong>
            <small>{m.hint}</small>
          </article>
        ))}
      </div>
      <div className="dashboard-grid">
        <article className="card chart">
          <div className="card-head">
            <div>
              <h3>Активность запросов</h3>
              <p>Обращения всех устройств с твоей DNS-настройкой</p>
            </div>
            <div className="segmented">
              <button
                className={days === 1 ? "selected" : ""}
                onClick={() => setDays(1)}
              >
                24 часа
              </button>
              <button
                className={days === 7 ? "selected" : ""}
                onClick={() => setDays(7)}
              >
                7 дней
              </button>
            </div>
          </div>
          {data.buckets.length ? (
            <>
              <div className="chart-axis">
                <span>{number(max)}</span>
                <span>{number(Math.round(max / 2))}</span>
                <span>0</span>
              </div>
              <svg
                viewBox="0 0 800 180"
                preserveAspectRatio="none"
                role="img"
                aria-label="График DNS-запросов"
              >
                <defs>
                  <linearGradient id="area" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#82e5a8" stopOpacity=".2" />
                    <stop offset="100%" stopColor="#82e5a8" stopOpacity="0" />
                  </linearGradient>
                </defs>
                {[30, 90, 150].map((y) => (
                  <line
                    key={y}
                    x1="0"
                    x2="800"
                    y1={y}
                    y2={y}
                    stroke="#294336"
                    strokeDasharray="4 5"
                  />
                ))}
                <polygon points={`0,170 ${points} 800,170`} fill="url(#area)" />
                <polyline
                  points={points}
                  fill="none"
                  stroke="#86e7a4"
                  strokeWidth="2.5"
                  vectorEffect="non-scaling-stroke"
                />
              </svg>
              <div className="chart-labels">
                <span>{date(data.buckets[0].at)}</span>
                <span>{date(data.buckets.at(-1).at)}</span>
              </div>
            </>
          ) : (
            <Empty>Подключи устройство — здесь появится график запросов.</Empty>
          )}
        </article>
        <article className="card protection">
          <div className="protection-symbol">
            {user.filtering ? (
              <ShieldCheck size={38} />
            ) : (
              <ShieldOff size={38} />
            )}
          </div>
          <Pill tone={user.filtering ? "green" : "amber"}>
            {user.filtering ? "Защита включена" : "Фильтрация выключена"}
          </Pill>
          <h3>
            {user.filtering
              ? "Меньше лишнего."
              : "Настройки под твоим контролем."}
          </h3>
          <p>
            AdGuard DNS Filter и HaGeZi Multi PRO. Обновление списков каждый
            день.
          </p>
          <div className="status-line">
            <span>Последнее обращение</span>
            <b>{date(user.last_dns)}</b>
          </div>
          <small>DNS не удаляет всю встроенную рекламу YouTube.</small>
        </article>
      </div>
      <div className="dashboard-grid">
        <article className="card">
          <div className="card-head">
            <h3>Последние запросы</h3>
            <span className="subtle">Хранятся 24 часа</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Домен</th>
                  <th>Результат</th>
                  <th>Время</th>
                </tr>
              </thead>
              <tbody>
                {data.recent.slice(0, 12).map((r: any, i: number) => (
                  <tr key={i}>
                    <td className="mono">{r.domain}</td>
                    <td>
                      <Pill
                        tone={
                          r.result === "blocked"
                            ? "muted"
                            : r.result === "error"
                              ? "red"
                              : "green"
                        }
                      >
                        {
                          {
                            blocked: "Заблокирован",
                            proxied: "Через сервис",
                            allowed: "Разрешён",
                            error: "Ошибка",
                          }[r.result as string]
                        }
                      </Pill>
                    </td>
                    <td className="subtle">
                      {new Date(r.at * 1000).toLocaleTimeString("ru-RU")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!data.recent.length && <Empty>Запросов пока нет.</Empty>}
          </div>
        </article>
        <article className="card">
          <div className="card-head">
            <h3>Чаще блокируются</h3>
            <ShieldCheck size={18} />
          </div>
          {data.top_blocked.map((r: any, i: number) => (
            <div className="rank-row" key={r.domain}>
              <span>{String(i + 1).padStart(2, "0")}</span>
              <b>{r.domain}</b>
              <em>{number(r.count)}</em>
            </div>
          ))}
          {!data.top_blocked.length && (
            <Empty>
              Здесь появятся заблокированные рекламные и трекинговые домены.
            </Empty>
          )}
        </article>
      </div>
    </>
  );
}

function ConnectionCards({
  id,
  notice,
  revision,
}: {
  id: string;
  notice: Notice;
  revision: number;
}) {
  const { data, loading } = useData(
    "/admin/users/" + id + "/connection",
    notice,
    revision,
  );
  if (loading) return <Spinner />;
  if (!data) return <Empty>Подключения недоступны</Empty>;
  return (
    <section className="card connection-cards">
      <h3>Подключения · версия ключа {data.version}</h3>
      <p>
        Один DNS-профиль для всех устройств. Ссылки и файл выдаёт администратор.
      </p>
      {[
        {
          title: "Android",
          hint: "Подключения → Другие настройки соединения → Частный DNS → Имя хоста провайдера.",
          value: data.dot,
        },
        {
          title: "ПК и совместимые роутеры",
          hint: "Добавь адрес DNS over HTTPS. Bootstrap IP: " + data.bootstrap,
          value: data.doh,
        },
      ].map((c) => (
        <div className="connection-block" key={c.title}>
          <h4>{c.title}</h4>
          <p>{c.hint}</p>
          <div className="code-box">
            <code>{c.value}</code>
            <Copy value={c.value} notice={notice} />
          </div>
        </div>
      ))}
      <div className="info-box">
        <Wifi size={21} />
        <div>
          <b>Ubuntu и приложения на компьютере</b>
          <p>
            Отдельный ключ не нужен. Обычное поле «DNS» в настройках Ubuntu не
            принимает URL DoH. Для системного DNS используйте systemd-resolved с
            DoT: IP сервера и имя DoT выше для TLS/SNI. DNS, настроенный только
            в браузере, не распространяется на Codex и другие приложения. Уже
            работающее системное подключение менять не нужно.
          </p>
        </div>
      </div>
      <div className="connection-block">
        <h4>iPhone и MacBook</h4>
        <p>
          Общий профиль DNS over HTTPS. Скачай файл и передай владельцу
          устройства.
        </p>
        <a
          className="primary inline"
          href={"/api/v1/admin/users/" + id + "/profile.mobileconfig"}
        >
          <ArrowDownToLine size={17} /> Скачать .mobileconfig
        </a>
      </div>
    </section>
  );
}

function Filtering({
  notice,
  accountId,
  onChange,
}: {
  notice: Notice;
  onChange: () => void;
  accountId: string;
}) {
  const base = "/admin/users/" + accountId;
  const [revision, setRevision] = useState(0);
  const result = useData(base, notice, revision);
  const loading = result.loading;
  const data = result.data
    ? {
        enabled: !!result.data.user.filtering,
        exceptions: result.data.user.exceptions,
      }
    : null;
  const [domain, setDomain] = useState("");
  const [action, setAction] = useState("allow");
  const [busy, setBusy] = useState(false);
  async function save(path: string, method: string, body?: unknown) {
    setBusy(true);
    try {
      await api(path, method, body);
      setRevision((x) => x + 1);
      onChange();
      notice("Настройки сохранены");
    } catch (e) {
      notice((e as Error).message, true);
    } finally {
      setBusy(false);
    }
  }
  if (loading) return <Spinner />;
  if (!data)
    return <Empty>Не удалось загрузить данные. Обнови страницу.</Empty>;
  return (
    <>
      <div className="section-title">
        <h2>Меньше рекламы и трекеров</h2>
        <p>Изменения действуют на все устройства пользователя.</p>
      </div>
      <section className="card toggle-card">
        <div className="small-icon">
          <ShieldCheck />
        </div>
        <div>
          <h3>Усиленная защита</h3>
          <p>
            AdGuard DNS Filter + HaGeZi Multi PRO, обновление каждые 24 часа.
          </p>
        </div>
        <button
          role="switch"
          aria-checked={data.enabled}
          aria-label="Усиленная защита"
          className={"switch " + (data.enabled ? "on" : "")}
          disabled={busy}
          onClick={() =>
            save(base + "/filtering", "PUT", { enabled: !data.enabled })
          }
        >
          <span />
        </button>
      </section>
      <section className="card">
        <div className="card-head">
          <div>
            <h3>Личные исключения</h3>
            <p>Разрешай нужные домены или блокируй нежелательные.</p>
          </div>
          <span className="count">{data.exceptions.length}</span>
        </div>
        <form
          className="inline-form"
          onSubmit={(e) => {
            e.preventDefault();
            void save(base + "/exceptions", "POST", { domain, action }).then(
              () => setDomain(""),
            );
          }}
        >
          <input
            aria-label="Домен"
            placeholder="example.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            required
          />
          <select
            aria-label="Действие"
            value={action}
            onChange={(e) => setAction(e.target.value)}
          >
            <option value="allow">Разрешить</option>
            <option value="block">Блокировать</option>
          </select>
          <button className="primary" disabled={busy}>
            <Plus size={17} /> Добавить
          </button>
        </form>
        <table>
          <thead>
            <tr>
              <th>Домен</th>
              <th>Действие</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {data.exceptions.map((r: any) => (
              <tr key={r.domain}>
                <td className="mono">{r.domain}</td>
                <td>
                  <Pill tone={r.action === "allow" ? "green" : "muted"}>
                    {r.action === "allow" ? "Разрешён" : "Заблокирован"}
                  </Pill>
                </td>
                <td className="align-right">
                  <button
                    aria-label={"Удалить " + r.domain}
                    className="icon-button"
                    disabled={busy}
                    onClick={() =>
                      save(
                        base + "/exceptions/" + encodeURIComponent(r.domain),
                        "DELETE",
                      )
                    }
                  >
                    <X size={16} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!data.exceptions.length && (
          <Empty>
            Исключений пока нет. Существующие списки уже блокируют рекламу.
          </Empty>
        )}
      </section>
      <p className="footnote">
        Исключения фильтрации не добавляют домен в каталог проксируемых
        сервисов.
      </p>
    </>
  );
}

function ServiceCatalog({ notice, admin }: { notice: Notice; admin: boolean }) {
  const [revision, setRevision] = useState(0);
  const { data, loading } = useData(
    admin ? "/admin/catalog" : "/catalog",
    notice,
    revision,
  );
  const [search, setSearch] = useState("");
  const [busy, setBusy] = useState(false);
  async function refresh() {
    setBusy(true);
    try {
      const r = await api("/admin/catalog-refresh", "POST");
      notice(`Каталог обновлён: ${number(r.rules)} правил`);
      setRevision((x) => x + 1);
    } catch (e) {
      notice((e as Error).message, true);
    } finally {
      setBusy(false);
    }
  }
  if (loading) return <Spinner />;
  if (!data)
    return <Empty>Не удалось загрузить данные. Обнови страницу.</Empty>;
  const services = data.services.filter((s: any) =>
    (s.name + " " + s.category).toLowerCase().includes(search.toLowerCase()),
  );
  return (
    <>
      <div className="section-title flex">
        <div>
          <h2>Зарубежные сервисы</h2>
          <p>
            Проверяемый каталог доменов и CDN. Поддерживаемые возможности
            указаны в карточках.
          </p>
        </div>
        {admin && (
          <button className="secondary" disabled={busy} onClick={refresh}>
            <RefreshCw size={16} className={busy ? "spin" : ""} /> Обновить
            списки
          </button>
        )}
      </div>
      <div className="search-box">
        <Search size={18} />
        <input
          aria-label="Поиск сервиса"
          placeholder="Найти сервис или категорию"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <span>{services.length} сервисов</span>
      </div>
      <div className="service-grid">
        {services.map((s: any) => (
          <article className="card service-card" key={s.id}>
            <div className="service-head">
              <div className="service-monogram">
                {s.name.slice(0, 2).toUpperCase()}
              </div>
              <Pill tone={s.enabled ? "green" : "muted"}>
                {s.enabled ? "В каталоге" : "Отключён"}
              </Pill>
            </div>
            <h3>{s.name}</h3>
            <span className="category">{s.category}</span>
            <p>{s.capability}</p>
            <div className="service-bottom">
              <span>{number(s.domains)} доменов</span>
              {admin ? (
                <button
                  className="text-button"
                  onClick={async () => {
                    try {
                      await api("/admin/catalog/" + s.id, "PATCH", {
                        enabled: !s.enabled,
                      });
                      setRevision((x) => x + 1);
                    } catch (e) {
                      notice((e as Error).message, true);
                    }
                  }}
                >
                  {s.enabled ? "Отключить" : "Включить"}
                  <ChevronRight size={15} />
                </button>
              ) : (
                <Globe2 size={16} />
              )}
            </div>
          </article>
        ))}
      </div>
      {admin && (
        <CatalogAdmin
          data={data}
          notice={notice}
          reload={() => setRevision((x) => x + 1)}
        />
      )}
      <div className="info-box">
        <Globe2 size={22} />
        <p>
          DNS направляет HTTPS-соединения, начинающиеся с доменного запроса.
          Прямые IP, MTProto и звонки Telegram этим режимом не перехватываются.
          Доступ также зависит от аккаунта и региона.
        </p>
      </div>
    </>
  );
}

function CatalogAdmin({
  data,
  notice,
  reload,
}: {
  data: any;
  notice: Notice;
  reload: () => void;
}) {
  const [domain, setDomain] = useState("");
  const [action, setAction] = useState("direct");
  const [service, setService] = useState("");
  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h3>Ручные маршруты</h3>
          <p>
            Имеют приоритет над импортированными правилами. Последнее
            обновление: {date(data.metadata?.catalog_updated)}
          </p>
        </div>
      </div>
      <form
        className="inline-form"
        onSubmit={async (e) => {
          e.preventDefault();
          try {
            await api("/admin/routes", "POST", {
              domain,
              kind: "suffix",
              action,
              service_id: action === "proxy" ? service : null,
            });
            setDomain("");
            reload();
            notice("Маршрут сохранён");
          } catch (e) {
            notice((e as Error).message, true);
          }
        }}
      >
        <input
          placeholder="example.com"
          aria-label="Домен маршрута"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          required
        />
        <select value={action} onChange={(e) => setAction(e.target.value)}>
          <option value="direct">Напрямую</option>
          <option value="proxy">Через выход сервиса</option>
        </select>
        {action === "proxy" && (
          <select
            aria-label="Сервис"
            value={service}
            onChange={(e) => setService(e.target.value)}
            required
          >
            <option value="">Выбери сервис</option>
            {data.services.map((s: any) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>
        )}
        <button className="primary">Добавить</button>
      </form>
      {data.overrides?.map((r: any) => (
        <div className="rank-row" key={r.domain}>
          <b>{r.domain}</b>
          <span>{r.action === "direct" ? "Напрямую" : r.service_id}</span>
          <button
            className="icon-button"
            aria-label={"Удалить маршрут " + r.domain}
            onClick={async () => {
              try {
                await api(
                  "/admin/routes/" +
                    r.kind +
                    "/" +
                    encodeURIComponent(r.domain),
                  "DELETE",
                );
                reload();
              } catch (e) {
                notice((e as Error).message, true);
              }
            }}
          >
            <X size={15} />
          </button>
        </div>
      ))}
      <p className="footnote">
        Telegram: {data.cidrs?.length || 0} опубликованных сетей в справочнике.
        Неприменённых выражений источника:{" "}
        {data.metadata?.catalog_skipped?.length || 0}.
      </p>
    </section>
  );
}

function Profile({
  user,
  notice,
  onChange,
}: {
  user: User;
  notice: Notice;
  onChange: () => void;
}) {
  const [current, setCurrent] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  async function passwordSubmit(e: React.SubmitEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    try {
      await api("/auth/password", "PUT", {
        current: current || null,
        new: password,
      });
      setPassword("");
      setCurrent("");
      onChange();
      notice("Пароль изменён; остальные сеансы завершены.");
    } catch (e) {
      notice((e as Error).message, true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <div className="section-title">
        <h2>Профиль и безопасность</h2>
        <p>Вход в кабинет не влияет на работу личного DNS.</p>
      </div>
      <div className="dashboard-grid">
        <section className="card">
          <h3>Пароль</h3>
          <form onSubmit={passwordSubmit}>
            {user.has_password && (
              <Field label="Текущий пароль">
                <input
                  type="password"
                  autoComplete="current-password"
                  value={current}
                  onChange={(e) => setCurrent(e.target.value)}
                  required
                />
              </Field>
            )}
            <Field label="Новый пароль">
              <input
                type="password"
                minLength={12}
                maxLength={256}
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </Field>
            <small>
              От 12 символов. Другие сеансы кабинета будут завершены.
            </small>
            <button className="primary" disabled={busy}>
              Сохранить пароль
            </button>
          </form>
        </section>
        <section className="card">
          <h3>Сеансы кабинета</h3>
          <p className="subtle">
            Заверши вход на других компьютерах и браузерах. DNS на устройствах
            продолжит работать.
          </p>
          <button
            className="secondary"
            onClick={async () => {
              try {
                await api("/auth/logout-others", "POST");
                notice("Остальные сеансы завершены");
              } catch (e) {
                notice((e as Error).message, true);
              }
            }}
          >
            Завершить остальные сеансы
          </button>
        </section>
      </div>
    </>
  );
}

function UserCard({
  id,
  notice,
  onClose,
  onChange,
}: {
  id: string;
  notice: Notice;
  onClose: () => void;
  onChange: () => void;
}) {
  const [revision, setRevision] = useState(0);
  const [days, setDays] = useState(1);
  const [busy, setBusy] = useState(false);
  const { data, loading } = useData(
    "/admin/users/" + id + "?days=" + days,
    notice,
    revision,
  );
  async function action(path: string, method: string, body?: unknown) {
    setBusy(true);
    try {
      await api("/admin/users/" + id + path, method, body);
      setRevision((x) => x + 1);
      onChange();
      notice("Изменения сохранены");
    } catch (e) {
      notice((e as Error).message, true);
    } finally {
      setBusy(false);
    }
  }
  useEffect(() => {
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", key);
    return () => {
      document.body.style.overflow = previous;
      document.removeEventListener("keydown", key);
    };
  }, [onClose]);
  return (
    <div
      className="user-dialog-backdrop"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <section
        role="dialog"
        aria-modal="true"
        aria-label="Пользователь"
        className="user-dialog"
      >
        <button autoFocus className="secondary dialog-close" onClick={onClose}>
          <X size={18} /> Закрыть
        </button>
        {loading ? (
          <Spinner />
        ) : !data ? (
          <Empty>Пользователь недоступен</Empty>
        ) : (
          <>
            <div className="section-title">
              <h2>{data.user.login}</h2>
              <Pill tone={data.user.status === "active" ? "green" : "amber"}>
                {data.user.status === "active" ? "Активен" : "Отключён"}
              </Pill>
              <p>Последний DNS-запрос: {date(data.user.last_dns)}</p>
            </div>
            <div className="card">
              <div className="card-head">
                <h3>DNS-активность</h3>
                <select
                  aria-label="Период статистики"
                  value={days}
                  onChange={(e) => setDays(Number(e.target.value))}
                >
                  <option value={1}>Сутки</option>
                  <option value={7}>Неделя</option>
                </select>
              </div>
              <p>
                Запросы: {number(data.stats.totals.total)} · блокировки:{" "}
                {number(data.stats.totals.blocked)} · ошибки:{" "}
                {number(data.stats.totals.errors)}
              </p>
              <div className="user-bars" aria-label="График запросов">
                {data.stats.buckets.map((b: any) => (
                  <span
                    key={b.at}
                    title={date(b.at) + ": " + number(b.total)}
                    style={{
                      height:
                        Math.max(
                          3,
                          (80 * b.total) /
                            Math.max(
                              1,
                              ...data.stats.buckets.map((x: any) => x.total),
                            ),
                        ) + "px",
                    }}
                  />
                ))}
              </div>
            </div>
            <ConnectionCards id={id} notice={notice} revision={revision} />
            <Filtering accountId={id} notice={notice} onChange={onChange} />
            <section className="card danger-zone">
              <button
                className="secondary"
                disabled={busy}
                onClick={() =>
                  action("", "PATCH", {
                    enabled: data.user.status !== "active",
                  })
                }
              >
                {data.user.status === "active"
                  ? "Отключить пользователя"
                  : "Включить пользователя"}
              </button>
              <button
                className="secondary"
                disabled={busy}
                onClick={() => {
                  if (
                    confirm(
                      "Сменить DNS-ключ? Все устройства потребуется настроить заново. Старые адреса перестанут работать.",
                    )
                  )
                    void action("/rotate-key", "POST");
                }}
              >
                <RefreshCw size={16} /> Сменить DNS-ключ
              </button>
            </section>
          </>
        )}
      </section>
    </div>
  );
}
function AdminUsers({ notice }: { notice: Notice }) {
  const [revision, setRevision] = useState(0);
  const { data, loading } = useData("/admin/users", notice, revision);
  const [username, setUsername] = useState("");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <>
      <div className="section-title">
        <h2>Пользователи</h2>
        <p>Создай DNS-профиль и передай подключения лично.</p>
      </div>
      <section className="card">
        <h3>Новый пользователь</h3>
        <form
          className="inline-form"
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            try {
              const r = await api("/admin/users", "POST", { username });
              setUsername("");
              setRevision((x) => x + 1);
              setSelected(r.id);
              notice("DNS-профиль активен");
            } catch (e) {
              notice((e as Error).message, true);
            } finally {
              setBusy(false);
            }
          }}
        >
          <input
            aria-label="Username нового пользователя"
            placeholder="Username"
            pattern="[A-Za-z0-9._-]{3,40}"
            minLength={3}
            maxLength={40}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
          <button className="primary" disabled={busy}>
            <Plus size={17} /> Создать
          </button>
        </form>
      </section>
      <section className="card">
        <div className="search-box">
          <Search size={18} />
          <input
            aria-label="Найти пользователя"
            placeholder="Найти пользователя"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        {loading ? (
          <Spinner />
        ) : data ? (
          <>
            <p>
              {data.users.length} / {data.limit}
            </p>
            <table>
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Доступ</th>
                  <th>Активность DNS</th>
                </tr>
              </thead>
              <tbody>
                {data.users
                  .filter((u: any) => u.login.includes(search.toLowerCase()))
                  .map((u: any) => (
                    <tr key={u.id}>
                      <td>
                        <button
                          className="user-link"
                          onClick={() => setSelected(u.id)}
                        >
                          {u.login}
                        </button>
                        {u.role === "admin" && <small> Администратор</small>}
                      </td>
                      <td>
                        <Pill tone={u.status === "active" ? "green" : "amber"}>
                          {u.status === "active" ? "Активен" : "Отключён"}
                        </Pill>
                      </td>
                      <td>{date(u.last_dns)}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </>
        ) : (
          <Empty>Не удалось загрузить пользователей</Empty>
        )}
      </section>
      {selected && (
        <UserCard
          key={selected}
          id={selected}
          notice={notice}
          onClose={() => setSelected(null)}
          onChange={() => setRevision((x) => x + 1)}
        />
      )}
    </>
  );
}

function System({ notice }: { notice: Notice }) {
  const { data, loading } = useData("/admin/system", notice);
  if (loading) return <Spinner />;
  if (!data)
    return <Empty>Не удалось загрузить данные. Обнови страницу.</Empty>;
  return (
    <>
      <div className="section-title">
        <h2>Состояние системы</h2>
        <p>Службы приложения, ресурсы и последние административные действия.</p>
      </div>
      <div className="metrics">
        <article className="card metric">
          <div>
            Агент допуска
            <Server size={18} />
          </div>
          <strong>{data.agent.ready ? "Готов" : "Не готов"}</strong>
          <small>{data.agent.error || "Контроль временных разрешений"}</small>
        </article>
        <article className="card metric">
          <div>
            Свободная память
            <Activity size={18} />
          </div>
          <strong>
            {Math.round((data.memory.MemAvailable || 0) / 1024 / 1024)}{" "}
            <em>МБ</em>
          </strong>
          <small>
            Из {Math.round((data.memory.MemTotal || 0) / 1024 / 1024)} МБ на VPS
          </small>
        </article>
        <article className="card metric">
          <div>
            Сертификат
            <LockKeyhole size={18} />
          </div>
          <strong>
            {data.certificate_expires
              ? Math.max(
                  0,
                  Math.floor(
                    (data.certificate_expires - Date.now() / 1000) / 86400,
                  ),
                )
              : "—"}{" "}
            <em>дней</em>
          </strong>
          <small>{date(data.certificate_expires)}</small>
        </article>
        <article className="card metric">
          <div>
            Правила каталога
            <Globe2 size={18} />
          </div>
          <strong>{number(data.counts.domains)}</strong>
          <small>
            {data.counts.users} пользователей · {data.version}
          </small>
        </article>
      </div>
      <section className="card">
        <h3>Административные действия</h3>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Время</th>
                <th>Действие</th>
                <th>Объект</th>
                <th>Кто</th>
              </tr>
            </thead>
            <tbody>
              {data.audit.map((a: any, i: number) => (
                <tr key={i}>
                  <td className="subtle">{date(a.at)}</td>
                  <td>{a.action}</td>
                  <td className="mono">{a.target || "—"}</td>
                  <td className="mono">{a.actor}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!data.audit.length && <Empty>Действий пока нет.</Empty>}
        </div>
      </section>
    </>
  );
}

function App() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [view, setView] = useState<View>("overview");
  const [menu, setMenu] = useState(false);
  const [toast, setToast] = useState<{ text: string; error: boolean } | null>(
    null,
  );
  const notice: Notice = (text, error = false) => {
    setToast({ text, error });
  };
  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 6000);
    return () => clearTimeout(t);
  }, [toast]);
  async function load() {
    try {
      const u = await api<User>("/me");
      setCSRF(u.csrf);
      setUser(u);
    } catch (e) {
      setUser(null);
      if (!(e instanceof APIError && e.status === 401))
        notice((e as Error).message, true);
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    void load();
  }, []);
  useEffect(() => {
    if (!user) return;
    const timer = setInterval(() => void load(), 15000);
    return () => clearInterval(timer);
  }, [user?.id]);
  async function logout() {
    try {
      await api("/auth/logout", "POST");
      setCSRF("");
      setUser(null);
      history.replaceState(null, "", "/login");
    } catch (e) {
      notice((e as Error).message, true);
    }
  }
  const title = nav.find((n) => n.id === view)?.label;
  let content: React.ReactNode = null;
  if (user) {
    switch (view) {
      case "overview":
        content = <Overview user={user} notice={notice} />;
        break;

      case "catalog":
        content = (
          <ServiceCatalog notice={notice} admin={user.role === "admin"} />
        );
        break;
      case "profile":
        content = <Profile user={user} notice={notice} onChange={load} />;
        break;
      case "users":
        content = <AdminUsers notice={notice} />;
        break;

      case "system":
        content = <System notice={notice} />;
    }
  }
  return (
    <>
      {loading ? (
        <Spinner />
      ) : !user ? (
        <Auth onLogin={load} notice={notice} />
      ) : (
        <div className="shell">
          <aside className={menu ? "open" : ""}>
            <Brand />
            <div className="workspace-label">АДМИНИСТРАТОР</div>
            <nav>
              {nav
                .filter((n) => !n.admin || user.role === "admin")
                .map((n, i) => (
                  <React.Fragment key={n.id}>
                    {n.admin && i === 5 && (
                      <div className="workspace-label">УПРАВЛЕНИЕ</div>
                    )}
                    <button
                      className={view === n.id ? "active" : ""}
                      onClick={() => {
                        setView(n.id);
                        setMenu(false);
                      }}
                    >
                      <n.icon size={19} />
                      {n.label}
                      {view === n.id && <ChevronRight size={15} />}
                    </button>
                  </React.Fragment>
                ))}
            </nav>
            <div className="sidebar-bottom">
              <div className="node-status">
                <i /> SmartDNS <span>DNS</span>
              </div>
              <div className="sidebar-version">
                {user.version}
                <span>RC</span>
              </div>
              <button className="logout" onClick={logout}>
                <LogOut size={17} /> Выйти
              </button>
            </div>
          </aside>
          {menu && (
            <button
              className="scrim"
              onClick={() => setMenu(false)}
              aria-label="Закрыть меню"
            />
          )}
          <div className="main-column">
            <header>
              <button
                className="icon-button mobile-menu"
                onClick={() => setMenu(!menu)}
                aria-label="Открыть меню"
              >
                <Menu size={22} />
              </button>
              <div className="breadcrumb">
                Панель <ChevronRight size={14} />
                <b>{title}</b>
              </div>
              <div className="user-info">
                <span>
                  {user.name}
                  <small>
                    {user.role === "admin" ? "Администратор" : "Личный профиль"}
                  </small>
                </span>
                <div className="avatar">
                  {user.name.slice(0, 1).toUpperCase()}
                </div>
              </div>
            </header>
            <main className="page" key={view}>
              {content}
            </main>
            <footer>
              <span>SmartDNS · панель администратора</span>
              <span>{user.version} · HTTPS / DoT</span>
            </footer>
          </div>
        </div>
      )}
      {toast && (
        <div className={"toast " + (toast.error ? "error" : "")} role="status">
          {toast.error ? <X size={18} /> : <CheckCircle2 size={18} />}
          <span>{toast.text}</span>
          <button
            onClick={() => setToast(null)}
            aria-label="Закрыть уведомление"
          >
            <X size={15} />
          </button>
        </div>
      )}
    </>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
