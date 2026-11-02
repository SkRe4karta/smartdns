import { useState } from "react";
import { ShieldCheck, KeyRound } from "lucide-react";
import { api } from "./api";
import type { Notice } from "./diagnostics";
export function MFASettings({
  enabled,
  notice,
  onChange,
}: {
  enabled: boolean;
  notice: Notice;
  onChange: () => void;
}) {
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(
    null,
  );
  const [recovery, setRecovery] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  async function submit(e: React.SubmitEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    try {
      if (enabled) {
        await api("/auth/totp/disable", "POST", { password, code });
        notice("Второй фактор отключён");
        onChange();
      } else if (setup) {
        const r = await api<{ recovery_codes: string[] }>(
          "/auth/totp/enable",
          "POST",
          { code },
        );
        setRecovery(r.recovery_codes);
        setSetup(null);
        notice("Второй фактор включён. Сохраните коды восстановления.");
        onChange();
      } else setSetup(await api("/auth/totp/setup", "POST", { password }));
      setPassword("");
      setCode("");
    } catch (e) {
      notice((e as Error).message, true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="card">
      <div className="card-head">
        <h3>
          <ShieldCheck size={18} /> Второй фактор
        </h3>
        <span className={"pill " + (enabled ? "green" : "muted")}>
          {enabled ? "Включён" : "По желанию"}
        </span>
      </div>
      <p>
        Код TOTP из приложения-аутентификатора защищает вход администратора.
      </p>
      {setup && (
        <div className="info-box">
          <KeyRound size={20} />
          <div>
            <b>Добавьте аккаунт в аутентификатор</b>
            <p>
              Секрет: <code className="secret-text">{setup.secret}</code>
            </p>
            <a className="text-button" href={setup.uri}>
              Открыть аутентификатор
            </a>
            <p>6 цифр, интервал 30 секунд.</p>
          </div>
        </div>
      )}
      {recovery.length > 0 && (
        <div className="recovery">
          <b>Одноразовые коды восстановления</b>
          <p>Сохраните в защищённом месте. Повторно показать их нельзя.</p>
          <pre>{recovery.join("\n")}</pre>
          <button className="secondary" onClick={() => setRecovery([])}>
            Я сохранил коды
          </button>
        </div>
      )}
      <form onSubmit={submit}>
        {!setup && (
          <label className="field">
            <span>Текущий пароль</span>
            <input
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
        )}
        {(setup || enabled) && (
          <label className="field">
            <span>Код TOTP{enabled ? " или код восстановления" : ""}</span>
            <input
              autoComplete="one-time-code"
              maxLength={32}
              value={code}
              required
              onChange={(e) => setCode(e.target.value)}
            />
          </label>
        )}
        <button className="secondary" disabled={busy}>
          {enabled
            ? "Отключить второй фактор"
            : setup
              ? "Подтвердить код"
              : "Настроить TOTP"}
        </button>
      </form>
    </section>
  );
}
export function ThemeToggle() {
  const [theme, setTheme] = useState(
    () => localStorage.getItem("smartdns-theme") || "system",
  );
  function change(value: string) {
    setTheme(value);
    localStorage.setItem("smartdns-theme", value);
    document.documentElement.dataset.theme =
      value === "system"
        ? matchMedia("(prefers-color-scheme: dark)").matches
          ? "dark"
          : "light"
        : value;
  }
  return (
    <select
      className="theme-select"
      aria-label="Тема оформления"
      value={theme}
      onChange={(e) => change(e.target.value)}
    >
      <option value="system">Системная тема</option>
      <option value="light">Светлая</option>
      <option value="dark">Тёмная</option>
    </select>
  );
}
