let csrf = "";
export function setCSRF(value: string) {
  csrf = value;
}
export class APIError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}
export async function api<T = any>(
  path: string,
  method = "GET",
  data?: unknown,
): Promise<T> {
  const response = await fetch("/api/v1" + path, {
    method,
    credentials: "same-origin",
    headers: {
      ...(data === undefined ? {} : { "Content-Type": "application/json" }),
      ...(method === "GET" ? {} : { "X-CSRF-Token": csrf }),
    },
    ...(data === undefined ? {} : { body: JSON.stringify(data) }),
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new APIError(
      response.status,
      typeof body.detail === "string"
        ? body.detail
        : "Проверь введённые данные",
    );
  }
  return response.json() as Promise<T>;
}
export type User = {
  id: string;
  name: string;
  login: string;
  role: "admin" | "user";
  csrf: string;
  filtering: boolean;
  last_dns: number | null;
  has_password: boolean;
  version: string;
  agent: { ready: boolean; error?: string };
};
export function number(value: number | undefined) {
  return new Intl.NumberFormat("ru-RU").format(value ?? 0);
}
export function date(value: number | null | undefined) {
  return value
    ? new Date(value * 1000).toLocaleString("ru-RU")
    : "Пока нет данных";
}
