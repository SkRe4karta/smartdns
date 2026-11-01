import { describe, it, expect, vi, afterEach } from "vitest";
import { api, setCSRF, APIError, number, date } from "./api";
afterEach(() => vi.unstubAllGlobals());
describe("authenticated API transport", () => {
  it("passes CSRF on mutations and never puts it in the URL", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValue({ ok: true, json: async () => ({ ok: true }) });
    vi.stubGlobal("fetch", fetch);
    setCSRF("csrf-fixture");
    await api("/me/filtering", "PUT", { enabled: false });
    expect(fetch).toHaveBeenCalledWith(
      "/api/v1/me/filtering",
      expect.objectContaining({
        credentials: "same-origin",
        headers: expect.objectContaining({ "X-CSRF-Token": "csrf-fixture" }),
        body: '{"enabled":false}',
      }),
    );
  });
  it("surfaces authorization failures", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue({
          ok: false,
          status: 403,
          json: async () => ({ detail: "Нет доступа" }),
        }),
    );
    await expect(api("/admin/users")).rejects.toEqual(
      new APIError(403, "Нет доступа"),
    );
  });
  it("formats real zeroes and missing activity", () => {
    expect(number(0)).toBe("0");
    expect(date(null)).toBe("Пока нет данных");
  });
});
