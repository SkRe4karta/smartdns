import { test, expect } from "@playwright/test";
async function login(page: import("@playwright/test").Page) {
  await page.goto("/");
  await page.getByLabel("Логин", { exact: true }).fill("browser-admin");
  await page
    .getByLabel("Пароль", { exact: true })
    .fill("browser-test-password-123");
  await page.getByRole("button", { name: "Войти", exact: true }).click();
  await expect(page.getByRole("heading", { name: /Привет,/ })).toBeVisible();
}
test("administrator creates active username and sees every connection on one screen", async ({
  page,
}) => {
  await login(page);
  await page.getByRole("button", { name: "Пользователи", exact: true }).click();
  await page.getByLabel("Username нового пользователя").fill("browser-friend");
  await page.getByRole("button", { name: "Создать", exact: true }).click();
  const card = page.getByRole("dialog");
  await expect(
    card.getByRole("heading", { name: "browser-friend", exact: true }),
  ).toBeVisible();
  await expect(
    card.getByRole("heading", { name: "Android", exact: true }),
  ).toBeVisible();
  await expect(
    card.getByRole("heading", { name: "ПК и совместимые роутеры" }),
  ).toBeVisible();
  await expect(
    card.getByRole("link", { name: /Скачать .mobileconfig/ }),
  ).toBeVisible();
  await expect(card.getByRole("tab")).toHaveCount(0);
  await card.getByLabel("Домен", { exact: true }).fill("ads.example.com");
  await card.getByRole("button", { name: "Добавить", exact: true }).click();
  await expect(
    card.getByText("ads.example.com", { exact: true }),
  ).toBeVisible();
  await page.screenshot({ path: "test-results/user-card.png", fullPage: true });
});
test("desktop admin navigation has no recipient portal or egress page", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await login(page);
  await expect(
    page.getByRole("button", { name: "Выходные IP", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Подключение", exact: true }),
  ).toHaveCount(0);
  await page
    .getByRole("button", { name: "Каталог сервисов", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "ChatGPT / OpenAI" }),
  ).toBeVisible();
  await page.screenshot({
    path: "test-results/panel-desktop.png",
    fullPage: true,
  });
  expect(errors).toEqual([]);
});
test("mobile admin menu fits viewport", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await login(page);
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth),
  ).toBeLessThanOrEqual(390);
  await page.screenshot({
    path: "test-results/panel-mobile.png",
    fullPage: true,
  });
});
