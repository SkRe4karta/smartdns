import { test, expect } from '@playwright/test';
async function login(page: import('@playwright/test').Page) {
  await page.goto('/');
  await page.getByLabel('Логин').fill('browser-admin');
  await page.getByLabel('Пароль', {exact:true}).fill('browser-test-password-123');
  await page.getByRole('button', {name:'Войти',exact:true}).click();
  await expect(page.getByRole('heading', {name:/Привет,/})).toBeVisible();
}
test('real password login, account creation and isolated setup', async ({page,browser}) => {
  await login(page);
  await page.getByRole('button', {name:'Пользователи',exact:true}).click();
  await page.getByLabel('Логин нового пользователя').fill('browser-friend');
  await page.getByLabel('Имя нового пользователя').fill('Друг');
  await page.getByRole('button', {name:'Создать',exact:true}).click();
  const invitation = await page.locator('.issued-link code').textContent();
  expect(invitation).toContain('/setup#');
  const context = await browser.newContext();
  const friend = await context.newPage();
  await friend.goto(invitation!);
  await friend.getByLabel('Пароль', {exact:true}).fill('friend-browser-password-123');
  await friend.getByRole('button', {name:'Создать пароль и войти'}).click();
  await expect(friend.getByRole('heading',{name:/Привет,/})).toBeVisible();
  await expect(friend.getByRole('button',{name:'Пользователи',exact:true})).toHaveCount(0);
  expect((await context.request.get('/api/v1/admin/users')).status()).toBe(403);
  await context.close();
});
test('desktop navigation, filter controls and screenshot', async ({page}) => {
  await page.setViewportSize({width:1440,height:1000});
  const errors:string[]=[]; page.on('pageerror', error=>errors.push(error.message));
  await login(page);
  await page.screenshot({path:'test-results/panel-desktop.png',fullPage:true});
  await page.getByRole('button',{name:'Фильтрация',exact:true}).click();
  await page.getByLabel('Домен').fill('ads.example.com');
  await page.getByRole('button',{name:'Добавить',exact:true}).click();
  await expect(page.getByText('ads.example.com',{exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Подключение',exact:true}).click();
  await expect(page.getByText('Android', {exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Каталог сервисов',exact:true}).click();
  await expect(page.getByRole('heading',{name:'ChatGPT / OpenAI'})).toBeVisible();
  expect(errors).toEqual([]);
});
test('mobile menu fits viewport', async ({page}) => {
  await page.setViewportSize({width:390,height:844});
  await login(page);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  await page.screenshot({path:'test-results/panel-mobile.png',fullPage:true});
});
