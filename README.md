<div align="center">

# Trendify Nexus

**پنل مدیریت همه‌کاره روی Cloudflare**
<br>
All-in-one control panel for Cloudflare

<br>

<a href="https://trendif-nexus-cloudv2.berni-khan61-ba9.workers.dev/">
  <img src="https://img.shields.io/badge/%F0%9F%9A%80%20%20Open%20Installer-F0B90B?style=for-the-badge&labelColor=111827" alt="Open Installer" height="52">
</a>

<br><br>

<a href="#persian"><img src="https://img.shields.io/badge/%D9%81%D8%A7%D8%B1%D8%B3%DB%8C-2ea043?style=for-the-badge" alt="فارسی"></a>
<a href="#english"><img src="https://img.shields.io/badge/English-1f6feb?style=for-the-badge" alt="English"></a>

<br><br>

![Cloudflare Pages](https://img.shields.io/badge/Cloudflare-Pages-F38020?logo=cloudflare&logoColor=white)
![D1](https://img.shields.io/badge/Database-D1-F38020?logo=cloudflare&logoColor=white)
![Telegram](https://img.shields.io/badge/Bot-Telegram-26A5E4?logo=telegram&logoColor=white)
![No server](https://img.shields.io/badge/Servers-0-success)

</div>

---

<a id="persian"></a>

<div dir="rtl">

# 🇮🇷 فارسی

## معرفی

Trendify Nexus کاملاً روی زیرساخت Cloudflare اجرا می‌شود. نیازی به اجاره VPS یا بک‌اند جداگانه نیست: پنل، API، سرویس ساب‌اسکریپشن، ربات تلگرام و اندپوینت پروکسی همه در یک استقرار قرار دارند و دیتابیس آن D1 است.

**نصب‌کننده تحت وب** همه‌چیز را برای شما آماده می‌کند. فقط یک API Token می‌دهید و خودش دیتابیس، پروژه Pages، بایندینگ‌ها و رمز ادمین را می‌سازد و پنل را مستقر می‌کند.

## امکانات

| | |
|---|---|
| 👤 **کاربران** | ساخت اکانت با محدودیت حجم، تاریخ انقضا و اختصاص گیتوی. ریست ترافیک و فعال/غیرفعال‌سازی با یک کلیک. |
| 🌐 **گیتوی‌ها** | چند نقطه ورود، هرکدام با مسیر `/ws/<id>` و دامنه اختصاصی اختیاری. بررسی سلامت و ثبت تأخیر. |
| 🔗 **ساب‌اسکریپشن** | لینک عمومی همراه با اطلاعات حجم و انقضا برای کلاینت‌هایی مثل v2rayNG و Hiddify. |
| 🔍 **اسکنر IP** | پیدا کردن IPهای سریع Cloudflare از داخل مرورگر خودتان و افزودن بهترین‌ها به لینک‌ها. |
| 🤖 **ربات تلگرام** | ربات با دکمه‌های شیشه‌ای برای مدیریت گیتوی، کانفیگ و ساب، به‌همراه مانیتورینگ زنده. |
| 📊 **مانیتورینگ** | آمار کلی، پرمصرف‌ترین کاربران، کاربران نزدیک به اتمام حجم یا انقضا، وضعیت گیتوی‌ها و آخرین خطاها. |
| 🔐 **امنیت** | هش رمز با PBKDF2، کوکی HttpOnly برای نشست و تأیید secret در وبهوک. |

## شروع سریع

1. **[نصب‌کننده](https://trendif-nexus-cloudv2.berni-khan61-ba9.workers.dev/)** را باز کنید.
2. در Cloudflare یک API Token با این دسترسی‌ها بسازید:
   - **Account ← Cloudflare Pages ← Edit**
   - **Account ← D1 ← Edit**
   - **Account ← Account Settings ← Read**
3. توکن را بچسبانید، نام پروژه را انتخاب کنید و **شروع نصب** را بزنید.
4. در پایان، آدرس پنل و رمز ادمین نمایش داده می‌شود. رمز را ذخیره کنید.
5. توکن API را از داشبورد Cloudflare حذف کنید.

با نام کاربری `admin` و رمزی که نصب‌کننده نشان داد وارد شوید و از بخش **Settings** رمز را تغییر دهید.

## ربات تلگرام

1. از [@BotFather](https://t.me/BotFather) یک ربات بسازید و توکن را بردارید.
2. در پنل به **Settings ← Telegram Bot** بروید، توکن را بگذارید و **Save & Activate** را بزنید.
3. به ربات `/start` بفرستید. اگر آیدی شما هنوز ثبت نشده باشد، ربات آن را نشان می‌دهد.
4. آیدی عددی را در **Admin IDs** بگذارید، **Save only** را بزنید و دوباره `/start` بفرستید.

## اتصال کلاینت

1. از **Users ← Config** لینک اول (direct) را کپی کنید، یا یک ساب بسازید و آدرسش را در کلاینت اضافه کنید.
2. در کلاینت **Mux را خاموش** کنید.
3. اگر وصل نشد، بخش **Connection Logs** در صفحه Gateways را ببینید. خطاها آنجا ثبت می‌شوند.

## نکات مهم

- **از دامنه شخصی استفاده کنید.** آدرس‌های `workers.dev` و `pages.dev` روی بعضی شبکه‌ها کند یا فیلتر هستند. در پروژه Pages از بخش **Custom domains** دامنه خودتان را وصل کنید و پنل را با همان دامنه باز کنید.
- **UDP محدود است.** فقط DNS روی UDP پشتیبانی می‌شود. بازی و QUIC در Cloudflare Workers ممکن نیست.
- **پروکسی جایگزین.** مقصدهایی که پشت Cloudflare هستند به پروکسی جایگزین نیاز دارند. در **Settings** پروکسی خودتان را بگذارید، چون مقدار پیش‌فرض متعلق به شخص ثالث است.
- **اعتماد به نصب‌کننده.** نصب‌کننده هنگام اجرا توکن شما را می‌بیند. از نسخه شخصی خودتان استفاده کنید و بعد از نصب توکن را حذف کنید.
- **نصب دوباره** با همان نام پروژه، دیتابیس موجود را استفاده می‌کند و فقط کد جدید را مستقر می‌کند. رمز ادمین فقط در اولین اجرا اعمال می‌شود.

## فناوری‌ها

Cloudflare Pages (`_worker.js`) · Cloudflare D1 · `cloudflare:sockets` · Telegram Bot API (وبهوک)

## سلب مسئولیت

این پروژه برای استفاده قانونی در شبکه و حفظ حریم خصوصی ارائه شده است. رعایت قوانین کشور خودتان و شرایط استفاده از Cloudflare بر عهده شماست.

<div align="center">

[⬆️ بازگشت به بالا](#trendify-nexus) · [🇬🇧 English](#english)

</div>

</div>

---

<a id="english"></a>

# 🇬🇧 English

## Overview

Trendify Nexus runs entirely on Cloudflare. There is no VPS to rent and no separate backend: the panel, the API, the subscription service, the Telegram bot and the proxy endpoint all live in one deployment, backed by a D1 database.

The **web installer** sets everything up for you. You give it one API token, and it creates the database, the Pages project, the bindings and the admin password, then deploys the panel.

## Features

| | |
|---|---|
| 👤 **Users** | Create accounts with data limits, expiry dates and gateway assignment. Reset traffic, enable or disable in one click. |
| 🌐 **Gateways** | Multiple entry points, each with its own `/ws/<id>` path and optional custom domain. Health checks and latency tracking. |
| 🔗 **Subscriptions** | Public subscription URLs with traffic and expiry info for clients like v2rayNG and Hiddify. |
| 🔍 **IP Scanner** | Finds fast Cloudflare IPs from your own browser and adds the best ones to subscription links. |
| 🤖 **Telegram Bot** | Glass-button bot to manage gateways, configs and subscriptions, plus a live monitoring view. |
| 📊 **Monitoring** | Totals, top usage, users near their limit or expiry, gateway status and recent errors. |
| 🔐 **Security** | PBKDF2 password hashing, HttpOnly session cookies, webhook secret verification. |

## Quick start

1. Open the **[Installer](https://trendif-nexus-cloudv2.berni-khan61-ba9.workers.dev/)**.
2. Create a Cloudflare API token with these permissions:
   - **Account → Cloudflare Pages → Edit**
   - **Account → D1 → Edit**
   - **Account → Account Settings → Read**
3. Paste the token, choose a project name and click **Start install**.
4. When it finishes, you get your panel URL and the admin password. Save the password.
5. Delete the API token from your Cloudflare dashboard.

Log in with the username `admin` and the password shown by the installer, then open **Settings** to change it.

## Telegram bot

1. Create a bot with [@BotFather](https://t.me/BotFather) and copy the token.
2. In the panel, go to **Settings → Telegram Bot**, paste the token and click **Save & Activate**.
3. Send `/start` to the bot. If your ID is not registered yet, the bot shows it.
4. Put that numeric ID in **Admin IDs**, click **Save only**, and send `/start` again.

## Connecting a client

1. Go to **Users → Config** and copy the first link (direct), or create a subscription and add its URL to your client.
2. Turn **Mux off** in the client.
3. Check **Connection Logs** under Gateways if something does not connect. Errors are recorded there.

## Good to know

- **Use a custom domain.** `workers.dev` and `pages.dev` addresses can be slow or blocked on some networks. Add your own domain under your Pages project's **Custom domains**, then open the panel from that domain.
- **UDP support is limited.** Only DNS over UDP is handled. Games and QUIC are not supported by Cloudflare Workers.
- **Fallback proxy.** Targets hosted on Cloudflare need a fallback proxy. Set your own in **Settings**, because the built-in default is a third-party host.
- **Installer trust.** The installer sees your token while it runs. Use your own deployment of it, and remove the token afterwards.
- **Reinstalling** with the same project name reuses the existing database and only deploys new code. The admin password is applied only on the very first run.

## Tech stack

Cloudflare Pages (`_worker.js`) · Cloudflare D1 · `cloudflare:sockets` · Telegram Bot API (webhook)

## Disclaimer

This project is provided for legitimate networking and privacy use. You are responsible for complying with the laws of your country and with Cloudflare's Terms of Service.

<div align="center">

[⬆️ Back to top](#trendify-nexus) · [🇮🇷 فارسی](#persian)

</div>

---

<div align="center">

Made with care by **Trendify**

</div>
