# Otillion Loyalty

Standalone loyalty-card product (not part of the café/POS system). The admin creates a business, picks its theme and logo, and gives it a login. The business gives its own customers a points card (for example 6 haircuts = 1 free).

- `index.html` — the whole app (admin console, business dashboard, customer card). Built from `src/app.html` with `python3 build.py <supabase-url> <publishable-key>`.
- `backend/loyalty-app.sql` — run once in the Supabase SQL editor of the project that backs this app.

## Setup
1. Create (or pick) the Supabase project, turn **public sign-up off** in Auth settings.
2. Run `backend/loyalty-app.sql`.
3. Make yourself admin: create a user in Auth (email + password), then run  
   `insert into public.lp_admins select id from auth.users where email = 'YOU@example.com';`
4. Open the site, sign in with that email, create a business, create its account.

## URLs
- Customers: `?c=<slug>` to join, `?card=<token>` to open a card (the token is the card's only credential).
- Business staff: sign in with the username and password the admin set.

## Themes
Presets: coffee, black & red (barber), black & gold, rose, blue, green, black & white, plus a custom theme (background, text, main colour, card). Each business gets its own theme on its dashboard and customer card.
