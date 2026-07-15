# DMGuardBot

Telegram group DM-harassment guard bot, Supabase + Groq AI ke saath.

## GitHub pe daalne se pehle

1. `.env` file kabhi bhi commit mat karo — `.gitignore` me already add hai.
2. Sirf `.env.example` GitHub pe jayega (dummy values).

## GitHub pe upload

```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/<username>/<repo-name>.git
git push -u origin main
```

## Render pe deploy

1. https://dashboard.render.com pe **New +** → **Background Worker** choose karo (Web Service NAHI, kyunki bot polling use karta hai).
2. Apna GitHub repo connect karo.
3. Settings:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `python bot.py`
4. **Environment** tab me ye variables daalo (apni `.env` file ki values se):
   - `BOT_TOKEN`
   - `SUPABASE_URL`
   - `SUPABASE_KEY`
   - `GROQ_API_KEY`
   - `GROQ_MODEL` (optional, default `openai/gpt-oss-20b`)
5. Deploy karo. Logs me `✅ DMGuardBot (Supabase + Groq AI) start ho gaya.` dikhna chahiye.

(`render.yaml` bhi diya hai agar Render Blueprint se deploy karna ho to.)

## ⚠️ Zaroori Security Note

Tumhari purani `.env` file me jo BOT_TOKEN, SUPABASE_KEY aur GROQ_API_KEY hain,
wo mujhe (aur is chat ko) dikh chuki hain aur pehle bot.py me bhi hardcoded
thi. Safe rehne ke liye:
- Telegram **@BotFather** se `/revoke` karke naya BOT_TOKEN generate kar lo.
- Supabase dashboard se service_role key **regenerate** kar lo.
- Groq console se naya API key bana lo.

Phir naye keys hi Render ke Environment Variables me daalna.
