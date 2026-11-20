import { Pool } from "pg";
import { randomBytes, createHash, scryptSync, timingSafeEqual } from "node:crypto";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("neon.tech") ? { rejectUnauthorized: false } : undefined,
  max: 3,
  connectionTimeoutMillis: 5000,
  idleTimeoutMillis: 30000,
  query_timeout: 10000,
  statement_timeout: 10000
});
let schemaReady;
async function ensureSchema() {
  if (!schemaReady) schemaReady = (async () => {
    await pool.query("ALTER TABLE players ADD COLUMN IF NOT EXISTS avatar_url text");
    await pool.query("ALTER TABLE players ADD COLUMN IF NOT EXISTS total_play_seconds bigint NOT NULL DEFAULT 0");
    await pool.query(`CREATE TABLE IF NOT EXISTS activity_events (
      id bigserial PRIMARY KEY,
      player_id uuid NOT NULL REFERENCES players(id) ON DELETE CASCADE,
      username text NOT NULL,
      avatar_url text,
      item_name text NOT NULL,
      item_image text,
      case_title text,
      item_value integer NOT NULL DEFAULT 0,
      rarity text,
      created_at timestamptz NOT NULL DEFAULT now()
    )`);
    await pool.query("ALTER TABLE activity_events ADD COLUMN IF NOT EXISTS item_value integer NOT NULL DEFAULT 0");
    await pool.query("ALTER TABLE activity_events ADD COLUMN IF NOT EXISTS rarity text");
    await pool.query("ALTER TABLE activity_events ADD COLUMN IF NOT EXISTS event_type text NOT NULL DEFAULT 'legacy_drop'");
    await pool.query("CREATE INDEX IF NOT EXISTS activity_events_created_idx ON activity_events(created_at DESC)");
    await pool.query(`CREATE TABLE IF NOT EXISTS player_inventory_items (
      id bigserial PRIMARY KEY,
      player_id uuid NOT NULL REFERENCES players(id) ON DELETE CASCADE,
      slot integer NOT NULL,
      item_name text NOT NULL,
      item_image text,
      item_value integer NOT NULL DEFAULT 0,
      rarity text,
      updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(player_id,slot)
    )`);
    await pool.query("ALTER TABLE player_inventory_items ADD COLUMN IF NOT EXISTS item_id integer");
    await pool.query("CREATE INDEX IF NOT EXISTS player_inventory_items_updated_idx ON player_inventory_items(updated_at DESC)");
  })();
  return schemaReady;
}
const hash = value => createHash("sha256").update(value).digest("hex");
const send = (res, status, body) => { res.status(status).json(body); };
function makePassword(password) {
  const salt = randomBytes(16).toString("hex");
  return "scrypt$" + salt + "$" + scryptSync(password, salt, 64).toString("hex");
}
function checkPassword(password, stored) {
  const parts = String(stored || "").split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") return false;
  const actual = scryptSync(password, parts[1], 64);
  const expected = Buffer.from(parts[2], "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
async function createSession(playerId) {
  const token = randomBytes(32).toString("hex");
  await pool.query(
    "INSERT INTO player_sessions (player_id, token_hash, expires_at, last_seen_at) VALUES ($1,$2,now()+interval '30 days',now())",
    [playerId, hash(token)]
  );
  return token;
}
async function getUser(req) {
  const auth = String(req.headers.authorization || "");
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token || token.length > 200) return null;
  const q = await pool.query(
    `SELECT p.id,p.username,p.avatar_url,p.total_play_seconds,s.id AS session_id
     FROM player_sessions s JOIN players p ON p.id=s.player_id
     WHERE s.token_hash=$1 AND s.expires_at>now() LIMIT 1`,
    [hash(token)]
  );
  return q.rows[0] || null;
}
export default async function handler(req, res) {
  try {
    const origin = String(req.headers.origin || "");
    if (origin === "https://localhost" || origin === "capacitor://localhost") {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
      res.setHeader("Access-Control-Max-Age", "86400");
    }
    const path = new URL(req.url, "https://local.invalid").pathname.replace(/^\/api\/?/, "").replace(/\/$/, "");
    if (req.method === "OPTIONS") return res.status(204).end();

    const authHeader = String(req.headers.authorization || "");
    const bearer = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
    const supabaseRoutes = new Set(["register","login","me","player-profile","presence","feed","optimized-mode","inventory","balance","activity-view","activity","password","username","avatar","delete-account"]);
    if (supabaseRoutes.has(path)) {
      const target = "https://qgsugmiaryvqixsypfgw.supabase.co/functions/v1/burmaldep-api/" + path + (req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : "");
      const upstream = await fetch(target, {
        method: req.method,
        headers: { "Content-Type": "application/json", "apikey": process.env.SUPABASE_PUBLISHABLE_KEY || "", ...(bearer ? { "x-burmaldep-token": bearer } : {}) },
        body: req.method === "GET" || req.method === "HEAD" ? undefined : JSON.stringify(req.body || {})
      });
      const payload = await upstream.json().catch(() => ({ error: "Не удалось прочитать ответ новой базы" }));
      // Neon fallback is temporarily disabled. Supabase is the only active account database.
      return send(res, upstream.status, payload);
    }

    await ensureSchema();

    if (path === "register" && req.method === "POST") {
      const username = String(req.body?.username || "").trim();
      const password = String(req.body?.password || "");
      if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) return send(res,400,{error:"Ник: 3–20 символов, латиница, цифры или _"});
      if (password.length < 8 || password.length > 128) return send(res,400,{error:"Пароль должен быть от 8 до 128 символов"});
      const result = await pool.query(
        "INSERT INTO players (username,password_hash) VALUES ($1,$2) RETURNING id,username,avatar_url",
        [username, makePassword(password)]
      ).catch(e => { if (e.code === "23505") return null; throw e; });
      if (!result) return send(res,409,{error:"Такой ник уже занят"});
      const token = await createSession(result.rows[0].id);
      return send(res,201,{token,user:result.rows[0]});
    }

    if (path === "login" && req.method === "POST") {
      const username = String(req.body?.username || "").trim();
      const password = String(req.body?.password || "");
      const q = await pool.query("SELECT id,username,password_hash,avatar_url FROM players WHERE lower(username)=lower($1) LIMIT 1",[username]);
      const player = q.rows[0];
      if (!player || !checkPassword(password,player.password_hash)) return send(res,401,{error:"Неверный ник или пароль"});
      const token = await createSession(player.id);
      return send(res,200,{token,user:{id:player.id,username:player.username,avatar_url:player.avatar_url}});
    }

    const user = await getUser(req);
    if (!user) return send(res,401,{error:"Сначала войди в аккаунт"});

    if (path === "me" && req.method === "GET") return send(res,200,{user:{id:user.id,username:user.username,avatar_url:user.avatar_url,total_play_seconds:Number(user.total_play_seconds)||0}});
    if (path === "player-profile" && req.method === "GET") {
      const playerId = String(new URL(req.url, "https://local.invalid").searchParams.get("id") || "");
      if (!/^[0-9a-f-]{36}$/i.test(playerId)) return send(res,400,{error:"Некорректный профиль"});
      const profile = await pool.query("SELECT id,username,avatar_url,total_play_seconds FROM players WHERE id=$1 LIMIT 1",[playerId]);
      if (!profile.rows.length) return send(res,404,{error:"Игрок не найден"});
      const items = await pool.query("SELECT item_id,item_name,item_image,item_value,rarity,slot,updated_at FROM player_inventory_items WHERE player_id=$1 ORDER BY slot ASC",[playerId]);
      return send(res,200,{user:profile.rows[0],items:items.rows});
    }
    if (path === "presence" && req.method === "POST") {
      const playtime = await pool.query("UPDATE players SET total_play_seconds=total_play_seconds+LEAST(60,GREATEST(0,FLOOR(EXTRACT(EPOCH FROM (now()-(SELECT last_seen_at FROM player_sessions WHERE id=$1)))))) WHERE id=$2 RETURNING total_play_seconds",[user.session_id,user.id]);
      await pool.query("UPDATE player_sessions SET last_seen_at=now(),expires_at=now()+interval '30 days' WHERE id=$1",[user.session_id]);
      const count = await pool.query("SELECT count(DISTINCT player_id)::int AS online FROM player_sessions WHERE expires_at>now() AND last_seen_at>now()-interval '90 seconds'");
      return send(res,200,{online:count.rows[0].online,total_play_seconds:Number(playtime.rows[0]?.total_play_seconds)||0});
    }
    if (path === "feed" && req.method === "GET") {
      const rows = await pool.query(`SELECT DISTINCT ON (p.id) p.id,p.username,p.avatar_url
        FROM player_sessions s JOIN players p ON p.id=s.player_id
        WHERE s.expires_at>now() AND s.last_seen_at>now()-interval '90 seconds'
        ORDER BY p.id,s.last_seen_at DESC LIMIT 20`);
      const count = await pool.query("SELECT count(DISTINCT player_id)::int AS online FROM player_sessions WHERE expires_at>now() AND last_seen_at>now()-interval '90 seconds'");
      const events = await pool.query(`SELECT id,username,avatar_url,item_name,item_image,case_title,item_value,rarity,created_at
        FROM activity_events WHERE event_type = 'upgrade_visit' ORDER BY created_at DESC LIMIT 12`);
      const inventoryItems = await pool.query(`SELECT i.id,i.item_name,i.item_image,i.item_value,i.rarity,i.updated_at,
        p.username,p.avatar_url
        FROM player_inventory_items i JOIN players p ON p.id=i.player_id
        ORDER BY i.updated_at DESC,i.id DESC LIMIT 12`);
      return send(res,200,{players:rows.rows,online:count.rows[0].online,events:events.rows,inventoryItems:inventoryItems.rows});
    }

    if (path === "inventory" && req.method === "GET") {
      const result = await pool.query(
        "SELECT item_id,item_name,item_image,item_value,rarity,slot,updated_at FROM player_inventory_items WHERE player_id=$1 ORDER BY slot ASC",
        [user.id]
      );
      return send(res,200,{items:result.rows});
    }

    if (path === "inventory" && req.method === "POST") {
      const items = Array.isArray(req.body?.items) ? req.body.items.slice(0,200) : [];
      await pool.query("DELETE FROM player_inventory_items WHERE player_id=$1",[user.id]);
      for (let slot=items.length-1;slot>=0;slot--) {
        const item=items[slot] || {};
        const itemId=Number.isInteger(Number(item.item_id)) ? Number(item.item_id) : null;
        const itemName=String(item.item_name || "").trim().slice(0,120);
        const itemImage=String(item.item_image || "").trim().slice(0,2048);
        const itemValue=Math.max(0,Math.min(100000000,Math.trunc(Number(item.item_value)||0)));
        const rarity=String(item.rarity || "").trim().slice(0,32);
        if (!itemName || (itemImage && !/^https:\/\//i.test(itemImage))) continue;
        await pool.query(
          "INSERT INTO player_inventory_items (player_id,slot,item_id,item_name,item_image,item_value,rarity) VALUES ($1,$2,$3,$4,$5,$6,$7)",
          [user.id,slot,itemId,itemName,itemImage || null,itemValue,rarity || null]
        );
      }
      return send(res,200,{ok:true,shown:items.length});
    }

    if (path === "activity-view" && req.method === "POST") {
      const recent = await pool.query("SELECT id FROM activity_events WHERE player_id=$1 AND event_type='upgrade_visit' AND created_at>now()-interval '10 minutes' LIMIT 1",[user.id]);
      if (!recent.rowCount) {
        await pool.query(
          "INSERT INTO activity_events (player_id,username,avatar_url,item_name,event_type) VALUES ($1,$2,$3,$4,'upgrade_visit')",
          [user.id,user.username,user.avatar_url,"Перешёл в раздел «Апгрейдер»"]
        );
      }
      return send(res,201,{ok:true});
    }

    if (path === "activity" && req.method === "POST") {
      const items = Array.isArray(req.body?.items) ? req.body.items.slice(0,10) : [];
      if (!items.length) return send(res,400,{error:"Нет предметов для публикации"});
      for (const item of items) {
        const itemName = String(item?.item_name || "").trim().slice(0,120);
        const itemImage = String(item?.item_image || "").trim().slice(0,2048);
        const caseTitle = String(item?.case_title || "").trim().slice(0,80);
        const itemValue = Math.max(0,Math.min(100000000,Math.trunc(Number(item?.item_value)||0)));
        const rarity = String(item?.rarity || "").trim().slice(0,32);
        if (!itemName) continue;
        if (itemImage && !/^https:\/\//i.test(itemImage)) continue;
        await pool.query(
          `INSERT INTO activity_events (player_id,username,avatar_url,item_name,item_image,case_title,item_value,rarity)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [user.id,user.username,user.avatar_url,itemName,itemImage || null,caseTitle || null,itemValue,rarity || null]
        );
      }
      await pool.query("DELETE FROM activity_events WHERE created_at < now()-interval '14 days'");
      return send(res,201,{ok:true});
    }
    if (path === "password" && req.method === "POST") {
      const currentPassword = String(req.body?.current_password || "");
      const newPassword = String(req.body?.new_password || "");
      if (newPassword.length < 8 || newPassword.length > 128) return send(res,400,{error:"Новый пароль должен быть от 8 до 128 символов"});
      const stored = await pool.query("SELECT password_hash FROM players WHERE id=$1",[user.id]);
      if (!stored.rowCount || !checkPassword(currentPassword,stored.rows[0].password_hash)) return send(res,401,{error:"Старый пароль указан неверно"});
      await pool.query("UPDATE players SET password_hash=$1 WHERE id=$2",[makePassword(newPassword),user.id]);
      return send(res,200,{ok:true});
    }
    if (path === "username" && req.method === "POST") {
      const username = String(req.body?.username || "").trim();
      if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) return send(res,400,{error:"Ник: 3–20 символов, латиница, цифры или _"});
      const taken = await pool.query("SELECT 1 FROM players WHERE lower(username)=lower($1) AND id<>$2 LIMIT 1",[username,user.id]);
      if (taken.rowCount) return send(res,409,{error:"Такой ник уже занят"});
      const changed = await pool.query("UPDATE players SET username=$1 WHERE id=$2 RETURNING username,avatar_url",[username,user.id]);
      return send(res,200,{user:{...changed.rows[0],id:user.id}});
    }
    if (path === "avatar" && req.method === "POST") {
      const avatar = String(req.body?.avatar || "");
      if (avatar && (!/^data:image\/(png|jpeg|webp|gif);base64,/.test(avatar) || avatar.length > 350000)) return send(res,400,{error:"Загрузи PNG, JPG, WEBP или GIF размером до 250 КБ"});
      await pool.query("UPDATE players SET avatar_url=$1 WHERE id=$2",[avatar || null,user.id]);
      return send(res,200,{avatar_url:avatar || null});
    }
    return send(res,404,{error:"Маршрут не найден"});
  } catch (error) {
    console.error("Burmaldep API:",error);
    return send(res,500,{error:"Ошибка сервера. Проверь подключение базы данных."});
  }
}
