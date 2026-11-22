import { createClient } from "npm:@supabase/supabase-js@2";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  { auth: { persistSession: false, autoRefreshToken: false } }
);
const json = (data: unknown, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "authorization,content-type", "Access-Control-Allow-Methods": "GET,POST,OPTIONS" }
});
const sha256 = async (s: string) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))).map(x=>x.toString(16).padStart(2,"0")).join("");
const randomHex = (n: number) => Array.from(crypto.getRandomValues(new Uint8Array(n))).map(x=>x.toString(16).padStart(2,"0")).join("");
async function makePassword(password: string) {
  const salt = randomHex(16), iterations = 210000;
  const key = await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({name:"PBKDF2",salt:new TextEncoder().encode(salt),iterations,hash:"SHA-256"},key,256);
  const digest = Array.from(new Uint8Array(bits)).map(x=>x.toString(16).padStart(2,"0")).join("");
  return `pbkdf2$${iterations}$${salt}$${digest}`;
}
async function checkPassword(password: string, stored: string) {
  const [kind,it,salt,expected] = String(stored||"").split("$");
  if(kind!=="pbkdf2" || !/^\d+$/.test(it||"") || !salt || !expected) return false;
  const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveBits"]);
  const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt:new TextEncoder().encode(salt),iterations:Number(it),hash:"SHA-256"},key,256);
  const actual=Array.from(new Uint8Array(bits)).map(x=>x.toString(16).padStart(2,"0")).join("");
  return actual===expected;
}
async function createSession(playerId: string) {
  const token="sb_"+randomHex(32), token_hash=await sha256(token);
  const {error}=await supabase.from("player_sessions").insert({player_id:playerId,token_hash,expires_at:new Date(Date.now()+30*86400000).toISOString(),last_seen_at:new Date().toISOString()});
  if(error) throw error;
  return token;
}
async function getUser(req: Request) {
  const token=req.headers.get("x-burmaldep-token")||"";
  if(!token.startsWith("sb_") || token.length>200) return null;
  const {data:s,error}=await supabase.from("player_sessions").select("id,player_id").eq("token_hash",await sha256(token)).gt("expires_at",new Date().toISOString()).maybeSingle();
  if(error||!s) return null;
  const {data:p}=await supabase.from("players").select("id,username,avatar_url,total_play_seconds,monthly_play_seconds,monthly_mission_rewarded,is_creator,share_upgrade_activity,optimized_mode,balance").eq("id",s.player_id).maybeSingle();
  return p ? {...p,session_id:s.id} : null;
}
Deno.serve(async (req) => {
  if(req.method==="OPTIONS") return json({});
  try {
    const url=new URL(req.url), path=url.pathname.split("/").filter(Boolean).at(-1)||"";
    const body=req.method==="POST" ? await req.json().catch(()=>({})) : {};
    if(path==="register" && req.method==="POST"){
      const username=String(body.username||"").trim(), password=String(body.password||"");
      if(!/^[a-zA-Z0-9_]{3,20}$/.test(username)) return json({error:"Ник: 3–20 символов, латиница, цифры или _"},400);
      if(password.length<8||password.length>128) return json({error:"Пароль должен быть от 8 до 128 символов"},400);
      const {data:player,error}=await supabase.from("players").insert({username,password_hash:await makePassword(password)}).select("id,username,avatar_url,is_creator,share_upgrade_activity").single();
      if(error?.code==="23505") return json({error:"Такой ник уже занят"},409);
      if(error) throw error;
      return json({token:await createSession(player.id),user:player},201);
    }
    if(path==="login" && req.method==="POST"){
      const username=String(body.username||"").trim(),password=String(body.password||"");
      const {data:player,error}=await supabase.from("players").select("id,username,password_hash,avatar_url,is_creator,share_upgrade_activity").ilike("username",username).limit(1).maybeSingle();
      if(error) throw error;
      if(!player || !(await checkPassword(password,player.password_hash))) return json({error:"Аккаунт не найден в новой базе"},404);
      const {password_hash,...user}=player;
      return json({token:await createSession(player.id),user});
    }
    const user=await getUser(req);
    if(!user) return json({error:"Сначала войди в аккаунт"},401);
    if(path==="me" && req.method==="GET") return json({user:{id:user.id,username:user.username,avatar_url:user.avatar_url,total_play_seconds:Number(user.total_play_seconds)||0,monthly_play_seconds:Number(user.monthly_play_seconds)||0,monthly_mission_rewarded:!!user.monthly_mission_rewarded,is_creator:!!user.is_creator,share_upgrade_activity:user.share_upgrade_activity!==false,optimized_mode:!!user.optimized_mode,balance:user.balance===null?null:Number(user.balance),monthly_mission_closed:Date.now()>=Date.UTC(2026,11,19,0,0,0)}});
    if(path==="leaderboard" && req.method==="GET"){
      const {data:players,error}=await supabase.from("players")
        .select("id,username,is_creator,balance")
        .not("balance","is",null)
        .order("balance",{ascending:false})
        .order("username",{ascending:true})
        .limit(50);
      if(error) throw error;
      return json({players:(players||[]).map((p:any)=>({
        id:p.id,
        username:p.username,
        is_creator:!!p.is_creator,
        balance:Number(p.balance)||0
      }))});
    }
    if(path==="balance" && req.method==="GET") return json({balance:user.balance===null?null:Number(user.balance)});
    if(path==="balance" && req.method==="POST"){
      if(body.action==="initialize"){
        const initial=Number(body.balance);
        if(!Number.isSafeInteger(initial)||initial<0||initial>1000000000000) return json({error:"Некорректный начальный баланс"},400);
        const {data:initialized,error:initError}=await supabase.rpc("initialize_player_balance",{p_player_id:user.id,p_balance:initial});
        if(initError) throw initError;
        const {data:current,error:currentError}=await supabase.from("players").select("balance").eq("id",user.id).single();
        if(currentError) throw currentError;
        if(current.balance===null) return json({error:"Баланс не удалось инициализировать"},409);
        return json({ok:true,initialized:initialized!==null,balance:Number(current.balance)});
      }
      if(body.action==="change"){
        const delta=Number(body.delta);
        if(!Number.isSafeInteger(delta)||delta===0||Math.abs(delta)>1000000000) return json({error:"Некорректное изменение баланса"},400);
        const {data:changed,error:changeError}=await supabase.rpc("change_player_balance",{p_player_id:user.id,p_delta:delta});
        if(changeError) throw changeError;
        if(changed===null||changed===undefined) return json({error:"Недостаточно БК или баланс ещё не перенесён"},409);
        return json({ok:true,balance:Number(changed)});
      }
      return json({error:"Неизвестное действие с балансом"},400);
    }
    if(path==="optimized-mode" && req.method==="POST"){
      const enabled=body.enabled===true;
      const {data,error}=await supabase.from("players").update({optimized_mode:enabled}).eq("id",user.id).select("optimized_mode").single();
      if(error) throw error;
      return json({ok:true,optimized_mode:!!data.optimized_mode});
    }
    if(path==="player-profile" && req.method==="GET"){
      const id=url.searchParams.get("id")||"";
      if(!/^[0-9a-f-]{36}$/i.test(id)) return json({error:"Некорректный профиль"},400);
      const {data:profile}=await supabase.from("players").select("id,username,avatar_url,total_play_seconds,is_creator,optimized_mode").eq("id",id).maybeSingle();
      if(!profile) return json({error:"Игрок не найден"},404);
      const {data:items,error}=await supabase.from("player_inventory_items").select("item_id,item_name,item_image,item_value,rarity,is_favorite,slot,updated_at").eq("player_id",id).order("slot");
      if(error) throw error;
      return json({user:profile,items});
    }
    if(path==="presence" && req.method==="POST"){
      const nowIso=new Date().toISOString();
      // The database takes the time from its own clock and serializes heartbeats per account.
      // Concurrent sessions cannot multiply the playtime, and the browser timezone is ignored.
      const {data:presence,error:presenceError}=await supabase.rpc("record_player_presence",{
        p_player_id:user.id,
        p_session_id:user.session_id
      });
      if(presenceError) throw presenceError;
      const player=Array.isArray(presence)?presence[0]:presence;
      if(!player) return json({error:"Не удалось обновить время игры."},500);

      let rewardAwarded=false;
      if(Number(player.monthly_play_seconds)>=86400&&!player.monthly_mission_rewarded){
        const {data:claimed,error:claimError}=await supabase.from("players")
          .update({monthly_mission_rewarded:true})
          .eq("id",user.id).eq("monthly_mission_rewarded",false).gte("monthly_play_seconds",86400)
          .select("id").maybeSingle();
        if(claimError) throw claimError;
        if(claimed){
          const {data:lastItems,error:lastItemsError}=await supabase.from("player_inventory_items")
            .select("slot").eq("player_id",user.id).order("slot",{ascending:false}).limit(1);
          if(lastItemsError) throw lastItemsError;
          const nextSlot=(lastItems?.[0]?.slot??-1)+1;
          const {error:rewardError}=await supabase.from("player_inventory_items").insert({
            player_id:user.id,slot:nextSlot,item_id:5030,item_name:"Босс Бурмалды",
            item_image:"https://halvamedia.scb.ru/82102/conversions/burmalda-mem.webp",
            item_value:10000000,rarity:"Мифический",is_favorite:false
          });
          if(rewardError){
            await supabase.from("players").update({monthly_mission_rewarded:false}).eq("id",user.id);
            throw rewardError;
          }
          rewardAwarded=true;
        }
      }

      // Weekly cleanup touches only expired sessions and old activity events.
      const weekAgo=new Date(Date.now()-7*86400000).toISOString();
      const {data:lease,error:leaseError}=await supabase.from("maintenance_state").update({last_run_at:nowIso})
        .eq("job_key","weekly_cleanup").lt("last_run_at",weekAgo).select("job_key");
      if(leaseError) throw leaseError;
      if(lease?.length){
        const {error:expiredSessionsError}=await supabase.from("player_sessions").delete().lt("expires_at",nowIso);
        if(expiredSessionsError) throw expiredSessionsError;
        const {error:oldEventsError}=await supabase.from("activity_events").delete()
          .lt("created_at",new Date(Date.now()-14*86400000).toISOString());
        if(oldEventsError) throw oldEventsError;
      }
      const cutoff=new Date(Date.now()-90000).toISOString();
      const {data:active,error:activeError}=await supabase.from("player_sessions").select("player_id")
        .gt("expires_at",nowIso).gt("last_seen_at",cutoff);
      if(activeError) throw activeError;
      return json({
        online:new Set((active||[]).map(x=>x.player_id)).size,
        total_play_seconds:Number(player.total_play_seconds)||0,
        monthly_play_seconds:Number(player.monthly_play_seconds)||0,
        monthly_mission_rewarded:!!player.monthly_mission_rewarded||rewardAwarded,
        monthly_mission_closed:Date.now()>=Date.UTC(2026,11,19,0,0,0),
        reward_awarded:rewardAwarded
      });
    }
    if(path==="feed" && req.method==="GET"){
      const cutoff=new Date(Date.now()-90000).toISOString();
      const {data:sessions}=await supabase.from("player_sessions").select("player_id,last_seen_at").gt("expires_at",new Date().toISOString()).gt("last_seen_at",cutoff).order("last_seen_at",{ascending:false}).limit(100);
      const ids=[...new Set((sessions||[]).map(x=>x.player_id))];
      const {data:players}=ids.length?await supabase.from("players").select("id,username,avatar_url,is_creator,optimized_mode").in("id",ids).limit(20):{data:[]};
      const {data:events}=await supabase.from("activity_events").select("id,username,avatar_url,item_name,item_image,case_title,item_value,rarity,created_at").eq("event_type","upgrade_visit").order("created_at",{ascending:false}).limit(12);
      const {data:inventoryItems}=await supabase.from("player_inventory_items").select("id,item_name,item_image,item_value,rarity,updated_at,players(username,avatar_url,is_creator,optimized_mode)").order("updated_at",{ascending:false}).limit(12);
      const mapped=(inventoryItems||[]).map(x=>({id:x.id,item_name:x.item_name,item_image:x.item_image,item_value:x.item_value,rarity:x.rarity,updated_at:x.updated_at,username:x.players?.username,avatar_url:x.players?.avatar_url,is_creator:!!x.players?.is_creator,optimized_mode:!!x.players?.optimized_mode}));
      return json({players:players||[],online:ids.length,events:events||[],inventoryItems:mapped});
    }
    if(path==="inventory" && req.method==="GET"){
      const {data,error}=await supabase.from("player_inventory_items").select("item_id,item_name,item_image,item_value,rarity,is_favorite,slot,updated_at").eq("player_id",user.id).order("slot");
      if(error) throw error; return json({items:data||[]});
    }
    if(path==="inventory" && req.method==="POST"){
      const items=Array.isArray(body.items)?body.items.slice(0,200):[];
      const {error:delError}=await supabase.from("player_inventory_items").delete().eq("player_id",user.id);
      if(delError) throw delError;
      const rows=items.map((item:any,slot:number)=>({
        player_id:user.id,slot,
        item_id:Number.isInteger(Number(item?.item_id))?Number(item.item_id):null,
        item_name:String(item?.item_name||"").trim().slice(0,120),
        item_image:String(item?.item_image||"").trim().slice(0,2048)||null,
        item_value:Math.max(0,Math.min(100000000,Math.trunc(Number(item?.item_value)||0))),
        rarity:String(item?.rarity||"").trim().slice(0,32)||null,
        is_favorite:!!item?.is_favorite
      })).filter((x:any)=>x.item_name&&(!x.item_image||/^https:\/\//i.test(x.item_image)));
      if(rows.length){const {error}=await supabase.from("player_inventory_items").insert(rows);if(error)throw error;}
      return json({ok:true,shown:items.length});
    }
    if(path==="activity-view" && req.method==="POST"){
      if(user.share_upgrade_activity===false) return json({ok:true,skipped:true});
      const since=new Date(Date.now()-600000).toISOString();
      const {data:recent}=await supabase.from("activity_events").select("id").eq("player_id",user.id).eq("event_type","upgrade_visit").gt("created_at",since).limit(1);
      if(!recent?.length){const {error}=await supabase.from("activity_events").insert({player_id:user.id,username:user.username,avatar_url:user.avatar_url,item_name:"Перешёл в раздел «Апгрейдер»",event_type:"upgrade_visit"});if(error)throw error;}
      return json({ok:true},201);
    }
    if(path==="activity" && req.method==="POST"){
      const items=Array.isArray(body.items)?body.items.slice(0,10):[];
      if(!items.length)return json({error:"Нет предметов для публикации"},400);
      const rows=items.map((item:any)=>({player_id:user.id,username:user.username,avatar_url:user.avatar_url,item_name:String(item?.item_name||"").trim().slice(0,120),item_image:String(item?.item_image||"").trim().slice(0,2048)||null,case_title:String(item?.case_title||"").trim().slice(0,80)||null,item_value:Math.max(0,Math.min(100000000,Math.trunc(Number(item?.item_value)||0))),rarity:String(item?.rarity||"").trim().slice(0,32)||null})).filter((x:any)=>x.item_name&&(!x.item_image||/^https:\/\//i.test(x.item_image)));
      if(rows.length){const {error}=await supabase.from("activity_events").insert(rows);if(error)throw error;}
      await supabase.from("activity_events").delete().lt("created_at",new Date(Date.now()-14*86400000).toISOString());
      return json({ok:true},201);
    }
    if(path==="delete-account" && req.method==="POST"){
      const password=String(body.password||"");
      if(!password||password.length>128)return json({error:"Введи пароль аккаунта для подтверждения."},400);
      const {data:stored,error:storedError}=await supabase.from("players").select("password_hash").eq("id",user.id).single();
      if(storedError)throw storedError;
      if(!stored||!(await checkPassword(password,stored.password_hash)))return json({error:"Пароль указан неверно. Аккаунт не удалён."},401);
      const {error:deleteError}=await supabase.from("players").delete().eq("id",user.id);
      if(deleteError)throw deleteError;
      return json({ok:true,deleted:true});
    }
    if(path==="password" && req.method==="POST"){
      const current=String(body.current_password||""),next=String(body.new_password||"");
      if(next.length<8||next.length>128)return json({error:"Новый пароль должен быть от 8 до 128 символов"},400);
      const {data:p}=await supabase.from("players").select("password_hash").eq("id",user.id).single();
      if(!p||!(await checkPassword(current,p.password_hash)))return json({error:"Старый пароль указан неверно"},401);
      const {error}=await supabase.from("players").update({password_hash:await makePassword(next)}).eq("id",user.id);if(error)throw error;
      return json({ok:true});
    }
    if(path==="username" && req.method==="POST"){
      const username=String(body.username||"").trim();
      if(!/^[a-zA-Z0-9_]{3,20}$/.test(username))return json({error:"Ник: 3–20 символов, латиница, цифры или _"},400);
      const {data:existing}=await supabase.from("players").select("id").ilike("username",username).neq("id",user.id).limit(1);
      if(existing?.length)return json({error:"Такой ник уже занят"},409);
      const {data,error}=await supabase.from("players").update({username}).eq("id",user.id).select("id,username,avatar_url").single();
      if(error?.code==="23505")return json({error:"Такой ник уже занят"},409);if(error)throw error;
      return json({user:data});
    }
    if(path==="avatar" && req.method==="POST"){
      const avatar=String(body.avatar||"");
      if(avatar&&(!/^data:image\/(png|jpeg|webp|gif);base64,/.test(avatar)||avatar.length>350000))return json({error:"Загрузи PNG, JPG, WEBP или GIF размером до 250 КБ"},400);
      const {error}=await supabase.from("players").update({avatar_url:avatar||null}).eq("id",user.id);if(error)throw error;
      return json({avatar_url:avatar||null});
    }
    return json({error:"Маршрут не найден"},404);
  } catch(error) {
    console.error("Burmaldep Supabase API:",error);
    return json({error:"Ошибка сервера новой базы данных."},500);
  }
});
