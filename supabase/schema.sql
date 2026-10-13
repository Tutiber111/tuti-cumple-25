-- Tuti Trivia: live, Kahoot-style game backend (Supabase / Postgres)
-- All writes go through SECURITY DEFINER functions; clients only get read access where safe.

create extension if not exists pgcrypto;

-- Questions -------------------------------------------------------------
create table public.questions (
  idx        int primary key,                 -- order, starting at 0
  text       text not null,
  options    jsonb not null,                  -- array of strings
  correct    int not null,                    -- 0-based index into options
  note       text,                            -- optional line shown after the answer
  time_limit int not null default 20          -- seconds
);

insert into public.questions (idx, text, options, correct, note, time_limit) values
  (0, '¿Cuántos hermanos tiene Tuti?',        '["1","2","3"]',          1, null,             20),
  (1, '¿Cuántos perros tuvo Tuti?',           '["0","1","2","3"]',      3, null,             20),
  (2, 'El piloto favorito de Tuti es Verstappen', '["Verdadero","Falso"]', 1, 'Es Colapinto.', 15);

-- Games -----------------------------------------------------------------
create table public.games (
  id            uuid primary key default gen_random_uuid(),
  pin           text not null unique,
  state         text not null default 'lobby' check (state in ('lobby','question','reveal','final')),
  q_index       int  not null default -1,
  q_started_at  timestamptz,
  q_time_limit  int,
  q_total       int  not null default 0,
  answer_count  int  not null default 0,
  created_at    timestamptz not null default now()
);

create table public.game_secrets (
  game_id     uuid primary key references public.games(id) on delete cascade,
  host_secret uuid not null default gen_random_uuid()
);

create table public.players (
  id         uuid primary key default gen_random_uuid(),
  game_id    uuid not null references public.games(id) on delete cascade,
  name       text not null check (char_length(name) between 1 and 24),
  score      int  not null default 0,
  created_at timestamptz not null default now()
);
create index players_game_idx on public.players(game_id);

create table public.answers (
  game_id     uuid not null references public.games(id) on delete cascade,
  player_id   uuid not null references public.players(id) on delete cascade,
  q_index     int  not null,
  choice      int  not null,
  is_correct  boolean not null,
  points      int  not null,
  answered_at timestamptz not null default now(),
  primary key (player_id, q_index)
);
create index answers_game_q_idx on public.answers(game_id, q_index);

-- Row level security ----------------------------------------------------
alter table public.questions    enable row level security;
alter table public.games        enable row level security;
alter table public.game_secrets enable row level security;
alter table public.players      enable row level security;
alter table public.answers      enable row level security;

revoke all on public.questions, public.games, public.game_secrets, public.players, public.answers from anon, authenticated;
grant select on public.games, public.players, public.answers to anon, authenticated;

create policy games_read   on public.games   for select to anon, authenticated using (true);
create policy players_read on public.players for select to anon, authenticated using (true);
-- Answers become readable only once their question is no longer open (no peeking at others mid-question).
create policy answers_read on public.answers for select to anon, authenticated using (
  exists (select 1 from public.games g
          where g.id = answers.game_id
            and (g.state <> 'question' or answers.q_index < g.q_index))
);
-- questions and game_secrets: no policies -> not readable by clients.

-- Realtime --------------------------------------------------------------
alter publication supabase_realtime add table public.games, public.players, public.answers;

-- Functions -------------------------------------------------------------
create or replace function public.server_now() returns timestamptz
language sql stable as $$ select now() $$;

create or replace function public.create_game() returns json
language plpgsql security definer set search_path = public as $$
declare v_pin text; v_id uuid; v_secret uuid;
begin
  loop
    v_pin := lpad((floor(random() * 1000000))::int::text, 6, '0');
    exit when not exists (select 1 from games where pin = v_pin);
  end loop;
  insert into games (pin, q_total) values (v_pin, (select count(*) from questions)) returning id into v_id;
  insert into game_secrets (game_id) values (v_id) returning host_secret into v_secret;
  return json_build_object('game_id', v_id, 'pin', v_pin, 'host_secret', v_secret);
end $$;

create or replace function public.join_game(p_pin text, p_name text) returns json
language plpgsql security definer set search_path = public as $$
declare v_game games; v_player uuid; v_name text := left(btrim(p_name), 24);
begin
  if v_name is null or v_name = '' then raise exception 'name_required'; end if;
  select * into v_game from games where pin = btrim(p_pin);
  if not found then raise exception 'game_not_found'; end if;
  if v_game.state = 'final' then raise exception 'game_over'; end if;
  insert into players (game_id, name) values (v_game.id, v_name) returning id into v_player;
  return json_build_object('player_id', v_player, 'game_id', v_game.id, 'name', v_name);
end $$;

-- Current question for a game. The correct answer is only included once the question is revealed.
create or replace function public.current_question(p_game uuid) returns json
language plpgsql security definer set search_path = public as $$
declare v_game games; v_q questions;
begin
  select * into v_game from games where id = p_game;
  if not found or v_game.q_index < 0 then return null; end if;
  select * into v_q from questions where idx = v_game.q_index;
  if not found then return null; end if;
  return json_build_object(
    'idx', v_q.idx, 'text', v_q.text, 'options', v_q.options, 'time_limit', v_q.time_limit,
    'correct', case when v_game.state in ('reveal','final') then v_q.correct end,
    'note',    case when v_game.state in ('reveal','final') then v_q.note end
  );
end $$;

create or replace function public.check_host(p_game uuid, p_secret uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from game_secrets where game_id = p_game and host_secret = p_secret) then
    raise exception 'not_host';
  end if;
end $$;

-- Advance to the next question, or to the final screen after the last one.
create or replace function public.host_next(p_game uuid, p_secret uuid) returns void
language plpgsql security definer set search_path = public as $$
declare v_game games; v_q questions;
begin
  perform check_host(p_game, p_secret);
  select * into v_game from games where id = p_game for update;
  select * into v_q from questions where idx = v_game.q_index + 1;
  if found then
    update games set state = 'question', q_index = v_q.idx, q_started_at = now(),
                     q_time_limit = v_q.time_limit, answer_count = 0
     where id = p_game;
  else
    update games set state = 'final' where id = p_game;
  end if;
end $$;

create or replace function public.host_reveal(p_game uuid, p_secret uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  perform check_host(p_game, p_secret);
  update games set state = 'reveal' where id = p_game and state = 'question';
end $$;

-- Players answer through here. Timing is measured on the server so phone clocks don't matter.
create or replace function public.submit_answer(p_player uuid, p_choice int) returns json
language plpgsql security definer set search_path = public as $$
declare v_player players; v_game games; v_q questions; v_elapsed numeric; v_ok boolean; v_points int; v_rows int;
begin
  select * into v_player from players where id = p_player;
  if not found then raise exception 'player_not_found'; end if;
  select * into v_game from games where id = v_player.game_id;
  if v_game.state <> 'question' then return json_build_object('status', 'closed'); end if;
  v_elapsed := extract(epoch from (now() - v_game.q_started_at));
  if v_elapsed > v_game.q_time_limit + 1.5 then return json_build_object('status', 'late'); end if;
  select * into v_q from questions where idx = v_game.q_index;
  if p_choice < 0 or p_choice >= jsonb_array_length(v_q.options) then raise exception 'bad_choice'; end if;
  v_ok := (p_choice = v_q.correct);
  v_points := case when v_ok then greatest(500, round(1000 - 500 * least(v_elapsed, v_game.q_time_limit) / v_game.q_time_limit))::int else 0 end;
  insert into answers (game_id, player_id, q_index, choice, is_correct, points)
       values (v_game.id, p_player, v_game.q_index, p_choice, v_ok, v_points)
  on conflict do nothing;
  get diagnostics v_rows = row_count;
  if v_rows = 0 then return json_build_object('status', 'already'); end if;
  update players set score = score + v_points where id = p_player;
  update games set answer_count = answer_count + 1 where id = v_game.id;
  return json_build_object('status', 'ok');
end $$;

revoke execute on all functions in schema public from public;
grant execute on function public.server_now(), public.create_game(), public.join_game(text, text),
  public.current_question(uuid), public.host_next(uuid, uuid), public.host_reveal(uuid, uuid),
  public.submit_answer(uuid, int) to anon, authenticated;
