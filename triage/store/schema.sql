-- Probative AI state. Every write is an upsert keyed by alert_id, except the append-only audit log.

create table if not exists events (
    seq          bigserial,                 -- load order, so queries return events as the source listed them
    event_id     text primary key,
    host         text not null,
    ts           timestamptz not null,
    channel      text,
    event_code   integer,
    actor_pid    bigint,                    -- from triage.pipeline.process at load time
    actor_guid   text,
    parent_pid   bigint,
    parent_guid  text,
    fields       jsonb not null
);
create index if not exists events_actor_pid   on events (host, actor_pid);
create index if not exists events_actor_guid  on events (host, lower(actor_guid));
create index if not exists events_parent_pid  on events (host, parent_pid);
create index if not exists events_parent_guid on events (host, lower(parent_guid));

create table if not exists alerts (
    alert_id         text primary key,
    rule_title       text not null,
    host             text not null,
    ts               timestamptz not null,
    trigger_event_id text not null references events (event_id),
    alert            jsonb not null
);
create index if not exists alerts_host_ts on alerts (host, ts);

create table if not exists verdicts (
    alert_id     text primary key references alerts (alert_id),
    judge_result jsonb not null,
    score        jsonb not null,
    report       jsonb not null,
    route        text not null,
    reasons      jsonb not null,
    updated_at   timestamptz not null default now()
);
create index if not exists verdicts_route on verdicts (route);

create table if not exists human_decisions (
    alert_id        text primary key references alerts (alert_id),
    decision        text not null check (decision in ('accept', 'reject')),
    analyst         text not null,
    human_confirmed boolean not null default true,
    decided_at      timestamptz not null default now()
);

create table if not exists rule_modes (
    rule_title text primary key,
    mode       text not null check (mode in ('shadow', 'assisted', 'auto'))
);

create table if not exists audit_log (
    id       bigserial primary key,
    alert_id text,
    kind     text not null,
    payload  jsonb not null,
    at       timestamptz not null default now()
);

alter table audit_log add column if not exists case_id text;

-- Append-only. The one exception is retention: a sandbox case's rows may be deleted after 24 hours.
create or replace function audit_log_append_only() returns trigger language plpgsql as $$
begin
    if tg_op = 'DELETE' and old.case_id is not null and old.at < now() - interval '24 hours' then
        return old;
    end if;
    raise exception 'audit_log is append-only';
end $$;
drop trigger if exists audit_log_no_change on audit_log;
create trigger audit_log_no_change before update or delete on audit_log
    for each row execute function audit_log_append_only();

create table if not exists queue (
    id          bigserial primary key,
    stream      text not null,
    alert_id    text not null,
    priority    integer not null default 0,
    status      text not null default 'ready' check (status in ('ready', 'leased', 'done')),
    lease_until timestamptz,
    attempts    integer not null default 0,
    payload     jsonb not null,
    created_at  timestamptz not null default now(),
    unique (stream, alert_id)
);
create index if not exists queue_claim on queue (stream, status, priority desc, id);

-- Sandbox cases: a visitor's scenario or upload. Their events and alerts carry the case_id,
-- and the whole case is deleted when it expires. Demo data has no case_id.
create table if not exists cases (
    case_id    text primary key,
    source     text not null check (source in ('scenario', 'upload')),
    name       text not null,
    client     text not null,                -- a hash of the requester, for rate limits only
    status     text not null default 'queued' check (status in ('queued', 'processing', 'ready', 'failed')),
    detail     text not null default '',
    n_events   integer not null default 0,
    n_alerts   integer not null default 0,
    llm_used   integer not null default 0,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null
);
alter table events add column if not exists case_id text;
alter table alerts add column if not exists case_id text;
create index if not exists events_case on events (case_id, host);
create index if not exists alerts_case on alerts (case_id);

create table if not exists investigations (
    alert_id      text primary key references alerts (alert_id),
    investigation jsonb not null,
    at            timestamptz not null default now()
);
