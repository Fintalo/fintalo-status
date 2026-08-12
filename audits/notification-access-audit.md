# Notification Feature — Access-Control & Delivery Audit

**Date:** 2026-08-12
**Scope:** Fintalo notification & email system (Supabase project `Fintalo2.0` / `diuqaipsxeixjegorusd`)
**Reported symptoms:**
1. Users receive notifications they should not (e.g. an investor receiving a notification meant for the other party's deal‑team member).
2. This leaks sensitive information such as the **deal name**.
3. The **notifications & email toggle** in Account Settings has no effect.

> **How to read this:** each finding is tagged **CONFIRMED** (proven from code/DB in this audit) or **NEEDS‑VERIFY** (root cause is in the `fintalo2.0` app/frontend repo, which was not attached to this session — the backend evidence strongly implies it). Severity reflects confidentiality impact for an M&A data room.

---

## System architecture (as built)

The current (V2) pipeline:

```
domain event (stage change, upload, Q&A, NDA, negotiation, task…)
   └─ PL/pgSQL emitter (SECURITY DEFINER)  ── inserts a row into ──▶ notification_events
                                                                     (triggered_by_deal_team_id,
                                                                      send_to_deal_team_id,
                                                                      send_to_user_id, payload, internal)
        AFTER INSERT triggers on notification_events:
          • trg_enrich_comment_notification_payload (BEFORE) – adds deal_title to comment payloads
          • zzz_notifications_disabled (BEFORE)             – global kill-switch
          • trg_apply_in_app_suppressions   ── writes ──▶ notification_event_in_app_suppressions
          • trg_broadcast_notification      ── realtime broadcast to notifications:user:<profile_id>
          • send_notification_email         ── HTTP ──▶ send-email edge function ──▶ SendGrid
```

Three **delivery channels**, three **independent recipient computations**:

| Channel | Who receives it | Preference gate |
|---|---|---|
| **In‑app bell** | `get_my_notification_events` RPC (RLS‑equivalent, scoped to caller's own teams) | `notification_event_in_app_suppressions` (from `profile_notification_preferences.in_app_enabled`) |
| **Realtime push** | `broadcast_notification_to_recipients` → per‑member `notifications:user:<id>` topics | Principal/dropped‑team exclusions only |
| **Email** | `defaultResolveRecipients` → members of `send_to_deal_team_id` | `filterRecipientsByV2EmailPreference` (from `profile_notification_preferences.email_enabled`) |

**Good news (verified correct):**
- In‑app read path (`get_my_notification_events`) is correctly scoped to the caller's own active teams (`deal_team_members … deleted_at IS NULL`) and excludes suppressed rows.
- `notification_events` **SELECT** RLS is correctly scoped: `notification_events_select_for_recipients` (permissive, scoped to send‑to user/team) **AND** `notification_events_deny_principal` (restrictive). Reads do **not** leak across parties.
- Realtime channel authorization is correct: `authenticated_read_own_notification_channel` only lets a user read `notifications:user:<their own profile id>`.
- The cross‑party emitters reviewed (`stage_changed`, `document_uploaded`/`document_shared`, `qa_question`/`qa_answer`, `faq_published`, `deadline_created`, `nda_*`, `send_negotiation_*`) all set `send_to_*` to the **correct** counterpart team. No systematic mis‑targeting was found in the emitters.

The problems are therefore **not** in the in‑app read path. They are in (a) the **email** recipient computation, (b) **wide‑open write policies**, (c) **data‑integrity of team membership**, and (d) a **split‑brain preferences model**.

---

## FINDINGS

### F1 — Email is sent to **removed** team members (deal name leak) — **HIGH — CONFIRMED**

**Where:** `supabase/functions/_shared/templates/email.ts` → `defaultResolveRecipients`.

```ts
const { data: members } = await db
  .from('deal_team_members')
  .select('user_id')
  .eq('deal_team_id', ev.send_to_deal_team_id);   // ⬅ NO .is('deleted_at', null)
```

The team‑fan‑out branch of the **email** resolver does **not** filter `deleted_at`. Every other path filters soft‑deleted members:
- realtime broadcast: `WHERE dtm.deal_team_id = … AND dtm.deleted_at IS NULL`
- in‑app `get_my_notification_events`: `dtm.deleted_at IS NULL`

**Impact:** A user who was **removed from** (or moved off) a deal team keeps receiving **email** notifications for that team — deal title, stage changes, document uploads/shares, Q&A, NDA activity — even though the bell/in‑app correctly stops. This is exactly "receiving notifications as [a former] other‑party team member," and it leaks the deal name in the email body/subject. Because the in‑app UI looks correct, it is easy to miss.

**Evidence (production data at audit time):**
- 48 soft‑deleted memberships across 38 teams, 22 distinct removed users.
- **46 of 47** removed user↔team pairs have team‑targeted notification events → the leak is actively firing.

**Fix (one line):**
```ts
const { data: members } = await db
  .from('deal_team_members')
  .select('user_id')
  .eq('deal_team_id', ev.send_to_deal_team_id)
  .is('deleted_at', null);           // add this
```
Redeploy `send-email`. (The `send_to_user_id` branch already filters `profiles.deleted_at`; leave it.)

---

### F2 — Any authenticated user can INSERT / UPDATE / DELETE **any** notification event — **HIGH — CONFIRMED**

**Where:** RLS on `public.notification_events`.

| Policy | Cmd | Role | Expression |
|---|---|---|---|
| `notification_events_insert_any` | INSERT | `authenticated` | `WITH CHECK (true)` |
| `notification_events_update_any` | UPDATE | `authenticated` | `USING (true) WITH CHECK (true)` |
| `notification_events_delete_any` | DELETE | `authenticated` | `USING (true)` |

**Impact:**
- **INSERT:** A logged‑in user can insert an arbitrary `notification_events` row. The `AFTER INSERT` triggers then fire `send-email` and the realtime broadcast — so **any user can make the platform email/push arbitrary content to any team or user of their choosing**, referencing real deals, under Fintalo's brand (spoofing / phishing / notification injection).
- **UPDATE / DELETE:** A logged‑in user can rewrite the `payload`/`status` of, or delete, **any** notification event in the entire database — across all orgs and deals (tampering, evidence destruction, read‑state manipulation).

The service‑role and postgres variants (`…_insert_service`, `…_insert_postgres`, `…_update_service`, `…_delete_service`) already cover the legitimate writers. All legitimate producers are `SECURITY DEFINER` functions, so **no `authenticated` write policy is needed.**

**Fix (migration):**
```sql
DROP POLICY IF EXISTS notification_events_insert_any ON public.notification_events;
DROP POLICY IF EXISTS notification_events_update_any ON public.notification_events;
DROP POLICY IF EXISTS notification_events_delete_any ON public.notification_events;
-- keep *_service and *_postgres; the emitters are SECURITY DEFINER and unaffected.
```
Verify the client never writes `notification_events` directly (it should only read via `get_my_notification_events` and write `notification_reads`). `notification_reads` policies are already correctly scoped to the caller.

---

### F3 — Members of **multiple parties in the same deal** receive both parties' notifications — **HIGH — CONFIRMED (needs per‑deal triage)**

Delivery faithfully follows `deal_team_members`. If a person is an **active** member of two teams in one deal, they legitimately receive both teams' notifications on every channel. From the user's perspective this looks identical to the reported bug.

**Evidence (production data):**
- **28** users are active members of **both an owner team and a participant team in the same deal**.
- **22** users are active members of **2+ distinct participant teams in the same deal** (cross‑investor exposure — the most sensitive case in an M&A context, where bidders must not learn of each other).

Some of these may be intentional (e.g. an advisor legitimately on multiple sides). But each is a potential confidentiality breach and none of the delivery logic questions it. This is the most likely explanation for the **in‑app** "investor sees the other party" reports (F1 explains the email reports).

**Fix / action:**
1. Export the 28 + 22 rows and review each with the deal owners; remove erroneous `deal_team_members` rows (soft‑delete).
2. Add an invariant check / alert: a `user_id` mapped to more than one `deal_team` within a single `deal_id` (especially across `owner`↔`participant` or two `participant` teams) should be flagged at membership‑insert time unless explicitly whitelisted.

---

### F4 — Account‑Settings toggle writes the **legacy** preferences table; delivery reads only the **V2** table — **HIGH — CONFIRMED (backend) / NEEDS‑VERIFY (which table the UI writes)**

There are **two parallel, unlinked preference systems:**

| | Legacy | V2 (authoritative for delivery) |
|---|---|---|
| Table | `profile_notification_settings` (1008 rows) | `profile_notification_preferences` (5373 rows) |
| Keyed by | `notification_group_id` (uuid) | `group_key` (text) |
| Columns | `receive_notification`, `preferred_delivery_channel` (`email`/`in-app`/`mobile`/`all`), `delivery_frequency`, quiet hours, `unsubscribed_at` | `email_enabled`, `in_app_enabled`, `email_unsubscribed_at` |
| Writer | **edge fn `profile-notification-setting`** (CRUD) | **RPC `set_notification_preference`** |

**Delivery consults ONLY V2:**
- Email opt‑out → `filterRecipientsByV2EmailPreference()` reads `profile_notification_preferences.email_enabled` keyed on `notification_types_dim.preference_group_key`.
- In‑app suppression → `apply_in_app_suppressions()` reads `profile_notification_preferences.in_app_enabled` keyed on the same `preference_group_key`.
- The legacy table is read by `send-email` **only** for quiet‑hours + digest cadence (`filterRecipientsBySettings`, described in‑code as "best‑effort"). **`receive_notification = false` and `preferred_delivery_channel` are never used as an on/off switch by any delivery path.**

**Impact:** If the Account‑Settings notifications/email toggles write the **legacy** table (via the `profile-notification-setting` edge function), they have **zero effect** on whether email or in‑app notifications are delivered — matching the reported "toggle not effective." Both tables show recent writes (legacy last updated even more recently than V2), which confirms both are live and out of sync.

**To verify (in `fintalo2.0` app repo):** confirm the settings screen calls `profile-notification-setting` (legacy) rather than the `set_notification_preference` RPC (V2). The backend proves only V2 gates delivery regardless.

**Fix:**
1. Point the settings toggles at the **V2** `set_notification_preference(profile_id, group_key, email_enabled, in_app_enabled)` RPC.
2. One‑time backfill: translate legacy `receive_notification=false` / `preferred_delivery_channel` into V2 `email_enabled` / `in_app_enabled` per group so existing opt‑outs are honored.
3. Retire the legacy write path (or migrate quiet‑hours/digest into V2 as well) to end the split‑brain.

---

### F5 — Toggle **granularity** mismatch (many notification types share one preference group) — **MEDIUM — CONFIRMED**

Delivery preferences are keyed on `notification_types_dim.preference_group_key`, and many distinct types collapse into one group. Examples:

- `stage_change` → `stage_changed`, `deal_deleted`, `deal_marked_lost`, `deal_marked_success`, `deal_public_link_toggled`, `deal_room_live`, `deal_room_offline`, `deal_size_changed`.
- `qa` → `qa_question_submitted`, `qa_question_activity`, `qa_answer_received`, `faq_published`.
- `nda`, `negotiation`, `document`, `task`, `team`, `deadline`, `digest` similarly bundle multiple types.

If the settings UI presents **per‑type** switches but stores **per‑group** values, a user toggling one type silently changes the whole group (or the UI shows state that doesn't match what actually gets stored). Align the UI to the **9 groups** in `notification_preference_groups_dim`, or split the groups to match the UI's granularity.

---

### F6 — Types with a NULL `preference_group_key` are **unmutable** — **LOW/MEDIUM — CONFIRMED (currently latent)**

Both `apply_in_app_suppressions()` and `filterRecipientsByV2EmailPreference()` **no‑op when `preference_group_key IS NULL`** ("Legacy types … cannot be muted via preferences"). Today every row in `notification_types_dim` has a non‑null `preference_group_key`, so this is latent — but any new notification type added without a group becomes impossible to switch off, silently. Add a `NOT NULL` constraint (or a CI check + test) on `notification_types_dim.preference_group_key`.

---

### F7 — Legacy `notification_recipients` table & access helpers — **MEDIUM — NEEDS‑VERIFY**

`notification_recipients` (243 rows) still exists with full CRUD RLS gated by `notification_recipient_is_accessible(...)`, and the dead helper `notification_event_is_accessible(...)` (which grants read on **triggered_by OR send_to** team — broader than the active policy) is still defined. Neither is used by the active `notification_events` policies, but:
- If any client code still reads `notification_recipients`, its access function must be reviewed (not audited here).
- Dead over‑broad helpers are a re‑introduction hazard.

**Action:** confirm `notification_recipients` and `notification_event_is_accessible` are unused, then drop them; otherwise audit `notification_recipient_is_accessible` for correct scoping.

---

## Minor / hygiene

- **`create_participant_invited_notification`** resolves the inviter via `profiles.user_id = NEW.created_by`, whereas sibling emitters treat `created_by` as a **profile id** (`profiles.id`). If `created_by` is a profile id here, the lookup misses and the name falls back to "A team member." Cosmetic, but indicates inconsistent `created_by` semantics worth standardizing.
- **Email trigger fires unconditionally**, then filters inside `send-email`. Correct, but every event invokes the function even when all recipients have opted out (minor cost). Not a bug.
- 37 notification functions have `function_search_path_mutable` and the usual `SECURITY DEFINER executable by anon/authenticated` advisories — standard Supabase hardening backlog, not specific to this incident.

---

## Priority remediation order

1. **F1** — add `.is('deleted_at', null)` to the email resolver, redeploy `send-email`. *(Stops active email leakage to removed members — smallest change, immediate effect.)*
2. **F2** — drop the three `authenticated` write policies on `notification_events`. *(Closes notification injection/tampering.)*
3. **F3** — triage the 28 + 22 cross‑party membership rows; soft‑delete the erroneous ones; add a membership invariant. *(Stops in‑app cross‑party delivery.)*
4. **F4** — repoint Account‑Settings toggles to `set_notification_preference` (V2) + backfill legacy opt‑outs. *(Makes the toggle effective.)*
5. **F5 / F6 / F7** — align preference granularity, enforce non‑null `preference_group_key`, retire dead legacy tables/helpers.

## Suggested regression tests
- Removed team member (`deleted_at` set) receives **no** email for that team (all channels agree).
- Authenticated user cannot `INSERT`/`UPDATE`/`DELETE` `notification_events` (RLS denies).
- No `user_id` maps to >1 `deal_team` within one `deal_id` unless whitelisted.
- Toggling email/in‑app off in settings suppresses the corresponding channel for the next event of that group.
- A notification type with `preference_group_key IS NULL` fails CI.

---

*Investigation basis: Supabase edge functions `send-email`, `profile-notification-setting`; `notification_events` triggers and emitter functions; RLS policies on `notification_events` / `notification_recipients` / `notification_reads` / `profile_notification_*`; `realtime.messages` channel policies; and production data counts cited inline. The application/frontend wiring for the settings screen lives in the `fintalo2.0` repo, which was not attached to this session; items depending on it are marked NEEDS‑VERIFY.*
