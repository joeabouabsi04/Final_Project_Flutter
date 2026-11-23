-- UpSkills student assignment: current repository schema, 2026-11-16.
-- Fresh Supabase project only. Contains no seed rows, users, passwords or secrets.
-- Derived from all 104 learning migrations through 20260930000005.
begin;
create extension if not exists pgcrypto with schema public;
create extension if not exists citext with schema public;
-- A fresh project must have citext in public to match the source schema's types.
do $$ begin
 if (select n.nspname from pg_extension e join pg_namespace n on n.oid=e.extnamespace where e.extname='citext') <> 'public' then
  raise exception 'citext is installed outside public; use a fresh project or review extension placement before deployment';
 end if;
end $$;
--
-- PostgreSQL database dump
--


-- Dumped from database version 18.3
-- Dumped by pg_dump version 18.3

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;

SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA IF NOT EXISTS public;


--
-- Name: SCHEMA public; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON SCHEMA public IS 'standard public schema';


--
-- Name: restricted; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA restricted;


--
-- Name: SCHEMA restricted; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON SCHEMA restricted IS 'Not exposed via PostgREST. Beneficiary PII lives here; public-schema tables (assessment_scores, survey_responses) reference only a pseudonymous participant_code, never a row here directly.';


--
-- Name: accept_waitlist_offer(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.accept_waitlist_offer(p_registration_id uuid) RETURNS TABLE(registration_id uuid, status_code text, reason text)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  v_registration record;
  v_entry record;
  v_person_id uuid := public.current_person_id();
begin
  select * into v_registration from public.training_registrations where id = p_registration_id for update;
  if v_registration.id is null then
    raise exception 'Registration not found.';
  end if;
  if not (
    (v_person_id is not null and v_registration.person_id = v_person_id)
    or public.current_user_is_trainer_for(v_registration.training_id)
    or public.current_user_has_role('training_manager')
    or public.current_user_has_role('admin')
    or public.current_user_has_role('super_admin')
  ) then
    raise exception 'Only the applicant themselves or a training manager may accept this offer.' using errcode = '42501';
  end if;

  select * into v_entry from public.training_waitlist_entries where training_registration_id = p_registration_id for update;
  if v_entry.id is null or v_entry.status_code <> 'offered' then
    return query select v_registration.id, v_registration.status_code, 'no_active_offer'::text;
    return;
  end if;
  if v_entry.offer_expires_at < now() then
    return query select v_registration.id, v_registration.status_code, 'offer_expired'::text;
    return;
  end if;

  update public.training_waitlist_entries set status_code = 'accepted', accepted_at = now() where id = v_entry.id;
  perform set_config('app.registration_decision_guard', 'authorized', true);
  update public.training_registrations set status_code = 'approved' where id = p_registration_id;

  insert into public.training_registration_status_history
    (training_registration_id, from_status, to_status, reason_code, reason_note, actor_user_id)
    values (p_registration_id, v_registration.status_code, 'approved', 'waitlist_offer_accepted', 'Accepted the waitlist offer', auth.uid());

  return query select v_registration.id, 'approved'::text, null::text;
end;
$$;


--
-- Name: admin_can_manage_staff_user(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_can_manage_staff_user(p_user_id uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select public.current_user_has_role('super_admin') and public.current_user_aal2() and exists (
    select 1
    from public.user_role_assignments ura
    join public.roles r on r.code = ura.role_code
    where ura.user_id = p_user_id and r.is_staff
  );
$$;


--
-- Name: admin_complete_mfa_recovery(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_complete_mfa_recovery(p_user_id uuid) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if not (public.current_user_has_role('super_admin') and public.current_user_aal2()) then
    raise exception 'Only a super administrator with a completed MFA challenge can complete an MFA recovery.' using errcode = '42501';
  end if;

  insert into public.security_events (actor_user_id, subject_user_id, event_type)
  values (auth.uid(), p_user_id, 'mfa_recovery_completed');
end;
$$;


--
-- Name: admin_fail_mfa_recovery(uuid, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_fail_mfa_recovery(p_user_id uuid, p_reason text DEFAULT NULL::text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if not (public.current_user_has_role('super_admin') and public.current_user_aal2()) then
    raise exception 'Only a super administrator with a completed MFA challenge can record a failed MFA recovery.' using errcode = '42501';
  end if;

  insert into public.security_events (actor_user_id, subject_user_id, event_type, metadata)
  values (auth.uid(), p_user_id, 'mfa_recovery_failed', case when p_reason is null then null else jsonb_build_object('reason', p_reason) end);
end;
$$;


--
-- Name: admin_grant_role(text, text, text, uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_grant_role(target_email text, new_role_code text, p_scope_type text DEFAULT NULL::text, p_scope_id uuid DEFAULT NULL::uuid) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  target_user_id uuid;
begin
  if not (public.current_user_has_role('super_admin') and public.current_user_aal2()) then
    raise exception 'Only a super administrator with a completed MFA challenge can grant roles.' using errcode = '42501';
  end if;
  if public.current_user_in_recovery_hold() then
    raise exception 'Your account is in a 24-hour security hold after an MFA recovery and cannot grant roles yet. Ask a different super administrator to release the hold if this needs to happen sooner.' using errcode = '42501';
  end if;

  select id into target_user_id from auth.users where lower(email) = lower(target_email);
  if target_user_id is null then
    raise exception 'No account found for that email.';
  end if;

  if not exists (select 1 from public.roles where code = new_role_code and is_assignable) then
    raise exception 'Unknown or non-assignable role: %', new_role_code;
  end if;

  insert into public.user_role_assignments (user_id, role_code, scope_type, scope_id, granted_by)
  values (target_user_id, new_role_code, p_scope_type, p_scope_id, auth.uid())
  on conflict do nothing;

  insert into public.security_events (actor_user_id, subject_user_id, event_type, metadata)
  values (auth.uid(), target_user_id, 'role_granted', jsonb_build_object('role_code', new_role_code, 'scope_type', p_scope_type, 'scope_id', p_scope_id));
end;
$$;


--
-- Name: FUNCTION admin_grant_role(target_email text, new_role_code text, p_scope_type text, p_scope_id uuid); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.admin_grant_role(target_email text, new_role_code text, p_scope_type text, p_scope_id uuid) IS 'Restricted to admin/super_admin, checked inside the function itself. Parameters are p_-prefixed where they would otherwise collide with user_role_assignments'' own column names (scope_type/scope_id), which previously caused "column reference is ambiguous".';


--
-- Name: admin_list_role_assignments(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_list_role_assignments() RETURNS TABLE(assignment_id uuid, user_id uuid, email text, role_code text, role_label text, scope_type text, scope_label text, granted_at timestamp with time zone, mfa_enrolled boolean, in_recovery_hold boolean)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select
    ura.id,
    ura.user_id,
    au.email::text,
    ura.role_code,
    r.label,
    ura.scope_type,
    coalesce(pt.title, it.title),
    ura.created_at,
    exists (
      select 1 from auth.mfa_factors mf
      where mf.user_id = ura.user_id and mf.status = 'verified'
    ),
    public.user_in_recovery_hold(ura.user_id)
  from public.user_role_assignments ura
  join auth.users au on au.id = ura.user_id
  join public.roles r on r.code = ura.role_code
  left join public.program_translations pt
    on ura.scope_type = 'program' and pt.program_id = ura.scope_id and pt.locale = 'en'
  left join public.initiative_translations it
    on ura.scope_type = 'initiative' and it.initiative_id = ura.scope_id and it.locale = 'en'
  where public.current_user_has_role('super_admin')
  order by au.email, ura.role_code, ura.created_at;
$$;


--
-- Name: admin_list_roles(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_list_roles() RETURNS TABLE(code text, label text, description text, supports_scope boolean)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select r.code, r.label, r.description, r.supports_scope
  from public.roles r
  where public.current_user_has_role('super_admin') and r.is_assignable
  order by r.label;
$$;


--
-- Name: admin_register_trainee(uuid, text, text, text, text, boolean); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_register_trainee(p_training_id uuid, p_full_name text, p_email text, p_phone text, p_reason text, p_override boolean DEFAULT false) RETURNS TABLE(registration_id uuid, status_code text, reason text)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  v_existing record;
  v_submitted record;
  v_decided record;
  v_new_id uuid;
begin
  if not public.current_user_has_permission('training.manage') then
    raise exception 'Only a training manager may register a trainee directly.' using errcode = '42501';
  end if;
  if coalesce(btrim(p_reason), '') = '' then
    raise exception 'A reason is required to register a trainee directly.';
  end if;
  if not exists (select 1 from public.trainings where id = p_training_id) then
    raise exception 'Training not found.';
  end if;

  select * into v_existing from public.training_registrations
    where training_id = p_training_id and email = p_email
    order by created_at desc limit 1;

  if v_existing.id is not null then
    if not p_override then
      return query select null::uuid, null::text, 'already_registered'::text;
      return;
    end if;
    select * into v_decided from public.decide_training_registration(v_existing.id, p_reason, true);
    return query select v_decided.registration_id, v_decided.status_code, v_decided.reason;
    return;
  end if;

  if p_override then
    insert into public.training_registrations (training_id, full_name, email, phone, status_code)
      values (p_training_id, p_full_name, p_email, p_phone, 'pending')
      returning id into v_new_id;
    select * into v_decided from public.decide_training_registration(v_new_id, p_reason, true);
    return query select v_decided.registration_id, v_decided.status_code, v_decided.reason;
    return;
  end if;

  select * into v_submitted from public.submit_training_registration(p_training_id, p_full_name, p_email, p_phone);
  if v_submitted.registration_id is null then
    return query select null::uuid, null::text, v_submitted.ineligibility_reason;
    return;
  end if;

  select * into v_decided from public.decide_training_registration(v_submitted.registration_id, p_reason, false);
  return query select v_decided.registration_id, v_decided.status_code, v_decided.reason;
end;
$$;


--
-- Name: admin_release_recovery_hold(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_release_recovery_hold(p_user_id uuid) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  original_rescuer uuid;
begin
  if not (public.current_user_has_role('super_admin') and public.current_user_aal2()) then
    raise exception 'Only a super administrator with a completed MFA challenge can release a recovery hold.' using errcode = '42501';
  end if;

  if p_user_id = auth.uid() then
    raise exception 'You cannot release your own recovery hold - ask a different super administrator.' using errcode = '42501';
  end if;

  select actor_user_id into original_rescuer
  from public.security_events
  where subject_user_id = p_user_id and event_type = 'mfa_recovery_started'
  order by created_at desc
  limit 1;

  if original_rescuer is null then
    raise exception 'No recovery event found for this account - nothing to release.';
  end if;

  if original_rescuer = auth.uid() then
    raise exception 'A different super administrator must release this hold than the one who performed the recovery.' using errcode = '42501';
  end if;

  insert into public.security_events (actor_user_id, subject_user_id, event_type)
  values (auth.uid(), p_user_id, 'recovery_hold_released');
end;
$$;


--
-- Name: admin_revoke_role(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_revoke_role(assignment_id uuid) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  target_role text;
  target_user uuid;
  target_scope_type text;
  target_scope_id uuid;
  remaining_roles integer;
begin
  if not (public.current_user_has_role('super_admin') and public.current_user_aal2()) then
    raise exception 'Only a super administrator with a completed MFA challenge can revoke roles.' using errcode = '42501';
  end if;
  if public.current_user_in_recovery_hold() then
    raise exception 'Your account is in a 24-hour security hold after an MFA recovery and cannot revoke roles yet. Ask a different super administrator to release the hold if this needs to happen sooner.' using errcode = '42501';
  end if;

  select role_code, user_id, scope_type, scope_id into target_role, target_user, target_scope_type, target_scope_id
  from public.user_role_assignments where id = assignment_id;

  if target_role = 'super_admin' and (
    select count(*) from public.user_role_assignments
    where role_code = 'super_admin' and scope_type is null
  ) <= 1 then
    raise exception 'The final super administrator cannot be removed.';
  end if;

  delete from public.user_role_assignments where id = assignment_id;

  insert into public.security_events (actor_user_id, subject_user_id, event_type, metadata)
  values (auth.uid(), target_user, 'role_revoked', jsonb_build_object('role_code', target_role, 'scope_type', target_scope_type, 'scope_id', target_scope_id));

  select count(*) into remaining_roles
  from public.user_role_assignments where user_id = target_user;
  if remaining_roles = 0 then
    perform public.admin_revoke_user_sessions(target_user);
  end if;
end;
$$;


--
-- Name: FUNCTION admin_revoke_role(assignment_id uuid); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.admin_revoke_role(assignment_id uuid) IS 'Restricted to admin/super_admin, checked inside the function itself, same reasoning as admin_grant_role.';


--
-- Name: admin_revoke_user_sessions(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_revoke_user_sessions(p_user_id uuid) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if not (public.current_user_has_role('super_admin') and public.current_user_aal2()) then
    raise exception 'Only a super administrator with a completed MFA challenge can revoke sessions.' using errcode = '42501';
  end if;

  delete from auth.sessions where user_id = p_user_id;
  delete from auth.refresh_tokens where user_id = p_user_id::text;

  insert into public.security_events (actor_user_id, subject_user_id, event_type)
  values (auth.uid(), p_user_id, 'sessions_revoked');
end;
$$;


--
-- Name: admin_role_access_matrix(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_role_access_matrix() RETURNS TABLE(role_code text, role_label text, module_code text, module_label text, can_read boolean, can_manage boolean)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select
    r.code,
    r.label,
    m.code,
    m.label,
    exists (
      select 1 from public.role_permissions rp
      where rp.role_code = r.code
        and rp.permission_code in (m.read_permission_code, m.manage_permission_code)
    ),
    exists (
      select 1 from public.role_permissions rp
      where rp.role_code = r.code and rp.permission_code = m.manage_permission_code
    )
  from public.roles r
  cross join public.app_modules m
  where public.current_user_has_role('super_admin') and m.is_active
  order by r.label, m.sort_order;
$$;


--
-- Name: admin_start_mfa_recovery(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_start_mfa_recovery(p_user_id uuid) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if not (public.current_user_has_role('super_admin') and public.current_user_aal2()) then
    raise exception 'Only a super administrator with a completed MFA challenge can start an MFA recovery.' using errcode = '42501';
  end if;

  delete from auth.sessions where user_id = p_user_id;
  delete from auth.refresh_tokens where user_id = p_user_id::text;

  insert into public.security_events (actor_user_id, subject_user_id, event_type)
  values (auth.uid(), p_user_id, 'mfa_recovery_started');
end;
$$;


--
-- Name: assign_training_system_identity(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.assign_training_system_identity() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  -- Always replace caller-supplied values. This is a system identifier, not a
  -- form field, and nextval is concurrency-safe.
  new.public_number := nextval('public.training_public_number_seq');
  new.slug := public.build_training_slug('training', new.starts_on, new.public_number);
  return new;
end;
$$;


--
-- Name: authorize_certificate_reissue(uuid, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.authorize_certificate_reissue(p_registration_id uuid, p_reason text) RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  v_revoked_certificate_id uuid;
  v_authorization_id uuid;
begin
  if not public.current_user_has_permission('training.manage') then
    raise exception 'Only training.manage can authorize a certificate reissue.' using errcode = '42501';
  end if;
  if p_reason is null or length(btrim(p_reason)) = 0 then
    raise exception 'A reason is required to authorize a certificate reissue.' using errcode = '22023';
  end if;

  select id into v_revoked_certificate_id
  from public.training_certificates
  where training_registration_id = p_registration_id and revoked_at is not null
  order by issued_at desc
  limit 1;

  if v_revoked_certificate_id is null then
    raise exception 'No revoked certificate exists for this registration to reissue.' using errcode = '42501';
  end if;

  insert into public.training_certificate_reissue_authorizations
    (training_registration_id, revoked_certificate_id, reason)
    values (p_registration_id, v_revoked_certificate_id, btrim(p_reason))
    returning id into v_authorization_id;

  return v_authorization_id;
end;
$$;


--
-- Name: FUNCTION authorize_certificate_reissue(p_registration_id uuid, p_reason text); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.authorize_certificate_reissue(p_registration_id uuid, p_reason text) IS 'training.manage-only, reason required, audited (authorized_by/authorized_at). Creates a one-time authorization keyed to the most recent revoked certificate for this registration - get-certificate.ts requires an unconsumed row here before it will generate a replacement, and marks it consumed the moment it does.';


--
-- Name: available_trainings_for_registration(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.available_trainings_for_registration() RETURNS TABLE(id uuid, slug text, starts_on date, ends_on date, fee_amount_minor_units bigint, fee_currency_code text)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select t.id, t.slug, t.starts_on, t.ends_on, t.fee_amount_minor_units, t.fee_currency_code
  from public.trainings t
  where t.publication_status_code = 'published'
    and public.registration_ineligibility_reason(t.id) is null
  order by t.starts_on asc;
$$;


--
-- Name: build_training_slug(text, date, bigint); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.build_training_slug(p_title text, p_starts_on date, p_public_number bigint) RETURNS text
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'public'
    AS $$
  select public.training_slug_part(p_title)
    || '-' || extract(year from p_starts_on)::integer
    || '-q' || extract(quarter from p_starts_on)::integer
    || '-' || lpad(p_public_number::text, 6, '0');
$$;


--
-- Name: cancel_training_quiz_question(uuid, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.cancel_training_quiz_question(p_question_id uuid, p_reason text) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_question public.training_quiz_questions; v_quiz public.training_quizzes; v_attempt_id uuid; v_count integer := 0;
begin
  select * into v_question from public.training_quiz_questions where id = p_question_id;
  if v_question.id is null then raise exception 'Question not found.' using errcode = '42501'; end if;
  v_quiz := public.training_quiz_staff_check(v_question.quiz_id);
  if v_quiz.status_code = 'draft' then raise exception 'In a draft quiz, remove the question instead.' using errcode = '22023'; end if;
  if coalesce(length(btrim(p_reason)), 0) < 3 then raise exception 'A cancellation needs a reason of at least three characters.' using errcode = '22023'; end if;
  if exists (select 1 from public.training_quiz_question_adjustments where quiz_question_id = p_question_id) then
    raise exception 'This question is already cancelled.' using errcode = '22023';
  end if;
  if (select count(*) from public.training_quiz_questions q where q.quiz_id = v_quiz.id
      and not exists (select 1 from public.training_quiz_question_adjustments a where a.quiz_question_id = q.id)) <= 1 then
    raise exception 'A quiz must keep at least one question; cancel the quiz instead.' using errcode = '22023';
  end if;
  insert into public.training_quiz_question_adjustments (quiz_question_id, adjustment_type, reason, decided_by)
  values (p_question_id, 'cancelled', btrim(p_reason), auth.uid());
  for v_attempt_id in
    select id from public.training_quiz_attempts where quiz_id = v_quiz.id and status_code in ('submitted', 'expired', 'awaiting_manual_marking')
  loop
    perform public.training_quiz_rescore_attempt(v_attempt_id);
    v_count := v_count + 1;
  end loop;
  return v_count;
end;
$$;


--
-- Name: cancel_training_registration(uuid, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.cancel_training_registration(p_registration_id uuid, p_reason text) RETURNS TABLE(registration_id uuid, status_code text)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  v_registration record;
  v_person_id uuid := public.current_person_id();
  v_is_self boolean;
  v_new_status text;
begin
  if coalesce(btrim(p_reason), '') = '' then
    raise exception 'A reason is required to cancel a registration.';
  end if;
  select * into v_registration from public.training_registrations where id = p_registration_id for update;
  if v_registration.id is null then
    raise exception 'Registration not found.';
  end if;
  if v_registration.status_code in ('rejected', 'withdrawn', 'cancelled') then
    raise exception 'This registration has already reached a final state.';
  end if;

  v_is_self := v_person_id is not null and v_registration.person_id = v_person_id;
  if not (
    v_is_self
    or public.current_user_is_trainer_for(v_registration.training_id)
    or public.current_user_has_role('training_manager')
    or public.current_user_has_role('admin')
    or public.current_user_has_role('super_admin')
  ) then
    raise exception 'Only the applicant themselves, the assigned trainer, or a training manager may cancel this registration.' using errcode = '42501';
  end if;

  v_new_status := case when v_is_self then 'withdrawn' else 'cancelled' end;
  perform set_config('app.registration_decision_guard', 'authorized', true);
  update public.training_registrations set status_code = v_new_status where id = p_registration_id;

  insert into public.training_registration_status_history
    (training_registration_id, from_status, to_status, reason_code, reason_note, actor_user_id)
    values (p_registration_id, v_registration.status_code, v_new_status, case when v_is_self then 'self_withdrawn' else 'staff_cancelled' end, p_reason, auth.uid());

  return query select v_registration.id, v_new_status;
end;
$$;


--
-- Name: create_training_charge_on_approval(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.create_training_charge_on_approval() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  fee_amount bigint;
  fee_currency text;
begin
  if new.status_code <> 'approved' or old.status_code = 'approved' then
    return new;
  end if;

  select fee_amount_minor_units, fee_currency_code into fee_amount, fee_currency
  from public.trainings where id = new.training_id;

  if fee_amount is null or fee_amount <= 0 then
    return new;
  end if;

  insert into public.training_charges (training_registration_id, amount_minor_units, currency_code)
  values (new.id, fee_amount, coalesce(fee_currency, 'USD'))
  on conflict (training_registration_id) do nothing;

  return new;
end;
$$;


--
-- Name: FUNCTION create_training_charge_on_approval(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.create_training_charge_on_approval() IS 'A free registration never gets a charge row at all - "not required" is the absence of one, not a zero-value charge. Fires only on the pending/rejected -> approved transition (guarded against re-firing on an already-approved row) so a training''s fee changing later never rewrites an existing charge.';


--
-- Name: current_person_id(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_person_id() RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select person_id from public.user_profiles where user_id = auth.uid();
$$;


--
-- Name: FUNCTION current_person_id(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.current_person_id() IS 'The people.id row linked to the signed-in auth user, or null if they have no profile.';


--
-- Name: current_user_aal2(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_aal2() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select coalesce((auth.jwt() ->> 'aal') = 'aal2', false);
$$;


--
-- Name: FUNCTION current_user_aal2(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.current_user_aal2() IS 'True only when the current session has completed a second authentication factor (TOTP) this session. Not yet referenced by any policy or function - see the migration file header for why enforcement is deliberately deferred.';


--
-- Name: current_user_can_access_beneficiary(uuid, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_can_access_beneficiary(p_beneficiary_id uuid, p_permission text) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public', 'restricted'
    AS $$
  select public.current_user_has_permission(p_permission)
    or exists (
      select 1
      from restricted.program_enrollments pe
      join public.cohorts c on c.id = pe.cohort_id
      join public.program_cycles pc on pc.id = c.program_cycle_id
      where pe.beneficiary_id = p_beneficiary_id
        and public.current_user_can_access_program(pc.program_id, p_permission)
    );
$$;


--
-- Name: current_user_can_access_cohort(uuid, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_can_access_cohort(p_cohort_id uuid, p_permission text) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (
    select 1 from public.cohorts c
    where c.id = p_cohort_id and public.current_user_can_access_program_cycle(c.program_cycle_id, p_permission)
  );
$$;


--
-- Name: current_user_can_access_indicator_scope(uuid, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_can_access_indicator_scope(p_scope_id uuid, p_permission text) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (
    select 1 from public.indicator_scopes s
    where s.id = p_scope_id and (
      (s.program_id is not null and public.current_user_can_access_program(s.program_id, p_permission))
      or (s.initiative_id is not null and public.current_user_can_access_initiative(s.initiative_id, p_permission))
    )
  );
$$;


--
-- Name: current_user_can_access_initiative(uuid, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_can_access_initiative(p_initiative_id uuid, p_permission text) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (
    select 1
    from public.user_role_assignments ura
    join public.role_permissions rp on rp.role_code = ura.role_code
    where ura.user_id = auth.uid()
      and rp.permission_code = p_permission
      and (
        (ura.scope_type is null and ura.scope_id is null)
        or (ura.scope_type = 'initiative' and ura.scope_id = p_initiative_id)
        or (
          ura.scope_type = 'program'
          and exists (
            select 1 from public.initiative_program_links link
            where link.initiative_id = p_initiative_id
              and public.current_user_can_access_program(link.program_id, p_permission)
          )
        )
      )
  );
$$;


--
-- Name: current_user_can_access_measurement_plan(uuid, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_can_access_measurement_plan(p_plan_id uuid, p_permission text) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (
    select 1 from public.measurement_plans mp
    where mp.id = p_plan_id
      and public.current_user_can_access_indicator_scope(mp.indicator_scope_id, p_permission)
  );
$$;


--
-- Name: current_user_can_access_observation(uuid, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_can_access_observation(p_observation_id uuid, p_permission text) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (
    select 1 from public.indicator_observations io
    where io.id = p_observation_id
      and public.current_user_can_access_measurement_plan(io.measurement_plan_id, p_permission)
  );
$$;


--
-- Name: current_user_can_access_program(uuid, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_can_access_program(p_program_id uuid, p_permission text) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  with recursive program_lineage as (
    select p.id, p.parent_program_id from public.programs p where p.id = p_program_id
    union all
    select parent.id, parent.parent_program_id
    from public.programs parent
    join program_lineage child on child.parent_program_id = parent.id
  )
  select exists (
    select 1
    from public.user_role_assignments ura
    join public.role_permissions rp on rp.role_code = ura.role_code
    where ura.user_id = auth.uid()
      and rp.permission_code = p_permission
      and (
        (ura.scope_type is null and ura.scope_id is null)
        or (ura.scope_type = 'program' and ura.scope_id in (select id from program_lineage))
      )
  );
$$;


--
-- Name: current_user_can_access_program_cycle(uuid, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_can_access_program_cycle(p_cycle_id uuid, p_permission text) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (
    select 1 from public.program_cycles pc
    where pc.id = p_cycle_id and public.current_user_can_access_program(pc.program_id, p_permission)
  );
$$;


--
-- Name: current_user_can_manage_attendance(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_can_manage_attendance(p_session_id uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (
    select 1 from public.training_sessions session
    where session.id = p_session_id
      and (
        public.current_user_is_trainer_for(session.training_id)
        or public.current_user_has_permission('training.manage')
      )
  );
$$;


--
-- Name: current_user_can_manage_content(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_can_manage_content() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select public.current_user_has_permission('team.manage') or public.current_user_has_permission('resources.manage');
$$;


--
-- Name: FUNCTION current_user_can_manage_content(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.current_user_can_manage_content() IS 'Owns resources (and, at the tab level only, team member bios — the underlying people/media_assets tables stay staff-wide since trainer/volunteer nomination also writes to them).';


--
-- Name: current_user_can_manage_finance_ops(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_can_manage_finance_ops() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select public.current_user_has_permission('finance.manage') or public.current_user_has_permission('funds.manage') or public.current_user_has_permission('support.manage');
$$;


--
-- Name: FUNCTION current_user_can_manage_finance_ops(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.current_user_can_manage_finance_ops() IS 'Owns funds, memberships and support items/fulfillments.';


--
-- Name: current_user_can_manage_impact(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_can_manage_impact() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select public.current_user_has_any_permission('impact.manage');
$$;


--
-- Name: FUNCTION current_user_can_manage_impact(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.current_user_can_manage_impact() IS 'Owns indicator scopes/measurement plans/reporting periods/observations.';


--
-- Name: current_user_can_manage_intake(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_can_manage_intake() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select public.current_user_has_permission('intake.manage');
$$;


--
-- Name: FUNCTION current_user_can_manage_intake(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.current_user_can_manage_intake() IS 'Owns general public-submission triage (contact/volunteer/partnership) — no specialist role is dedicated to this, so it stays admin/super_admin only rather than every staff role.';


--
-- Name: current_user_can_manage_memberships(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_can_manage_memberships() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select public.current_user_has_permission('memberships.manage');
$$;


--
-- Name: current_user_can_manage_programs(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_can_manage_programs() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select public.current_user_has_any_permission('programs.manage') or public.current_user_has_any_permission('initiatives.manage');
$$;


--
-- Name: FUNCTION current_user_can_manage_programs(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.current_user_can_manage_programs() IS 'Owns programs/initiatives content and structure.';


--
-- Name: current_user_can_manage_trainings(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_can_manage_trainings() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select public.current_user_has_permission('training.manage');
$$;


--
-- Name: FUNCTION current_user_can_manage_trainings(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.current_user_can_manage_trainings() IS 'Owns proposing/viewing trainer candidates and trainings — approving a candidate or publishing a training is already narrower still (trainers_manager_update, enforce_training_publish_approval), unchanged by this migration.';


--
-- Name: current_user_can_submit_training_feedback(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_can_submit_training_feedback(p_registration_id uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (
    select 1
    from public.training_registrations registration
    join public.user_profiles profile on profile.person_id = registration.person_id
    join public.trainings training on training.id = registration.training_id
    where registration.id = p_registration_id
      and profile.user_id = auth.uid()
      and registration.status_code = 'approved'
      and (training.fee_amount_minor_units is null or training.fee_amount_minor_units = 0 or registration.fee_paid)
      and training.ends_on < current_date
  );
$$;


--
-- Name: current_user_can_view_registration(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_can_view_registration(p_training_registration_id uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (
    select 1 from public.training_registrations tr
    where tr.id = p_training_registration_id
      and (tr.person_id = public.current_person_id() or public.current_user_is_trainer_for(tr.training_id))
  )
  or public.current_user_has_role('training_manager')
  or public.current_user_has_role('admin')
  or public.current_user_has_role('super_admin');
$$;


--
-- Name: current_user_has_any_permission(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_has_any_permission(check_permission text) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (
    select 1
    from public.user_role_assignments ura
    join public.role_permissions rp on rp.role_code = ura.role_code
    where ura.user_id = auth.uid() and rp.permission_code = check_permission
  );
$$;


--
-- Name: current_user_has_permission(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_has_permission(check_permission text) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (
    select 1
    from public.user_role_assignments ura
    join public.role_permissions rp on rp.role_code = ura.role_code
    where ura.user_id = auth.uid()
      and ura.scope_type is null
      and ura.scope_id is null
      and rp.permission_code = check_permission
  );
$$;


--
-- Name: current_user_has_role(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_has_role(check_role text) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (
    select 1 from public.user_role_assignments ura
    where ura.user_id = auth.uid()
      and ura.role_code = check_role
      and ura.scope_type is null
      and ura.scope_id is null
  );
$$;


--
-- Name: FUNCTION current_user_has_role(check_role text); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.current_user_has_role(check_role text) IS 'True only for a GLOBAL role assignment. Scoped assignments must be checked with a scope-aware permission helper.';


--
-- Name: current_user_in_recovery_hold(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_in_recovery_hold() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select public.user_in_recovery_hold(auth.uid());
$$;


--
-- Name: current_user_is_staff(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_is_staff() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (
    select 1
    from public.user_role_assignments ura
    join public.roles r on r.code = ura.role_code
    where ura.user_id = auth.uid() and r.is_staff
  );
$$;


--
-- Name: FUNCTION current_user_is_staff(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.current_user_is_staff() IS 'True if the signed-in user holds any internal operational role (not just "member").';


--
-- Name: current_user_is_trainee_for(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_is_trainee_for(p_training_id uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (
    select 1
    from public.training_registrations registration
    join public.user_profiles profile on profile.person_id = registration.person_id
    join public.trainings training on training.id = registration.training_id
    where registration.training_id = p_training_id
      and profile.user_id = auth.uid()
      and registration.status_code = 'approved'
      and (
        training.fee_amount_minor_units is null
        or training.fee_amount_minor_units = 0
        or registration.fee_paid
        or exists (
          select 1 from public.training_fee_access_exceptions exception
          where exception.training_registration_id = registration.id
            and exception.status_code = 'active'
            and (exception.expires_at is null or exception.expires_at > now())
        )
      )
  );
$$;


--
-- Name: FUNCTION current_user_is_trainee_for(p_training_id uuid); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.current_user_is_trainee_for(p_training_id uuid) IS 'True for an approved trainee only when the fee is not required, payment/waiver has cleared it, or a confirmed, unrevoked, unexpired deferred-payment access exception exists.';


--
-- Name: current_user_is_trainer_for(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_is_trainer_for(p_training_id uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (
    select 1
    from public.trainings t
    join public.trainers tr on tr.id = t.trainer_id
    join public.user_profiles up on up.person_id = tr.person_id
    where t.id = p_training_id
      and tr.status_code = 'approved'
      and up.user_id = auth.uid()
  );
$$;


--
-- Name: FUNCTION current_user_is_trainer_for(p_training_id uuid); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.current_user_is_trainer_for(p_training_id uuid) IS 'True only when the signed-in user is an approved trainer assigned to this exact training.';


--
-- Name: current_user_module_access(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_module_access() RETURNS TABLE(module_code text, module_label text, nav_group text, sort_order integer, can_manage boolean, is_scoped boolean)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select
    m.code,
    m.label,
    m.nav_group,
    m.sort_order,
    bool_or(rp.permission_code = m.manage_permission_code),
    not bool_or(ura.scope_type is null)
  from public.app_modules m
  join public.role_permissions rp
    on rp.permission_code in (m.read_permission_code, m.manage_permission_code)
  join public.user_role_assignments ura on ura.role_code = rp.role_code
  where ura.user_id = auth.uid() and m.is_active and m.is_navigation
    and (
      ura.scope_type is null
      or (ura.scope_type = 'program' and m.code in ('programs', 'initiatives', 'impact'))
      or (ura.scope_type = 'initiative' and m.code in ('initiatives', 'impact'))
    )
  group by m.code, m.label, m.nav_group, m.sort_order
  order by m.sort_order;
$$;


--
-- Name: FUNCTION current_user_module_access(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.current_user_module_access() IS 'Dashboard modules available to the caller. is_scoped means every granting assignment is scoped; row-level policies still enforce the exact records.';


--
-- Name: current_user_owns_training_registration(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_owns_training_registration(p_registration_id uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (
    select 1
    from public.training_registrations registration
    join public.user_profiles profile on profile.person_id = registration.person_id
    where registration.id = p_registration_id
      and profile.user_id = auth.uid()
  );
$$;


--
-- Name: current_user_registered_for(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_registered_for(p_training_id uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (
    select 1 from public.training_registrations r
    join public.user_profiles p on p.person_id = r.person_id
    where r.training_id = p_training_id and p.user_id = auth.uid()
  );
$$;


--
-- Name: current_user_role_codes(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_role_codes() RETURNS text[]
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select coalesce(array_agg(distinct ura.role_code), array[]::text[])
  from public.user_role_assignments ura
  where ura.user_id = auth.uid();
$$;


--
-- Name: FUNCTION current_user_role_codes(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.current_user_role_codes() IS 'All role codes the signed-in user holds (deduplicated, any scope). Used by AdminDashboard to decide which tabs to render — a UI convenience, not itself a security boundary; every table below still re-checks the specific role it requires.';


--
-- Name: current_user_trainer_id(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.current_user_trainer_id() RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select tr.id
  from public.trainers tr
  join public.user_profiles up on up.person_id = tr.person_id
  where up.user_id = auth.uid() and tr.status_code = 'approved'
  limit 1;
$$;


--
-- Name: FUNCTION current_user_trainer_id(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.current_user_trainer_id() IS 'The signed-in user''s own trainers.id if they are an approved trainer with a linked login, else null. Used to scope self-service access to exactly their own rows.';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: training_fee_refunds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_fee_refunds (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_charge_id uuid NOT NULL,
    amount_minor_units bigint NOT NULL,
    reason text NOT NULL,
    status_code text DEFAULT 'pending_approval'::text NOT NULL,
    recorded_by uuid,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    decided_by uuid,
    decided_at timestamp with time zone,
    rejection_reason text,
    CONSTRAINT training_fee_refunds_amount_minor_units_check CHECK ((amount_minor_units > 0)),
    CONSTRAINT training_fee_refunds_check CHECK (((status_code = 'rejected'::text) = (rejection_reason IS NOT NULL))),
    CONSTRAINT training_fee_refunds_reason_check CHECK ((length(btrim(reason)) > 0)),
    CONSTRAINT training_fee_refunds_status_code_check CHECK ((status_code = ANY (ARRAY['pending_approval'::text, 'approved'::text, 'rejected'::text])))
);


--
-- Name: TABLE training_fee_refunds; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.training_fee_refunds IS 'A requested refund against a charge - insert-only from a client''s side (mirrors training_fee_transactions); decided_by/decided_at/status_code/rejection_reason are only ever set by decide_fee_refund() below. A charge''s net cleared amount is verified transactions minus approved refunds, never a destructive edit to the transaction that is being refunded.';


--
-- Name: decide_fee_refund(uuid, text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.decide_fee_refund(p_refund_id uuid, p_decision text, p_rejection_reason text DEFAULT NULL::text) RETURNS public.training_fee_refunds
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  refund public.training_fee_refunds;
  charge public.training_charges;
  verified_total bigint;
  approved_refunds_total bigint;
  net_cleared bigint;
begin
  if not public.current_user_has_permission('finance.manage') then
    raise exception 'Only finance.manage can approve or reject a refund.' using errcode = '42501';
  end if;
  if p_decision not in ('approved', 'rejected') then
    raise exception 'decision must be ''approved'' or ''rejected''.';
  end if;
  if p_decision = 'rejected' and coalesce(btrim(p_rejection_reason), '') = '' then
    raise exception 'A rejection reason is required.';
  end if;

  select * into refund from public.training_fee_refunds where id = p_refund_id for update;
  if refund.id is null then
    raise exception 'Refund not found.';
  end if;
  if refund.status_code <> 'pending_approval' then
    raise exception 'This refund has already been decided.';
  end if;
  -- Same maker-checker rule as decide_payment_transaction(): whoever
  -- requested a refund cannot be the one who approves it either.
  if refund.recorded_by = auth.uid() then
    raise exception 'You cannot approve a refund you recorded yourself - ask another finance team member.' using errcode = '42501';
  end if;

  select * into charge from public.training_charges where id = refund.training_charge_id for update;

  if p_decision = 'approved' then
    select coalesce(sum(amount_minor_units), 0) into verified_total
    from public.training_fee_transactions
    where training_charge_id = charge.id and status_code = 'verified';
    select coalesce(sum(amount_minor_units), 0) into approved_refunds_total
    from public.training_fee_refunds
    where training_charge_id = charge.id and status_code = 'approved';

    net_cleared := verified_total - approved_refunds_total;
    if refund.amount_minor_units > net_cleared then
      raise exception 'This refund (%) exceeds the amount actually cleared and not yet refunded (%).', refund.amount_minor_units, net_cleared;
    end if;
  end if;

  update public.training_fee_refunds
  set status_code = p_decision,
      decided_by = auth.uid(),
      decided_at = now(),
      rejection_reason = case when p_decision = 'rejected' then p_rejection_reason else null end
  where id = p_refund_id
  returning * into refund;

  if p_decision = 'approved' then
    select coalesce(sum(amount_minor_units), 0) into verified_total
    from public.training_fee_transactions
    where training_charge_id = charge.id and status_code = 'verified';
    select coalesce(sum(amount_minor_units), 0) into approved_refunds_total
    from public.training_fee_refunds
    where training_charge_id = charge.id and status_code = 'approved';

    -- A partial refund on a previously-cleared charge un-clears the
    -- registration's roster/certificate eligibility going forward, but
    -- never deletes or edits the receipt already issued - see this
    -- project's "never edit an issued receipt" rule. get-certificate.ts
    -- and current_user_is_trainee_for() both re-check fee_paid live on
    -- every request, so this takes effect immediately without needing to
    -- touch either of them.
    update public.training_registrations
    set fee_paid = (verified_total - approved_refunds_total) >= charge.amount_minor_units
    where id = charge.training_registration_id;
  end if;

  return refund;
end;
$$;


--
-- Name: FUNCTION decide_fee_refund(p_refund_id uuid, p_decision text, p_rejection_reason text); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.decide_fee_refund(p_refund_id uuid, p_decision text, p_rejection_reason text) IS 'The only way a training_fee_refunds row can move out of pending_approval. Refuses to approve a refund larger than what is actually cleared net of prior refunds, and recalculates (never erases) the registration''s fee_paid from the same verified-minus-refunded balance decide_payment_transaction() uses.';


--
-- Name: training_fee_transactions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_fee_transactions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_charge_id uuid NOT NULL,
    amount_minor_units bigint NOT NULL,
    currency_code text NOT NULL,
    method text NOT NULL,
    external_reference text,
    occurred_on date DEFAULT CURRENT_DATE NOT NULL,
    internal_note text,
    status_code text DEFAULT 'verification_pending'::text NOT NULL,
    recorded_by uuid,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    verified_by uuid,
    verified_at timestamp with time zone,
    rejection_reason text,
    proof_storage_path text,
    proof_submission_id uuid,
    CONSTRAINT training_fee_transactions_amount_minor_units_check CHECK ((amount_minor_units > 0)),
    CONSTRAINT training_fee_transactions_check CHECK (((status_code = 'rejected'::text) = (rejection_reason IS NOT NULL))),
    CONSTRAINT training_fee_transactions_method_check CHECK ((method = ANY (ARRAY['cash'::text, 'bank_transfer'::text, 'cheque'::text, 'waiver'::text]))),
    CONSTRAINT training_fee_transactions_status_code_check CHECK ((status_code = ANY (ARRAY['verification_pending'::text, 'verified'::text, 'rejected'::text])))
);


--
-- Name: TABLE training_fee_transactions; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.training_fee_transactions IS 'One row per submitted piece of manual payment evidence (cash/bank_transfer/cheque/waiver) against a charge - insert-only from a client''s side; verified_by/verified_at/status_code/rejection_reason are only ever set by decide_payment_transaction() below, never a direct UPDATE. A charge''s balance is the sum of its verified transactions, not "the latest one wins".';


--
-- Name: COLUMN training_fee_transactions.proof_storage_path; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.training_fee_transactions.proof_storage_path IS 'Path in the private training-fee-proofs bucket for supporting evidence (a bank slip scan, a cash receipt photo) finance attaches when recording this transaction - optional, and only ever set at insert time alongside the transaction itself, never edited afterward (no UPDATE policy exists on this table for any role).';


--
-- Name: COLUMN training_fee_transactions.proof_submission_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.training_fee_transactions.proof_submission_id IS 'Set only when this transaction originated from a trainee''s own accepted proof submission (review_fee_proof_submission) - null for a transaction finance recorded directly (e.g. a phone-in payment), same as before this migration.';


--
-- Name: decide_payment_transaction(uuid, text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.decide_payment_transaction(p_transaction_id uuid, p_decision text, p_rejection_reason text DEFAULT NULL::text) RETURNS public.training_fee_transactions
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  txn public.training_fee_transactions;
  charge public.training_charges;
  verified_total bigint;
  all_waiver boolean;
begin
  if not public.current_user_has_permission('finance.manage') then
    raise exception 'Only finance.manage can verify or reject a payment.' using errcode = '42501';
  end if;
  if not public.current_user_aal2() then
    raise exception 'Verifying or rejecting a payment requires a step-up (AAL2) session.' using errcode = '42501';
  end if;
  if p_decision not in ('verified', 'rejected') then
    raise exception 'decision must be ''verified'' or ''rejected''.';
  end if;
  if p_decision = 'rejected' and coalesce(btrim(p_rejection_reason), '') = '' then
    raise exception 'A rejection reason is required.';
  end if;

  select * into txn from public.training_fee_transactions where id = p_transaction_id for update;
  if txn.id is null then
    raise exception 'Payment not found.';
  end if;
  if txn.status_code <> 'verification_pending' then
    raise exception 'This payment has already been decided.';
  end if;
  if txn.recorded_by = auth.uid() then
    raise exception 'You cannot verify a payment you recorded yourself - ask another finance team member.' using errcode = '42501';
  end if;

  select * into charge from public.training_charges where id = txn.training_charge_id for update;

  if p_decision = 'verified' then
    select coalesce(sum(amount_minor_units), 0) into verified_total
    from public.training_fee_transactions
    where training_charge_id = charge.id and status_code = 'verified';

    if verified_total + txn.amount_minor_units > charge.amount_minor_units then
      raise exception 'Verifying this would exceed the charge amount (already verified % of %).', verified_total, charge.amount_minor_units;
    end if;
  end if;

  update public.training_fee_transactions
  set status_code = p_decision,
      verified_by = auth.uid(),
      verified_at = now(),
      rejection_reason = case when p_decision = 'rejected' then p_rejection_reason else null end
  where id = p_transaction_id
  returning * into txn;

  if p_decision = 'verified' then
    select coalesce(sum(amount_minor_units), 0) into verified_total
    from public.training_fee_transactions
    where training_charge_id = charge.id and status_code = 'verified';

    if verified_total >= charge.amount_minor_units then
      update public.training_registrations set fee_paid = true where id = charge.training_registration_id;

      if charge.receipt_number is null then
        select bool_and(method = 'waiver') into all_waiver
        from public.training_fee_transactions
        where training_charge_id = charge.id and status_code = 'verified';

        if all_waiver then
          update public.training_charges
          set receipt_type = 'waiver_confirmation',
              receipt_number = 'USL-WAIVER-' || to_char(now(), 'YYYY') || '-' || lpad(nextval('public.training_waiver_confirmation_number_seq')::text, 6, '0'),
              receipt_issued_at = now()
          where id = charge.id;
        else
          update public.training_charges
          set receipt_type = 'receipt',
              receipt_number = 'USL-RCPT-' || to_char(now(), 'YYYY') || '-' || lpad(nextval('public.training_receipt_number_seq')::text, 6, '0'),
              receipt_issued_at = now()
          where id = charge.id;
        end if;
      end if;
    end if;
  end if;

  return txn;
end;
$$;


--
-- Name: FUNCTION decide_payment_transaction(p_transaction_id uuid, p_decision text, p_rejection_reason text); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.decide_payment_transaction(p_transaction_id uuid, p_decision text, p_rejection_reason text) IS 'The only way a training_fee_transactions row can move out of verification_pending. Now requires an AAL2 session in addition to finance.manage and the existing maker-checker rule (recorded_by <> auth.uid()) - closes the "one-person exception with step-up MFA" gap this function''s own comment named as deliberately deferred, now that current_user_aal2() exists. Recomputes the charge''s verified balance from scratch each time rather than trusting a running total, refuses to let a verified total exceed the charge amount, and - once the charge is fully covered - flips training_registrations.fee_paid and issues either a receipt or, when every contributing transaction was a waiver, a distinct waiver confirmation number, both exactly once.';


--
-- Name: decide_training_academic_plan(uuid, text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.decide_training_academic_plan(p_plan_id uuid, p_decision text, p_note text DEFAULT NULL::text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_weight numeric;
begin
  if not public.current_user_can_manage_trainings() then
    raise exception 'Only a training manager may decide an academic plan.' using errcode = '42501';
  end if;
  if p_decision not in ('approved', 'rejected') then
    raise exception 'Invalid academic-plan decision.' using errcode = '22023';
  end if;
  if p_decision = 'rejected' and coalesce(length(btrim(p_note)), 0) < 3 then
    raise exception 'A rejection needs a note the trainer can act on (at least three characters).' using errcode = '22023';
  end if;
  if p_decision = 'approved' then
    select coalesce(sum(weight_percent), 0) into v_weight from public.training_assessments where academic_plan_id = p_plan_id;
    if v_weight <> 100 then
      raise exception 'Assessment weights must total exactly 100%% (currently %).', v_weight || '%' using errcode = '22023';
    end if;
  end if;
  -- Exactly one approved plan per training: the previous approved version
  -- is retired first (the one-approved index would otherwise refuse the
  -- approval). If the approval below fails, the whole call rolls back.
  if p_decision = 'approved' and exists (select 1 from public.training_academic_plans where id = p_plan_id and status_code = 'pending_approval') then
    update public.training_academic_plans previous
    set status_code = 'superseded'
    where previous.training_id = (select training_id from public.training_academic_plans where id = p_plan_id)
      and previous.id <> p_plan_id and previous.status_code = 'approved';
  end if;

  update public.training_academic_plans
  set status_code = p_decision, decided_by = auth.uid(), decided_at = now(), decision_note = nullif(btrim(p_note), '')
  where id = p_plan_id and status_code = 'pending_approval';
  if not found then raise exception 'Plan not found or not awaiting approval.' using errcode = '42501'; end if;

end;
$$;


--
-- Name: decide_training_completion(uuid, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.decide_training_completion(p_registration_id uuid, p_decision text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  v_training_id uuid;
  v_is_trainer boolean;
  v_can_manage boolean;
  v_elig jsonb;
  v_new_status text;
begin
  if p_decision not in ('completed', 'incomplete', 'not_yet') then
    raise exception 'Invalid completion decision.' using errcode = '22023';
  end if;

  select training_id into v_training_id
  from public.training_registrations where id = p_registration_id
  for update;

  if v_training_id is null then
    raise exception 'Registration not found.' using errcode = '42501';
  end if;

  v_is_trainer := public.current_user_is_trainer_for(v_training_id);
  v_can_manage := public.current_user_has_permission('training.manage');
  if not (v_is_trainer or v_can_manage) then
    raise exception 'Not authorized to decide completion for this registration.' using errcode = '42501';
  end if;

  if p_decision = 'completed' then
    v_elig := public.training_completion_eligibility(p_registration_id);
    if not (v_elig->>'is_eligible')::boolean then
      raise exception 'This registration does not yet meet the completion requirements: %', array_to_string(
        (select array_agg(value #>> '{}') from jsonb_array_elements(v_elig->'reasons')), '; '
      ) using errcode = '42501';
    end if;

    if (v_elig->>'require_manager_approval')::boolean and not v_can_manage then
      v_new_status := 'pending_manager_approval';
    else
      v_new_status := 'completed';
    end if;
  else
    v_new_status := p_decision;
  end if;

  perform set_config('app.completion_decision_guard', 'authorized', true);
  update public.training_registrations set completion_status_code = v_new_status where id = p_registration_id;

  return jsonb_build_object('completion_status_code', v_new_status);
end;
$$;


--
-- Name: FUNCTION decide_training_completion(p_registration_id uuid, p_decision text); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.decide_training_completion(p_registration_id uuid, p_decision text) IS 'The only legitimate way to change completion_status_code - enforce_completion_status_guard below rejects any direct write, including from training.manage. "completed" always re-runs training_completion_eligibility() first; no override exists for either a trainer or a manager, since eligibility here is meant to be a hard gate, not something bypassable by role.';


--
-- Name: decide_training_final_grade(uuid, text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.decide_training_final_grade(p_registration_id uuid, p_decision text, p_note text DEFAULT NULL::text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_submitter uuid;
begin
  if not public.current_user_can_manage_trainings() or not public.current_user_aal2() then raise exception 'A training manager with a completed MFA challenge must approve final grades.' using errcode = '42501'; end if;
  if p_decision not in ('approved', 'rejected') then raise exception 'Invalid final-grade decision.' using errcode = '22023'; end if;
  select submitted_by into v_submitter from public.training_final_grades where training_registration_id = p_registration_id and status_code = 'submitted' for update;
  if v_submitter is null then raise exception 'Final grade not found or not awaiting approval.' using errcode = '42501'; end if;
  if v_submitter = auth.uid() then raise exception 'The person who submitted a final grade cannot approve it.' using errcode = '42501'; end if;
  if p_decision = 'rejected' and coalesce(length(btrim(p_note)), 0) < 3 then raise exception 'A rejection needs a useful note.' using errcode = '22023'; end if;
  update public.training_final_grades set status_code = p_decision, approved_by = auth.uid(), approved_at = now(), decision_note = nullif(btrim(p_note), '') where training_registration_id = p_registration_id;
end;
$$;


--
-- Name: decide_training_registration(uuid, text, boolean); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.decide_training_registration(p_registration_id uuid, p_reason text, p_override boolean DEFAULT false) RETURNS TABLE(registration_id uuid, status_code text, reason text)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  v_registration record;
  v_training record;
  v_on_track_count int;
  v_offered_count int;
  v_new_status text;
begin
  if coalesce(btrim(p_reason), '') = '' then
    raise exception 'A reason is required to decide a registration.';
  end if;

  select * into v_registration from public.training_registrations where id = p_registration_id for update;
  if v_registration.id is null then
    raise exception 'Registration not found.';
  end if;

  if not (
    public.current_user_is_trainer_for(v_registration.training_id)
    or public.current_user_has_role('training_manager')
    or public.current_user_has_role('admin')
    or public.current_user_has_role('super_admin')
  ) then
    raise exception 'Only the assigned trainer or a training manager may decide this registration.' using errcode = '42501';
  end if;

  if not p_override and not public.training_registration_prerequisites_met(p_registration_id) then
    return query select v_registration.id, v_registration.status_code, 'prerequisite_not_met'::text;
    return;
  end if;

  select * into v_training from public.trainings where id = v_registration.training_id for update;

  v_new_status := 'approved';
  if not p_override and v_training.capacity is not null then
    select count(*) into v_on_track_count from public.training_registrations tr
      where tr.training_id = v_registration.training_id and tr.status_code = 'approved' and tr.id <> p_registration_id;
    select count(*) into v_offered_count from public.training_waitlist_entries we
      where we.training_id = v_registration.training_id and we.status_code = 'offered';
    if (v_on_track_count + v_offered_count) >= v_training.capacity then
      if v_training.waitlist_enabled then
        v_new_status := 'waitlisted';
      else
        return query select v_registration.id, v_registration.status_code, 'at_capacity'::text;
        return;
      end if;
    end if;
  end if;

  perform set_config('app.registration_decision_guard', 'authorized', true);
  update public.training_registrations set status_code = v_new_status where id = p_registration_id;

  insert into public.training_registration_status_history
    (training_registration_id, from_status, to_status, reason_code, reason_note, actor_user_id)
    values (p_registration_id, v_registration.status_code, v_new_status, case when p_override then 'decision_override' else 'decision' end, p_reason, auth.uid());

  if v_new_status = 'waitlisted' and not exists (select 1 from public.training_waitlist_entries where training_registration_id = p_registration_id) then
    insert into public.training_waitlist_entries (training_id, training_registration_id, queue_position)
      values (
        v_registration.training_id,
        p_registration_id,
        coalesce((select max(queue_position) + 1 from public.training_waitlist_entries where training_id = v_registration.training_id), 1)
      );
  end if;

  return query select v_registration.id, v_new_status, null::text;
end;
$$;


--
-- Name: enforce_attendance_same_training(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_attendance_same_training() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'public'
    AS $$
begin
  if not exists (
    select 1
    from public.training_sessions session
    join public.training_registrations registration
      on registration.training_id = session.training_id
    where session.id = new.training_session_id
      and registration.id = new.training_registration_id
      and registration.status_code = 'approved'
  ) then
    raise exception 'Attendance session and approved registration must belong to the same training.'
      using errcode = '23514';
  end if;
  return new;
end;
$$;


--
-- Name: enforce_completion_status_guard(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_completion_status_guard() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if auth.role() = 'service_role' then
    return new;
  end if;
  if new.completion_status_code is distinct from old.completion_status_code
     and coalesce(current_setting('app.completion_decision_guard', true), '') <> 'authorized' then
    raise exception 'Completion status may only change through decide_training_completion().' using errcode = '42501';
  end if;
  return new;
end;
$$;


--
-- Name: FUNCTION enforce_completion_status_guard(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.enforce_completion_status_guard() IS 'Blocks every direct write to completion_status_code, even from training.manage - decide_training_completion() sets app.completion_decision_guard right before its own UPDATE, so this only ever passes for that one call path.';


--
-- Name: enforce_credential_self_service_columns(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_credential_self_service_columns() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if auth.role() = 'service_role' or public.current_user_can_manage_trainings() then
    return new;
  end if;

  new.trainer_id := old.trainer_id;
  new.reviewed_by := old.reviewed_by;
  new.reviewed_at := old.reviewed_at;
  new.review_notes := old.review_notes;

  if old.verification_status_code = 'verified' then
    -- Fully locked once verified - same reasoning as email on people:
    -- a trainer who wants to change a verified credential asks staff.
    return old;
  end if;

  -- A trainer may only ever move a credential to draft or submitted -
  -- verified/rejected/expired require training.manage, which already
  -- returned above for anyone who actually holds it.
  if new.verification_status_code not in ('draft', 'submitted') then
    new.verification_status_code := old.verification_status_code;
  end if;

  if old.verification_status_code = 'submitted' and new.verification_status_code = 'submitted' then
    -- Under review - editing the claim itself requires withdrawing to
    -- draft first (submitted -> draft is still allowed above), not
    -- editing out from under the reviewer while it's pending.
    new.credential_type := old.credential_type;
    new.title := old.title;
    new.issuer := old.issuer;
    new.issued_on := old.issued_on;
    new.expires_on := old.expires_on;
  end if;

  return new;
end;
$$;


--
-- Name: FUNCTION enforce_credential_self_service_columns(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.enforce_credential_self_service_columns() IS 'A trainer can draft, edit, withdraw (submitted->draft) and resubmit (rejected->submitted) their own credential, but can never self-verify/reject, touch review fields, or edit the claim while it is under review (submitted). Fully locked once verified.';


--
-- Name: enforce_fee_proof_submission_recorder(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_fee_proof_submission_recorder() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  new.submitted_by := auth.uid();
  new.submitted_at := now();
  new.status_code := 'submitted';
  new.reviewed_by := null;
  new.reviewed_at := null;
  new.review_note := null;
  new.resulting_transaction_id := null;
  return new;
end;
$$;


--
-- Name: enforce_fee_refund_recorder(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_fee_refund_recorder() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  new.recorded_by := auth.uid();
  new.recorded_at := now();
  new.status_code := 'pending_approval';
  new.decided_by := null;
  new.decided_at := null;
  new.rejection_reason := null;
  return new;
end;
$$;


--
-- Name: enforce_grade_only_submission(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_grade_only_submission() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if auth.role() = 'service_role' then return new; end if;
  if exists (select 1 from public.training_assignments t where t.id = new.training_assignment_id and t.is_grade_only
             and not (public.current_user_is_trainer_for(t.training_id) or public.current_user_has_permission('training.manage'))) then
    raise exception 'This task is marked on paper; there is nothing to submit online.' using errcode = '42501';
  end if;
  return new;
end;
$$;


--
-- Name: enforce_payment_record_immutable_fields(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_payment_record_immutable_fields() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if auth.role() = 'service_role' then
    return new;
  end if;
  new.recorded_by := auth.uid();
  new.recorded_at := now();
  return new;
end;
$$;


--
-- Name: FUNCTION enforce_payment_record_immutable_fields(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.enforce_payment_record_immutable_fields() IS 'recorded_by/recorded_at were only column defaults, not enforced - a caller could override either on insert. Forces both to the real caller and the real time regardless of what a client sends.';


--
-- Name: enforce_payment_transaction_recorder(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_payment_transaction_recorder() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  new.recorded_by := auth.uid();
  new.recorded_at := now();
  new.status_code := 'verification_pending';
  new.verified_by := null;
  new.verified_at := null;
  new.rejection_reason := null;
  return new;
end;
$$;


--
-- Name: FUNCTION enforce_payment_transaction_recorder(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.enforce_payment_transaction_recorder() IS 'Same lesson as payment_records'' own immutability fix (20260911000001), applied from the start here instead of found live after the fact: a client cannot supply recorded_by/recorded_at, and cannot insert a transaction that is already "verified" or "rejected" - every transaction starts pending regardless of what it is sent as.';


--
-- Name: enforce_people_self_service_columns(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_people_self_service_columns() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if auth.role() = 'service_role' or public.current_user_has_permission('people.manage') then
    return new;
  end if;
  new.email := old.email;
  new.country := old.country;
  new.notes := old.notes;
  new.archived_at := old.archived_at;
  return new;
end;
$$;


--
-- Name: FUNCTION enforce_people_self_service_columns(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.enforce_people_self_service_columns() IS 'Column-level half of self-service profile authorization on people - people_self_update''s RLS decides which ROW a signed-in person may touch (their own), this decides which COLUMNS. Only the verified, unique-identifier email stays locked (plus country/notes/archived_at, which are internal fields with no self-service UI) - full_name is self-editable as of this migration.';


--
-- Name: enforce_publish_transition_guard(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_publish_transition_guard() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if auth.role() = 'service_role' then
    return new;
  end if;
  if new.publication_status_code in ('publish_pending', 'published', 'publish_failed')
     and (tg_op = 'INSERT' or new.publication_status_code is distinct from old.publication_status_code)
     and coalesce(current_setting('app.publish_decision_guard', true), '') <> 'authorized' then
    raise exception 'Publishing must go through request_training_publication() - it is verified, not a direct status edit.' using errcode = '42501';
  end if;
  return new;
end;
$$;


--
-- Name: FUNCTION enforce_publish_transition_guard(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.enforce_publish_transition_guard() IS 'request_training_publication() sets app.publish_decision_guard right before its own UPDATE to reach publish_pending; only service_role (finalize-training-publications.ts) can reach published/publish_failed at all, since nothing else sets that guard for those two values. Also applies to INSERT - a brand-new training can never be created already published/publish_pending/publish_failed, only draft or archived, then published for real afterward.';


--
-- Name: enforce_submission_columns(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_submission_columns() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  is_grader boolean;
begin
  if auth.role() = 'service_role' then
    return new;
  end if;

  select (
    public.current_user_has_permission('training.manage')
    or exists (
      select 1 from public.training_assignments ta
      where ta.id = new.training_assignment_id
        and public.current_user_is_trainer_for(ta.training_id)
    )
  ) into is_grader;

  if is_grader then
    if new.status_code = 'graded' then
      new.graded_by := auth.uid();
      new.graded_at := now();
    end if;
    return new;
  end if;

  if tg_op = 'UPDATE' then
    if old.status_code not in ('submitted', 'returned') then
      raise exception 'This submission has already been graded and can no longer be edited.' using errcode = '42501';
    end if;
    if (to_jsonb(new) - array['content', 'link_url', 'submitted_at'])
       is distinct from
       (to_jsonb(old) - array['content', 'link_url', 'submitted_at']) then
      raise exception 'You may only update your submission content, not its grade or status.' using errcode = '42501';
    end if;
  end if;

  new.status_code := 'submitted';
  new.grade := null;
  new.is_passing := null;
  new.feedback := null;
  new.graded_by := null;
  new.graded_at := null;
  return new;
end;
$$;


--
-- Name: FUNCTION enforce_submission_columns(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.enforce_submission_columns() IS 'Column-level half of submission authorization (RLS above decides row access only) - a trainee can never set their own grade/feedback/status regardless of what a client sends, and cannot edit a graded submission at all. Mirrors enforce_trainer_registration_columns''s split between row-level RLS and column-level trigger enforcement.';


--
-- Name: enforce_trainer_profile_columns(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_trainer_profile_columns() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if auth.role() = 'service_role' or public.current_user_has_role('training_manager')
     or public.current_user_has_role('admin') or public.current_user_has_role('super_admin') then
    return new;
  end if;
  -- A trainer editing their own row (the only way to reach this trigger
  -- otherwise, since trainers_self_update below is the only other write
  -- policy that could apply) may only change these columns - everything
  -- else (status_code, person_id, reviewed_by/at, applied_at, document
  -- paths) snaps back to its previous value regardless of what a client
  -- sends, same split as enforce_trainer_registration_columns.
  new.status_code := old.status_code;
  new.person_id := old.person_id;
  new.reviewed_by := old.reviewed_by;
  new.reviewed_at := old.reviewed_at;
  new.applied_at := old.applied_at;
  new.cv_storage_path := old.cv_storage_path;
  new.certificate_storage_paths := old.certificate_storage_paths;
  return new;
end;
$$;


--
-- Name: FUNCTION enforce_trainer_profile_columns(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.enforce_trainer_profile_columns() IS 'Column-level half of trainer self-service profile authorization - trainers_self_update''s RLS decides which ROW a trainer may touch (their own), this decides which COLUMNS, same split used throughout this schema (enforce_trainer_registration_columns, enforce_submission_columns).';


--
-- Name: enforce_trainer_registration_columns(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_trainer_registration_columns() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  other_than_fee_paid_changed boolean := (to_jsonb(new) - array['fee_paid', 'updated_at'])
    is distinct from (to_jsonb(old) - array['fee_paid', 'updated_at']);
  fee_paid_changed boolean := new.fee_paid is distinct from old.fee_paid;
  status_changed boolean := new.status_code is distinct from old.status_code;
begin
  if auth.role() = 'service_role' then
    return new;
  end if;

  -- Guard first, before any permission branch below, so no role
  -- (including training_manager/admin/super_admin) can reach any of
  -- these five statuses through a plain update - only through the
  -- function that actually enforces the rule (capacity/prerequisite/
  -- reason, or - for rejected, as of this migration - just the reason)
  -- for that specific transition.
  if status_changed and new.status_code in ('approved', 'waitlisted', 'withdrawn', 'cancelled', 'rejected')
     and coalesce(current_setting('app.registration_decision_guard', true), '') <> 'authorized' then
    raise exception 'This status change must go through decide_training_registration, accept_waitlist_offer, cancel_training_registration or reject_training_registration.'
      using errcode = '42501';
  end if;

  -- fee_paid may only ever change alongside finance.manage, regardless of
  -- what else is changing in the same statement or whether the caller
  -- also separately holds training.manage.
  if fee_paid_changed and not public.current_user_has_permission('finance.manage') then
    raise exception 'Settling a fee requires the finance permission - record it in payment_records, not this column directly.'
      using errcode = '42501';
  end if;

  -- training.manage covers every other column - independent of the
  -- fee_paid check above, which already ran regardless of this permission.
  if public.current_user_has_permission('training.manage') then
    return new;
  end if;

  -- Not a training.manage holder: the finance-only path is only valid
  -- when fee_paid is truly the only thing changing.
  if public.current_user_has_permission('finance.manage') then
    if other_than_fee_paid_changed then
      raise exception 'Finance permission allows updating fee_paid only; other fields require training.manage or the assigned trainer.'
        using errcode = '42501';
    end if;
    return new;
  end if;

  if public.current_user_is_trainer_for(old.training_id) then
    if (to_jsonb(new) - array['status_code', 'completion_status_code', 'reviewed_by', 'reviewed_at', 'updated_at'])
       is distinct from
       (to_jsonb(old) - array['status_code', 'completion_status_code', 'reviewed_by', 'reviewed_at', 'updated_at']) then
      raise exception 'Trainers may update registration decisions and completion only; payment and identity fields require authorized staff.'
        using errcode = '42501';
    end if;

    if new.status_code is distinct from old.status_code then
      new.reviewed_by := auth.uid();
      new.reviewed_at := now();
    else
      new.reviewed_by := old.reviewed_by;
      new.reviewed_at := old.reviewed_at;
    end if;
    return new;
  end if;

  -- The registration's own person may change status_code only - this is
  -- how accept_waitlist_offer/cancel_training_registration let a trainee
  -- accept an offer or withdraw their own registration. Those functions
  -- already fully validate which transition is legitimate (and set the
  -- guard flag above); this just confirms no OTHER column is changing
  -- alongside it.
  if new.person_id is not null and new.person_id = public.current_person_id() then
    if (to_jsonb(new) - array['status_code', 'updated_at']) is distinct from (to_jsonb(old) - array['status_code', 'updated_at']) then
      raise exception 'You may only change your own registration''s status.' using errcode = '42501';
    end if;
    return new;
  end if;

  raise exception 'Not authorized to update this training registration.' using errcode = '42501';
end;
$$;


--
-- Name: enforce_training_assessment_grade(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_training_assessment_grade() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_training_id uuid; v_quiz_autograde boolean; v_task_export boolean;
begin
  if not public.training_grade_context_valid(new.training_registration_id, new.assessment_id) then
    raise exception 'A grade must belong to the registration''s currently approved academic plan.' using errcode = '23514';
  end if;
  select training_id into v_training_id from public.training_registrations where id = new.training_registration_id and status_code = 'approved';
  if v_training_id is null then raise exception 'Grades can only be recorded for an approved registration.' using errcode = '23514'; end if;
  v_quiz_autograde := coalesce(current_setting('app.training_quiz_autograde', true), '') = 'on'
    and exists (
      select 1 from public.training_quiz_attempts attempt
      join public.training_quizzes quiz on quiz.id = attempt.quiz_id
      where attempt.training_registration_id = new.training_registration_id
        and quiz.assessment_id = new.assessment_id
        and attempt.status_code in ('submitted', 'expired')
    );
  v_task_export := coalesce(current_setting('app.training_task_export', true), '') = 'on';
  if not v_task_export and public.training_assessment_is_task_linked(new.assessment_id) then
    raise exception 'This mark is calculated from its linked tasks; change the task marks or record an override with a reason.' using errcode = '42501';
  end if;
  if not (public.current_user_is_trainer_for(v_training_id) or public.current_user_can_manage_trainings() or v_quiz_autograde or v_task_export) then
    raise exception 'Only the assigned trainer or training manager may record grades.' using errcode = '42501';
  end if;
  if public.training_final_grade_locked(new.training_registration_id)
     or (tg_op = 'UPDATE' and public.training_final_grade_locked(old.training_registration_id)) then
    raise exception 'This trainee''s final grade is submitted or approved; marks are locked until it is rejected.' using errcode = '42501';
  end if;
  new.graded_by := case
    when v_quiz_autograde then current_setting('app.training_quiz_autograde_by', true)::uuid
    when v_task_export then coalesce(auth.uid(), nullif(current_setting('app.training_task_export_by', true), '')::uuid)
    else auth.uid() end;
  new.graded_at := now();
  return new;
end;
$$;


--
-- Name: enforce_training_publish_approval(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_training_publish_approval() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if auth.role() = 'service_role' then
    return new;
  end if;
  if new.publication_status_code = 'published'
     and (tg_op = 'INSERT' or old.publication_status_code is distinct from new.publication_status_code)
     and not (public.current_user_has_role('training_manager') or public.current_user_has_role('admin') or public.current_user_has_role('super_admin'))
  then
    raise exception 'Only a training manager can publish a training.';
  end if;
  return new;
end;
$$;


--
-- Name: enforce_training_system_identity(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_training_system_identity() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  english_title text;
begin
  -- Legacy rows keep their manually assigned identity. New rows retain the
  -- original sequence number and always recompute from title/date.
  if old.public_number is null then
    return new;
  end if;

  new.public_number := old.public_number;
  select tt.title into english_title
  from public.training_translations tt
  where tt.training_id = old.id and tt.locale = 'en';

  new.slug := public.build_training_slug(
    coalesce(english_title, 'training'),
    new.starts_on,
    old.public_number
  );
  return new;
end;
$$;


--
-- Name: enforce_training_task_link(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_training_task_link() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_type text; v_old_link_current boolean;
begin
  if tg_op = 'UPDATE' and exists (select 1 from public.training_task_marks where training_assignment_id = old.id) then
    if new.training_id is distinct from old.training_id then
      raise exception 'A task that has marks cannot move to another training.' using errcode = '42501';
    end if;
    if new.max_marks is distinct from old.max_marks or new.task_type is distinct from old.task_type then
      raise exception 'Maximum marks and task type are locked once any trainee has a mark, zero or excused status.' using errcode = '42501';
    end if;
    if old.is_published and not new.is_published then
      raise exception 'A task that has marks cannot be unpublished.' using errcode = '42501';
    end if;
    if new.assessment_id is distinct from old.assessment_id then
      -- Relinking is allowed only after a new plan version replaced the
      -- assessment the task was linked to (the old link is stale).
      select exists (
        select 1 from public.training_assessments a
        join public.training_academic_plans p on p.id = a.academic_plan_id and p.status_code = 'approved' and p.training_id = old.training_id
        where a.id = old.assessment_id
      ) into v_old_link_current;
      if new.assessment_id is null or v_old_link_current then
        raise exception 'The linked assessment is locked once any trainee has a mark, zero or excused status.' using errcode = '42501';
      end if;
    end if;
  end if;

  if new.assessment_id is not null and (tg_op = 'INSERT'
       or new.assessment_id is distinct from old.assessment_id
       or new.task_type is distinct from old.task_type
       or new.training_id is distinct from old.training_id) then
    select a.assessment_type into v_type
    from public.training_assessments a
    join public.training_academic_plans p on p.id = a.academic_plan_id and p.status_code = 'approved' and p.training_id = new.training_id
    where a.id = new.assessment_id;
    if v_type is null then
      raise exception 'A task can only be linked to an assessment in this training''s currently approved academic plan.' using errcode = '23514';
    end if;
    if v_type <> new.task_type then
      raise exception 'A % task cannot count towards a % assessment.', replace(new.task_type, '_', ' '), replace(v_type, '_', ' ') using errcode = '23514';
    end if;
  end if;
  if new.assessment_id is not null and new.max_marks is null then
    raise exception 'A task linked to the Gradebook needs maximum marks.' using errcode = '23514';
  end if;
  return new;
end;
$$;


--
-- Name: expire_due_training_quiz_attempts(integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.expire_due_training_quiz_attempts(p_limit integer DEFAULT 100) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_attempt_id uuid; v_count integer := 0;
begin
  if auth.role() <> 'service_role' then raise exception 'Only the scheduled quiz worker may expire attempts.' using errcode = '42501'; end if;
  if p_limit < 1 or p_limit > 1000 then raise exception 'Invalid batch limit.' using errcode = '22023'; end if;
  for v_attempt_id in
    select id from public.training_quiz_attempts
    where status_code = 'in_progress' and due_at <= now()
    order by due_at limit p_limit for update skip locked
  loop
    perform public.training_quiz_finish_attempt(v_attempt_id, true);
    v_count := v_count + 1;
  end loop;
  return v_count;
end;
$$;


--
-- Name: expire_waitlist_offers(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.expire_waitlist_offers() RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  v_expired record;
  v_count int := 0;
begin
  for v_expired in
    select id, training_id from public.training_waitlist_entries
    where status_code = 'offered' and offer_expires_at < now()
  loop
    perform 1 from public.trainings where id = v_expired.training_id for update;
    update public.training_waitlist_entries set status_code = 'expired' where id = v_expired.id;
    perform public.promote_next_waitlist_entry(v_expired.training_id);
    v_count := v_count + 1;
  end loop;
  return v_count;
end;
$$;


--
-- Name: training_fee_access_exceptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_fee_access_exceptions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_registration_id uuid CONSTRAINT training_fee_access_exception_training_registration_id_not_null NOT NULL,
    status_code text DEFAULT 'pending'::text NOT NULL,
    reason text NOT NULL,
    expires_at timestamp with time zone,
    requested_by uuid NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    decided_by uuid,
    decided_at timestamp with time zone,
    decision_note text,
    revoked_by uuid,
    revoked_at timestamp with time zone,
    revoke_reason text,
    CONSTRAINT training_fee_access_exceptions_check CHECK (((expires_at IS NULL) OR (expires_at > requested_at))),
    CONSTRAINT training_fee_access_exceptions_check1 CHECK (((decided_by IS NULL) OR (decided_by <> requested_by))),
    CONSTRAINT training_fee_access_exceptions_check2 CHECK (((decided_at IS NULL) = (decided_by IS NULL))),
    CONSTRAINT training_fee_access_exceptions_check3 CHECK ((((revoked_at IS NULL) AND (revoked_by IS NULL) AND (revoke_reason IS NULL)) OR ((revoked_at IS NOT NULL) AND (revoked_by IS NOT NULL) AND (revoke_reason IS NOT NULL)))),
    CONSTRAINT training_fee_access_exceptions_check4 CHECK (((status_code <> 'active'::text) OR (decided_by IS NOT NULL))),
    CONSTRAINT training_fee_access_exceptions_check5 CHECK (((status_code <> 'rejected'::text) OR ((decided_by IS NOT NULL) AND (decision_note IS NOT NULL)))),
    CONSTRAINT training_fee_access_exceptions_check6 CHECK (((status_code <> 'revoked'::text) OR (revoked_at IS NOT NULL))),
    CONSTRAINT training_fee_access_exceptions_reason_check CHECK (((length(btrim(reason)) >= 3) AND (length(btrim(reason)) <= 1000))),
    CONSTRAINT training_fee_access_exceptions_status_code_check CHECK ((status_code = ANY (ARRAY['pending'::text, 'active'::text, 'rejected'::text, 'revoked'::text, 'expired'::text])))
);


--
-- Name: TABLE training_fee_access_exceptions; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.training_fee_access_exceptions IS 'Deferred-payment learning access. Finance requests (finance.manage + AAL2), a different training.manage holder confirms (AAL2); either side can revoke. Rows are never overwritten or deleted - each request is its own audited row.';


--
-- Name: finance_request_training_access_exception(uuid, text, date); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.finance_request_training_access_exception(p_training_registration_id uuid, p_reason text, p_expires_on date DEFAULT NULL::date) RETURNS public.training_fee_access_exceptions
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  registration public.training_registrations;
  expiry timestamptz;
  exception_row public.training_fee_access_exceptions;
begin
  if not public.current_user_has_permission('finance.manage') then
    raise exception 'Only finance.manage can request deferred-payment access.' using errcode = '42501';
  end if;
  if not public.current_user_aal2() then
    raise exception 'Requesting deferred-payment access requires a step-up (AAL2) session.' using errcode = '42501';
  end if;
  if coalesce(length(btrim(p_reason)), 0) < 3 then
    raise exception 'A reason of at least three characters is required.' using errcode = '22023';
  end if;

  if p_expires_on is not null then
    expiry := ((p_expires_on + 1)::timestamp at time zone 'Asia/Beirut');
    if expiry <= now() then
      raise exception 'The expiry date must be today or later.' using errcode = '22023';
    end if;
  end if;

  select * into registration from public.training_registrations where id = p_training_registration_id for update;
  if registration.id is null or registration.status_code <> 'approved' then
    raise exception 'Deferred-payment access requires an approved registration.' using errcode = '22023';
  end if;
  if registration.fee_paid then
    raise exception 'This registration is already financially cleared; no exception is needed.' using errcode = '22023';
  end if;

  -- An active row past its expiry no longer grants anything; close it so
  -- it does not block a fresh request via the one-open index.
  update public.training_fee_access_exceptions
  set status_code = 'expired'
  where training_registration_id = p_training_registration_id
    and status_code = 'active' and expires_at is not null and expires_at <= now();

  if exists (select 1 from public.training_fee_access_exceptions
             where training_registration_id = p_training_registration_id and status_code in ('pending', 'active')) then
    raise exception 'This registration already has a pending or active deferred-access exception.' using errcode = '22023';
  end if;

  insert into public.training_fee_access_exceptions (training_registration_id, reason, expires_at, requested_by)
  values (p_training_registration_id, btrim(p_reason), expiry, auth.uid())
  returning * into exception_row;
  return exception_row;
end;
$$;


--
-- Name: handle_registration_status_side_effects(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.handle_registration_status_side_effects() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  v_had_offer boolean := false;
begin
  if new.status_code = old.status_code then
    return new;
  end if;

  if new.status_code in ('withdrawn', 'cancelled') then
    select exists(
      select 1 from public.training_waitlist_entries
      where training_registration_id = new.id and status_code = 'offered'
    ) into v_had_offer;

    update public.training_waitlist_entries
      set status_code = 'cancelled'
      where training_registration_id = new.id and status_code in ('active', 'offered');
  end if;

  if (old.status_code = 'approved' and new.status_code in ('rejected', 'withdrawn', 'cancelled')) or v_had_offer then
    perform public.promote_next_waitlist_entry(new.training_id);
  end if;

  return new;
end;
$$;


--
-- Name: log_own_mfa_event(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.log_own_mfa_event(p_event_type text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if p_event_type not in ('mfa_enrolled', 'mfa_removed') then
    raise exception 'Invalid event type for self-service logging: %', p_event_type;
  end if;
  if auth.uid() is null then
    raise exception 'Not signed in.';
  end if;
  insert into public.security_events (actor_user_id, subject_user_id, event_type)
  values (auth.uid(), auth.uid(), p_event_type);
end;
$$;


--
-- Name: log_status_change_to_audit_log(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.log_status_change_to_audit_log() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  status_column text := TG_ARGV[0];
  old_status text;
  new_status text;
begin
  old_status := case when tg_op = 'UPDATE' then (to_jsonb(old) ->> status_column) else null end;
  new_status := to_jsonb(new) ->> status_column;

  if tg_op = 'INSERT' or old_status is distinct from new_status then
    insert into public.audit_log (actor_user_id, action, table_name, record_id, before_data, after_data)
    values (
      auth.uid(),
      case when tg_op = 'INSERT' then 'status_set' else 'status_change' end,
      tg_table_name,
      new.id,
      case when old_status is null then null else jsonb_build_object(status_column, old_status) end,
      jsonb_build_object(status_column, new_status)
    );
  end if;
  return new;
end;
$$;


--
-- Name: FUNCTION log_status_change_to_audit_log(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.log_status_change_to_audit_log() IS 'Logs every transition of the status column named by the trigger''s first argument to audit_log, including the initial value on insert (before_data null). auth.uid() is null for rows changed by a Cloudflare Function using the service role (e.g. training-registration.ts''s initial insert) - that is the correct value for "no signed-in staff member made this change", not a bug.';


--
-- Name: log_submission_status_change(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.log_submission_status_change() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if tg_op = 'INSERT' or old.status_code is distinct from new.status_code then
    insert into public.submission_status_history (submission_table, submission_id, from_status_code, to_status_code, changed_by)
    values (tg_table_name, new.id, case when tg_op = 'INSERT' then null else old.status_code end, new.status_code, auth.uid());
  end if;
  return new;
end;
$$;


--
-- Name: FUNCTION log_submission_status_change(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.log_submission_status_change() IS 'Logs every status_code transition (including the initial one on insert, from_status_code null) to submission_status_history. auth.uid() is null for rows created by a Cloudflare Function using the service role - that is the correct, expected value for "no signed-in staff member made this change".';


--
-- Name: log_training_assessment_grade(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.log_training_assessment_grade() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_source text;
begin
  if tg_op = 'UPDATE' and new.score_percent is not distinct from old.score_percent and new.feedback is not distinct from old.feedback then
    return null;
  end if;
  v_source := case
    when current_setting('app.training_grade_override', true) = 'on' then 'override'
    when current_setting('app.training_task_export', true) = 'on' then 'tasks'
    when current_setting('app.training_quiz_autograde', true) = 'on' then 'quiz'
    else 'manual' end;
  insert into public.training_assessment_grade_history (training_registration_id, assessment_id, old_score_percent, new_score_percent, source, note, changed_by)
  values (coalesce(new.training_registration_id, old.training_registration_id), coalesce(new.assessment_id, old.assessment_id),
          case when tg_op <> 'INSERT' then old.score_percent end, case when tg_op <> 'DELETE' then new.score_percent end,
          v_source, case when tg_op <> 'DELETE' then new.feedback end, auth.uid());
  return null;
end;
$$;


--
-- Name: log_training_task_mark(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.log_training_task_mark() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  insert into public.training_task_mark_history (training_assignment_id, training_registration_id, old_status_code, old_marks_earned,
    new_status_code, new_marks_earned, excused_reason, changed_by)
  values (coalesce(new.training_assignment_id, old.training_assignment_id), coalesce(new.training_registration_id, old.training_registration_id),
          case when tg_op <> 'INSERT' then old.status_code end, case when tg_op <> 'INSERT' then old.marks_earned end,
          case when tg_op <> 'DELETE' then new.status_code end, case when tg_op <> 'DELETE' then new.marks_earned end,
          case when tg_op <> 'DELETE' then new.excused_reason end, auth.uid());
  return null;
end;
$$;


--
-- Name: mark_training_quiz_answer(uuid, uuid, numeric, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mark_training_quiz_answer(p_attempt_id uuid, p_question_id uuid, p_points numeric, p_feedback text DEFAULT NULL::text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_attempt public.training_quiz_attempts; v_question public.training_quiz_questions;
begin
  select * into v_attempt from public.training_quiz_attempts where id = p_attempt_id;
  if v_attempt.id is null then raise exception 'Quiz attempt not found.' using errcode = '42501'; end if;
  perform public.training_quiz_staff_check(v_attempt.quiz_id);
  if v_attempt.status_code = 'in_progress' then raise exception 'The trainee is still answering this attempt.' using errcode = '22023'; end if;
  select * into v_question from public.training_quiz_questions where id = p_question_id and quiz_id = v_attempt.quiz_id;
  if v_question.id is null then raise exception 'Question does not belong to this quiz.' using errcode = '23514'; end if;
  if v_question.question_type <> 'essay' then raise exception 'Only essay answers are marked by hand; cancel the question instead if it was wrong.' using errcode = '22023'; end if;
  if p_points is null or p_points < 0 or p_points > v_question.points then
    raise exception 'Points must be between 0 and %.', v_question.points using errcode = '22023';
  end if;
  insert into public.training_quiz_answers (quiz_attempt_id, quiz_question_id, response, is_correct, awarded_points, grader_feedback, graded_by, graded_at)
  values (p_attempt_id, p_question_id, 'null'::jsonb, null, p_points, nullif(btrim(p_feedback), ''), auth.uid(), now())
  on conflict (quiz_attempt_id, quiz_question_id) do update
    set awarded_points = excluded.awarded_points, grader_feedback = excluded.grader_feedback, graded_by = excluded.graded_by, graded_at = excluded.graded_at;
  perform public.training_quiz_rescore_attempt(p_attempt_id);
end;
$$;


--
-- Name: my_waitlist_position(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.my_waitlist_position(p_registration_id uuid) RETURNS integer
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select case when mine.status_code = 'active' then (
    select count(*) + 1 from public.training_waitlist_entries other
    where other.training_id = mine.training_id and other.status_code = 'active' and other.queue_position < mine.queue_position
  ) else null end
  from public.training_waitlist_entries mine
  where mine.training_registration_id = p_registration_id;
$$;


--
-- Name: override_training_quiz_grade(uuid, uuid, numeric, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.override_training_quiz_grade(p_quiz_id uuid, p_registration_id uuid, p_score_percent numeric, p_reason text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_quiz public.training_quizzes;
begin
  v_quiz := public.training_quiz_staff_check(p_quiz_id);
  if coalesce(length(btrim(p_reason)), 0) < 3 then raise exception 'An override needs a reason of at least three characters.' using errcode = '22023'; end if;
  if p_score_percent is null or p_score_percent < 0 or p_score_percent > 100 then raise exception 'The score must be between 0 and 100.' using errcode = '22023'; end if;
  if not exists (select 1 from public.training_registrations where id = p_registration_id and training_id = v_quiz.training_id and status_code = 'approved') then
    raise exception 'That trainee is not approved on this training.' using errcode = '22023';
  end if;
  if public.training_final_grade_locked(p_registration_id) then
    raise exception 'This trainee''s final grade is submitted or approved; return it before changing a mark.' using errcode = '42501';
  end if;
  insert into public.training_quiz_grade_overrides (quiz_id, training_registration_id, score_percent, reason, overridden_by, overridden_at)
  values (p_quiz_id, p_registration_id, p_score_percent, btrim(p_reason), auth.uid(), now())
  on conflict (quiz_id, training_registration_id) do update
    set score_percent = excluded.score_percent, reason = excluded.reason, overridden_by = excluded.overridden_by, overridden_at = excluded.overridden_at;
  insert into public.training_assessment_grades (training_registration_id, assessment_id, score_percent, feedback)
  values (p_registration_id, v_quiz.assessment_id, p_score_percent, 'Trainer override: ' || btrim(p_reason))
  on conflict (training_registration_id, assessment_id) do update set score_percent = excluded.score_percent, feedback = excluded.feedback;
end;
$$;


--
-- Name: override_training_task_assessment_grade(uuid, uuid, numeric, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.override_training_task_assessment_grade(p_assessment_id uuid, p_registration_id uuid, p_score_percent numeric, p_reason text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_training uuid;
begin
  select training_id into v_training from public.training_registrations where id = p_registration_id and status_code = 'approved';
  if v_training is null or not (public.current_user_is_trainer_for(v_training) or public.current_user_can_manage_trainings()) then
    raise exception 'Only the assigned trainer or training manager may override this mark.' using errcode = '42501';
  end if;
  if not public.training_grade_context_valid(p_registration_id, p_assessment_id) or not public.training_assessment_is_task_linked(p_assessment_id) then
    raise exception 'Only an assessment calculated from tasks in the approved plan can be overridden here.' using errcode = '22023';
  end if;
  if coalesce(length(btrim(p_reason)), 0) < 3 then raise exception 'An override needs a reason of at least three characters.' using errcode = '22023'; end if;
  if p_score_percent is not null and (p_score_percent < 0 or p_score_percent > 100) then raise exception 'The score must be between 0 and 100.' using errcode = '22023'; end if;
  if public.training_final_grade_locked(p_registration_id) then
    raise exception 'This trainee''s final grade is submitted or approved; return it before changing a mark.' using errcode = '42501';
  end if;

  perform set_config('app.training_task_export', 'on', true);
  perform set_config('app.training_grade_override', 'on', true);
  if p_score_percent is null then
    delete from public.training_task_assessment_overrides where assessment_id = p_assessment_id and training_registration_id = p_registration_id;
    insert into public.training_assessment_grade_history (training_registration_id, assessment_id, source, note, changed_by)
    values (p_registration_id, p_assessment_id, 'override', 'Override removed: ' || btrim(p_reason), auth.uid());
    perform set_config('app.training_grade_override', 'off', true);
    perform public.training_task_export_assessment(p_assessment_id, p_registration_id);
  else
    insert into public.training_task_assessment_overrides (assessment_id, training_registration_id, score_percent, reason, overridden_by, overridden_at)
    values (p_assessment_id, p_registration_id, p_score_percent, btrim(p_reason), auth.uid(), now())
    on conflict (assessment_id, training_registration_id) do update
      set score_percent = excluded.score_percent, reason = excluded.reason, overridden_by = excluded.overridden_by, overridden_at = excluded.overridden_at;
    insert into public.training_assessment_grades (training_registration_id, assessment_id, score_percent, feedback)
    values (p_registration_id, p_assessment_id, p_score_percent, 'Trainer override: ' || btrim(p_reason))
    on conflict (training_registration_id, assessment_id) do update set score_percent = excluded.score_percent, feedback = excluded.feedback;
  end if;
  perform set_config('app.training_grade_override', 'off', true);
  perform set_config('app.training_task_export', 'off', true);
end;
$$;


--
-- Name: prevent_history_change(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.prevent_history_change() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
  raise exception 'Grade history is append-only.' using errcode = '42501';
end;
$$;


--
-- Name: prevent_linked_training_grade_delete(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.prevent_linked_training_grade_delete() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if exists (select 1 from public.training_registrations where id = old.training_registration_id)
     and coalesce(current_setting('app.training_task_export', true), 'off') <> 'on'
     and public.training_assessment_is_task_linked(old.assessment_id) then
    raise exception 'This mark is calculated from its linked tasks; change the task marks or record an override with a reason.' using errcode = '42501';
  end if;
  return old;
end;
$$;


--
-- Name: prevent_locked_training_grade_delete(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.prevent_locked_training_grade_delete() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  -- A registration being deleted cascades here after its own row is gone
  -- (the order against its final grade's cascade is not guaranteed), so
  -- only a direct delete of a locked mark is refused.
  if exists (select 1 from public.training_registrations where id = old.training_registration_id)
     and public.training_final_grade_locked(old.training_registration_id) then
    raise exception 'This trainee''s final grade is submitted or approved; marks are locked until it is rejected.' using errcode = '42501';
  end if;
  return old;
end;
$$;


--
-- Name: prevent_marked_task_delete(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.prevent_marked_task_delete() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  -- A training being deleted cascades here after its own row is gone.
  if exists (select 1 from public.trainings where id = old.training_id)
     and exists (select 1 from public.training_task_marks where training_assignment_id = old.id) then
    raise exception 'A task that has marks cannot be deleted.' using errcode = '42501';
  end if;
  return old;
end;
$$;


--
-- Name: promote_next_waitlist_entry(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.promote_next_waitlist_entry(p_training_id uuid) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  v_next record;
begin
  perform 1 from public.trainings where id = p_training_id for update;

  select * into v_next from public.training_waitlist_entries
    where training_id = p_training_id and status_code = 'active'
    order by queue_position asc
    limit 1
    for update;

  if v_next.id is null then
    return;
  end if;

  update public.training_waitlist_entries
    set status_code = 'offered', offered_at = now(), offer_expires_at = now() + interval '72 hours'
    where id = v_next.id;
end;
$$;


--
-- Name: record_prerequisite_decision(uuid, uuid, text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.record_prerequisite_decision(p_training_registration_id uuid, p_prerequisite_id uuid, p_decision_code text, p_recommendation_text text DEFAULT NULL::text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  v_training_id uuid;
  v_is_manager boolean;
begin
  if p_decision_code not in ('met', 'not_met', 'review_required', 'waived', 'rejected') then
    raise exception 'Invalid decision code.';
  end if;
  select training_id into v_training_id from public.training_registrations where id = p_training_registration_id;
  if v_training_id is null then
    raise exception 'Registration not found.';
  end if;
  v_is_manager := public.current_user_has_role('training_manager') or public.current_user_has_role('admin') or public.current_user_has_role('super_admin');
  if not (public.current_user_is_trainer_for(v_training_id) or v_is_manager) then
    raise exception 'Only the assigned trainer or a training manager may record a prerequisite decision.' using errcode = '42501';
  end if;
  if p_decision_code <> 'review_required' and not v_is_manager then
    raise exception 'Only a training manager may finalize a prerequisite decision - record a recommendation instead.' using errcode = '42501';
  end if;

  insert into public.training_prerequisite_decisions
    (training_registration_id, prerequisite_id, decision_code, recommendation_text, requested_by, reviewed_by, reviewed_at)
    values (
      p_training_registration_id, p_prerequisite_id, p_decision_code, p_recommendation_text, auth.uid(),
      case when p_decision_code = 'review_required' then null else auth.uid() end,
      case when p_decision_code = 'review_required' then null else now() end
    )
  on conflict (training_registration_id, prerequisite_id) do update
    set decision_code = excluded.decision_code,
        recommendation_text = excluded.recommendation_text,
        reviewed_by = excluded.reviewed_by,
        reviewed_at = excluded.reviewed_at;
end;
$$;


--
-- Name: record_training_registration_status_history(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.record_training_registration_status_history() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if tg_op = 'INSERT' then
    insert into public.training_registration_status_history (
      training_registration_id,
      from_status,
      to_status,
      reason_code,
      reason_note,
      actor_user_id
    )
    values (
      new.id,
      null,
      new.status_code,
      null,
      'created',
      auth.uid()
    );
    return new;
  end if;

  if tg_op = 'UPDATE' and old.status_code is distinct from new.status_code then
    insert into public.training_registration_status_history (
      training_registration_id,
      from_status,
      to_status,
      reason_code,
      reason_note,
      actor_user_id
    )
    values (
      new.id,
      old.status_code,
      new.status_code,
      coalesce(new.status_code, 'status_change'),
      null,
      auth.uid()
    );
  end if;

  return new;
end;
$$;


--
-- Name: record_training_task_mark(uuid, uuid, text, numeric, text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.record_training_task_mark(p_assignment_id uuid, p_registration_id uuid, p_status text, p_marks numeric DEFAULT NULL::numeric, p_reason text DEFAULT NULL::text, p_feedback text DEFAULT NULL::text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_task public.training_assignments;
begin
  select * into v_task from public.training_assignments where id = p_assignment_id;
  if v_task.id is null or not (public.current_user_is_trainer_for(v_task.training_id) or public.current_user_can_manage_trainings()) then
    raise exception 'Only the assigned trainer or training manager may mark this task.' using errcode = '42501';
  end if;
  if v_task.assessment_id is null then raise exception 'This task is not linked to the Gradebook.' using errcode = '22023'; end if;
  if not v_task.is_published then raise exception 'Publish the task before marking it.' using errcode = '22023'; end if;
  if not exists (select 1 from public.training_registrations where id = p_registration_id and training_id = v_task.training_id and status_code = 'approved') then
    raise exception 'That trainee is not approved on this training.' using errcode = '22023';
  end if;
  if not public.training_grade_context_valid(p_registration_id, v_task.assessment_id) then
    raise exception 'This task is linked to an assessment that is no longer in the approved plan; link it to the current plan first.' using errcode = '22023';
  end if;
  if public.training_final_grade_locked(p_registration_id) then
    raise exception 'This trainee''s final grade is submitted or approved; return it before changing a mark.' using errcode = '42501';
  end if;

  if p_status = 'ungraded' then
    delete from public.training_task_marks where training_assignment_id = p_assignment_id and training_registration_id = p_registration_id;
  elsif p_status = 'marked' then
    if p_marks is null or p_marks < 0 or p_marks > v_task.max_marks then
      raise exception 'The mark must be between 0 and %.', trim_scale(v_task.max_marks) using errcode = '22023';
    end if;
  elsif p_status = 'excused' then
    if coalesce(length(btrim(p_reason)), 0) < 3 then raise exception 'An excused status needs a reason of at least three characters.' using errcode = '22023'; end if;
  elsif p_status is distinct from 'missing' then
    raise exception 'Unknown mark status.' using errcode = '22023';
  end if;

  if p_status <> 'ungraded' then
    insert into public.training_task_marks (training_assignment_id, training_registration_id, status_code, marks_earned, excused_reason, feedback, marked_by, marked_at)
    values (p_assignment_id, p_registration_id, p_status,
            case p_status when 'marked' then p_marks when 'missing' then 0 end,
            case when p_status = 'excused' then btrim(p_reason) end,
            nullif(btrim(p_feedback), ''), auth.uid(), now())
    on conflict (training_assignment_id, training_registration_id) do update
      set status_code = excluded.status_code, marks_earned = excluded.marks_earned, excused_reason = excluded.excused_reason,
          feedback = excluded.feedback, marked_by = excluded.marked_by, marked_at = excluded.marked_at;
  end if;
  perform public.training_task_export_assessment(v_task.assessment_id, p_registration_id);
end;
$$;


--
-- Name: refresh_training_slug_from_english_title(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.refresh_training_slug_from_english_title() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  target_training_id uuid;
  target_title text;
begin
  if tg_op = 'DELETE' then
    if old.locale = 'en' then
      update public.trainings t
      set slug = public.build_training_slug('training', t.starts_on, t.public_number)
      where t.id = old.training_id and t.public_number is not null;
    end if;
    return old;
  end if;

  if tg_op = 'UPDATE'
     and old.locale = 'en'
     and (new.locale <> 'en' or new.training_id <> old.training_id) then
    update public.trainings t
    set slug = public.build_training_slug('training', t.starts_on, t.public_number)
    where t.id = old.training_id and t.public_number is not null;
  end if;

  if new.locale = 'en' then
    target_training_id := new.training_id;
    target_title := new.title;
    update public.trainings t
    set slug = public.build_training_slug(target_title, t.starts_on, t.public_number)
    where t.id = target_training_id and t.public_number is not null;
  end if;

  return new;
end;
$$;


--
-- Name: registration_ineligibility_reason(uuid, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.registration_ineligibility_reason(p_training_id uuid, p_email text DEFAULT NULL::text) RETURNS text
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  v_training record;
  v_person_id uuid := public.current_person_id();
begin
  select publication_status_code, ends_on, registration_closes_on, registration_opens_on
    into v_training
    from public.trainings where id = p_training_id;

  if v_training is null or v_training.publication_status_code <> 'published' then
    return 'not_published';
  end if;
  if v_training.ends_on < current_date then
    return 'ended';
  end if;
  if v_training.registration_closes_on is not null and v_training.registration_closes_on < current_date then
    return 'registration_closed';
  end if;
  if v_training.registration_opens_on is not null and v_training.registration_opens_on > current_date then
    return 'registration_not_open';
  end if;

  if v_person_id is not null then
    if exists (select 1 from public.training_registrations where training_id = p_training_id and person_id = v_person_id) then
      return 'already_registered';
    end if;
  elsif p_email is not null then
    if exists (select 1 from public.training_registrations where training_id = p_training_id and email = p_email) then
      return 'already_registered';
    end if;
  end if;

  return null;
end;
$$;


--
-- Name: reject_training_registration(uuid, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.reject_training_registration(p_registration_id uuid, p_reason text) RETURNS TABLE(registration_id uuid, status_code text)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  v_registration record;
begin
  if coalesce(btrim(p_reason), '') = '' then
    raise exception 'A reason is required to reject a registration.';
  end if;

  select * into v_registration from public.training_registrations where id = p_registration_id for update;
  if v_registration.id is null then
    raise exception 'Registration not found.';
  end if;
  if v_registration.status_code not in ('pending', 'waitlisted') then
    raise exception 'Only a pending or waitlisted registration can be rejected.';
  end if;

  if not (
    public.current_user_is_trainer_for(v_registration.training_id)
    or public.current_user_has_role('training_manager')
    or public.current_user_has_role('admin')
    or public.current_user_has_role('super_admin')
  ) then
    raise exception 'Only the assigned trainer or a training manager may reject this registration.' using errcode = '42501';
  end if;

  perform set_config('app.registration_decision_guard', 'authorized', true);
  update public.training_registrations set status_code = 'rejected' where id = p_registration_id;

  insert into public.training_registration_status_history
    (training_registration_id, from_status, to_status, reason_code, reason_note, actor_user_id)
    values (p_registration_id, v_registration.status_code, 'rejected', 'decision', p_reason, auth.uid());

  return query select v_registration.id, 'rejected'::text;
end;
$$;


--
-- Name: request_training_publication(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.request_training_publication(p_training_id uuid) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  v_missing_locales text[];
begin
  if not public.current_user_can_manage_trainings() then
    raise exception 'Only a training manager can publish a training.' using errcode = '42501';
  end if;

  select array_agg(expected.locale) into v_missing_locales
  from (values ('en'), ('ar'), ('fr')) as expected(locale)
  where not exists (
    select 1 from public.training_translations tt
    where tt.training_id = p_training_id and tt.locale = expected.locale and length(btrim(tt.title)) > 0
  );

  if v_missing_locales is not null then
    raise exception 'Cannot publish: missing a title for %.', array_to_string(v_missing_locales, ', ') using errcode = '22023';
  end if;

  perform set_config('app.publish_decision_guard', 'authorized', true);
  update public.trainings
  set publication_status_code = 'publish_pending', publish_requested_at = now(), publish_error = null
  where id = p_training_id;

  if not found then
    raise exception 'Training not found.' using errcode = '42501';
  end if;
end;
$$;


--
-- Name: FUNCTION request_training_publication(p_training_id uuid); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.request_training_publication(p_training_id uuid) IS 'The only legitimate way to request publishing a training - enforce_publish_transition_guard rejects any direct write to publish_pending/published/publish_failed. Validates every locale (en/ar/fr) has a non-blank title first; finalize-training-publications.ts is what actually reaches ''published'', only after confirming the built pages are live. Calling this again on a publish_failed (or draft) row is how a manager retries.';


--
-- Name: training_fee_proof_submissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_fee_proof_submissions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_charge_id uuid NOT NULL,
    submitted_by uuid,
    submitted_at timestamp with time zone DEFAULT now() NOT NULL,
    method text NOT NULL,
    amount_minor_units bigint NOT NULL,
    currency_code text NOT NULL,
    external_reference text,
    occurred_on date DEFAULT CURRENT_DATE NOT NULL,
    note text,
    proof_storage_path text NOT NULL,
    status_code text DEFAULT 'submitted'::text NOT NULL,
    reviewed_by uuid,
    reviewed_at timestamp with time zone,
    review_note text,
    resulting_transaction_id uuid,
    CONSTRAINT training_fee_proof_submissions_amount_minor_units_check CHECK ((amount_minor_units > 0)),
    CONSTRAINT training_fee_proof_submissions_check CHECK ((((status_code = ANY (ARRAY['needs_information'::text, 'rejected'::text])) AND (review_note IS NOT NULL)) OR (status_code = ANY (ARRAY['submitted'::text, 'accepted'::text])))),
    CONSTRAINT training_fee_proof_submissions_method_check CHECK ((method = ANY (ARRAY['cash'::text, 'bank_transfer'::text, 'cheque'::text]))),
    CONSTRAINT training_fee_proof_submissions_status_code_check CHECK ((status_code = ANY (ARRAY['submitted'::text, 'needs_information'::text, 'rejected'::text, 'accepted'::text])))
);


--
-- Name: TABLE training_fee_proof_submissions; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.training_fee_proof_submissions IS 'A trainee''s own claim of payment, pending finance triage - kept entirely separate from training_fee_transactions (the verified-evidence ledger) until review_fee_proof_submission() accepts one and creates the corresponding transaction. Insert-only from the client; every other column change happens only through that function.';


--
-- Name: review_fee_proof_submission(uuid, text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.review_fee_proof_submission(p_submission_id uuid, p_decision text, p_note text DEFAULT NULL::text) RETURNS public.training_fee_proof_submissions
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  submission public.training_fee_proof_submissions;
  new_transaction_id uuid;
begin
  if not public.current_user_has_permission('finance.manage') then
    raise exception 'Only finance.manage can review a payment proof submission.' using errcode = '42501';
  end if;
  if p_decision not in ('needs_information', 'rejected', 'accepted') then
    raise exception 'decision must be ''needs_information'', ''rejected'' or ''accepted''.';
  end if;
  if p_decision in ('needs_information', 'rejected') and coalesce(btrim(p_note), '') = '' then
    raise exception 'A note is required to ask for more information or reject a submission.';
  end if;

  select * into submission from public.training_fee_proof_submissions where id = p_submission_id for update;
  if submission.id is null then
    raise exception 'Submission not found.';
  end if;
  if submission.status_code <> 'submitted' then
    raise exception 'This submission has already been reviewed.';
  end if;

  if p_decision = 'accepted' then
    insert into public.training_fee_transactions
      (training_charge_id, amount_minor_units, currency_code, method, external_reference, occurred_on, proof_storage_path, proof_submission_id)
      values (submission.training_charge_id, submission.amount_minor_units, submission.currency_code, submission.method, submission.external_reference, submission.occurred_on, submission.proof_storage_path, submission.id)
      returning id into new_transaction_id;
  end if;

  update public.training_fee_proof_submissions
  set status_code = p_decision,
      reviewed_by = auth.uid(),
      reviewed_at = now(),
      review_note = p_note,
      resulting_transaction_id = new_transaction_id
  where id = p_submission_id
  returning * into submission;

  return submission;
end;
$$;


--
-- Name: FUNCTION review_fee_proof_submission(p_submission_id uuid, p_decision text, p_note text); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.review_fee_proof_submission(p_submission_id uuid, p_decision text, p_note text) IS 'Triages a trainee''s proof submission. needs_information/rejected just record a note back to the trainee. accepted creates the corresponding training_fee_transactions row (verification_pending, recorded_by forced to the caller by the existing enforce_payment_transaction_recorder trigger) - a DIFFERENT finance team member must then call decide_payment_transaction to actually verify it, both by the existing maker-checker rule there and, as of this migration, an AAL2 requirement.';


--
-- Name: review_prerequisite_evidence(uuid, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.review_prerequisite_evidence(p_evidence_id uuid, p_status_code text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  v_training_id uuid;
begin
  if p_status_code not in ('accepted', 'rejected', 'needs_more_info') then
    raise exception 'status must be accepted, rejected or needs_more_info.';
  end if;
  select tr.training_id into v_training_id
    from public.training_prerequisite_evidence e
    join public.training_registrations tr on tr.id = e.training_registration_id
    where e.id = p_evidence_id;
  if v_training_id is null then
    raise exception 'Evidence not found.';
  end if;
  if not (
    public.current_user_is_trainer_for(v_training_id)
    or public.current_user_has_role('training_manager')
    or public.current_user_has_role('admin')
    or public.current_user_has_role('super_admin')
  ) then
    raise exception 'Only the assigned trainer or a training manager may review this evidence.' using errcode = '42501';
  end if;
  update public.training_prerequisite_evidence
    set status_code = p_status_code, reviewed_by = auth.uid(), reviewed_at = now()
    where id = p_evidence_id;
end;
$$;


--
-- Name: revoke_certificate(uuid, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.revoke_certificate(p_certificate_id uuid, p_reason text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if not public.current_user_has_permission('training.manage') then
    raise exception 'Only training.manage can revoke a certificate.' using errcode = '42501';
  end if;
  if p_reason is null or length(btrim(p_reason)) = 0 then
    raise exception 'A reason is required to revoke a certificate.' using errcode = '22023';
  end if;

  update public.training_certificates
  set revoked_at = now(), revoked_reason = btrim(p_reason)
  where id = p_certificate_id and revoked_at is null;

  if not found then
    raise exception 'Certificate not found, or already revoked.' using errcode = '42501';
  end if;
end;
$$;


--
-- Name: FUNCTION revoke_certificate(p_certificate_id uuid, p_reason text); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.revoke_certificate(p_certificate_id uuid, p_reason text) IS 'Revokes the document only - deliberately does not touch completion_status_code, keeping "was this decision correct" and "is this specific PDF still valid" as separate concerns. get-certificate.ts issues a fresh certificate (linked via replaces_certificate_id) the next time it is requested and eligibility still holds.';


--
-- Name: revoke_training_access_exception(uuid, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.revoke_training_access_exception(p_exception_id uuid, p_reason text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if not (public.current_user_has_permission('finance.manage') or public.current_user_has_permission('training.manage')) then
    raise exception 'Only finance or a training manager can revoke deferred-payment access.' using errcode = '42501';
  end if;
  if coalesce(length(btrim(p_reason)), 0) < 3 then
    raise exception 'A revocation reason of at least three characters is required.' using errcode = '22023';
  end if;
  update public.training_fee_access_exceptions
  set status_code = 'revoked', revoked_by = auth.uid(), revoked_at = now(), revoke_reason = btrim(p_reason)
  where id = p_exception_id and status_code in ('pending', 'active');
  if not found then
    raise exception 'No pending or active deferred-access exception with this id.' using errcode = '22023';
  end if;
end;
$$;


--
-- Name: save_training_quiz_answer(uuid, uuid, jsonb); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.save_training_quiz_answer(p_attempt_id uuid, p_question_id uuid, p_response jsonb) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_attempt public.training_quiz_attempts; v_question public.training_quiz_questions;
        v_correct boolean; v_points numeric; v_response_number numeric; v_answer_number numeric;
begin
  select * into v_attempt from public.training_quiz_attempts where id = p_attempt_id for update;
  if v_attempt.id is null or not public.current_user_owns_training_registration(v_attempt.training_registration_id) then
    raise exception 'Quiz attempt not found.' using errcode = '42501';
  end if;
  if v_attempt.status_code <> 'in_progress' or now() >= v_attempt.due_at then
    raise exception 'This quiz attempt has closed.' using errcode = '42501';
  end if;
  select * into v_question from public.training_quiz_questions where id = p_question_id and quiz_id = v_attempt.quiz_id;
  if v_question.id is null then raise exception 'Question does not belong to this quiz.' using errcode = '23514'; end if;
  v_response_number := public.training_quiz_numeric_value(p_response #>> '{}');
  v_answer_number := public.training_quiz_numeric_value(v_question.correct_answer #>> '{}');
  v_correct := case v_question.question_type
    when 'short_answer' then lower(btrim(p_response #>> '{}')) = lower(btrim(v_question.correct_answer #>> '{}'))
    when 'numerical' then v_response_number is not null and v_answer_number is not null
                          and abs(v_response_number - v_answer_number) <= v_question.numerical_tolerance
    when 'essay' then null else p_response = v_question.correct_answer end;
  v_points := case when v_correct is true then v_question.points when v_correct is false then 0 else null end;
  insert into public.training_quiz_answers (quiz_attempt_id, quiz_question_id, response, is_correct, awarded_points)
  values (p_attempt_id, p_question_id, p_response, v_correct, v_points)
  on conflict (quiz_attempt_id, quiz_question_id) do update
    set response = excluded.response, is_correct = excluded.is_correct, awarded_points = excluded.awarded_points, answered_at = now();
end;
$$;


--
-- Name: set_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.set_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
  new.updated_at = now();
  return new;
end;
$$;


--
-- Name: FUNCTION set_updated_at(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.set_updated_at() IS 'Trigger function: stamps updated_at = now() on every UPDATE. Attach with: create trigger set_updated_at before update on <table> for each row execute function public.set_updated_at();';


--
-- Name: stamp_credential_status_dates(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.stamp_credential_status_dates() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if new.verification_status_code = 'submitted' and (tg_op = 'INSERT' or old.verification_status_code is distinct from new.verification_status_code) then
    new.submitted_at := now();
  end if;
  if new.verification_status_code in ('verified', 'rejected') and (tg_op = 'INSERT' or old.verification_status_code is distinct from new.verification_status_code) then
    new.reviewed_by := auth.uid();
    new.reviewed_at := now();
  end if;
  return new;
end;
$$;


--
-- Name: training_quiz_attempts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_quiz_attempts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    quiz_id uuid NOT NULL,
    training_registration_id uuid NOT NULL,
    attempt_number integer NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    due_at timestamp with time zone NOT NULL,
    submitted_at timestamp with time zone,
    status_code text DEFAULT 'in_progress'::text NOT NULL,
    auto_submitted boolean DEFAULT false NOT NULL,
    score_points numeric(9,2),
    score_percent numeric(5,2),
    manual_marking_required boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT training_quiz_attempts_attempt_number_check CHECK ((attempt_number > 0)),
    CONSTRAINT training_quiz_attempts_check CHECK ((((status_code = 'in_progress'::text) AND (submitted_at IS NULL) AND (score_percent IS NULL)) OR ((status_code = ANY (ARRAY['submitted'::text, 'expired'::text])) AND (submitted_at IS NOT NULL) AND (score_percent IS NOT NULL)) OR ((status_code = 'awaiting_manual_marking'::text) AND (submitted_at IS NOT NULL) AND (score_percent IS NULL)))),
    CONSTRAINT training_quiz_attempts_status_code_check CHECK ((status_code = ANY (ARRAY['in_progress'::text, 'submitted'::text, 'expired'::text, 'awaiting_manual_marking'::text])))
);


--
-- Name: start_training_quiz_attempt(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.start_training_quiz_attempt(p_quiz_id uuid) RETURNS public.training_quiz_attempts
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_quiz public.training_quizzes; v_registration_id uuid; v_next integer; v_attempt public.training_quiz_attempts; v_extra_minutes integer; v_close_at timestamptz;
begin
  select * into v_quiz from public.training_quizzes where id = p_quiz_id and status_code = 'scheduled' for update;
  if v_quiz.id is null or now() < v_quiz.opens_at or now() >= v_quiz.closes_at then raise exception 'This quiz is not open.' using errcode = '42501'; end if;
  if not public.current_user_is_trainee_for(v_quiz.training_id) then raise exception 'You do not have learning access to this training.' using errcode = '42501'; end if;
  select id into v_registration_id from public.training_registrations r where r.training_id = v_quiz.training_id and public.current_user_owns_training_registration(r.id) and r.status_code = 'approved';
  if v_registration_id is null then raise exception 'You do not have an approved registration for this training.' using errcode = '42501'; end if;
  select * into v_attempt from public.training_quiz_attempts where quiz_id = p_quiz_id and training_registration_id = v_registration_id and status_code = 'in_progress' order by attempt_number desc limit 1;
  if v_attempt.id is not null then return v_attempt; end if;
  select coalesce(max(attempt_number), 0) + 1 into v_next from public.training_quiz_attempts where quiz_id = p_quiz_id and training_registration_id = v_registration_id;
  if v_next > v_quiz.attempt_limit then raise exception 'No quiz attempts remain.' using errcode = '42501'; end if;
  select coalesce(extra_minutes, 0), closes_at_override into v_extra_minutes, v_close_at
    from public.training_quiz_accommodations where quiz_id = p_quiz_id and training_registration_id = v_registration_id;
  v_close_at := coalesce(v_close_at, v_quiz.closes_at);
  insert into public.training_quiz_attempts (quiz_id, training_registration_id, attempt_number, due_at)
  values (p_quiz_id, v_registration_id, v_next, least(v_close_at + make_interval(mins => v_quiz.grace_minutes), now() + make_interval(mins => v_quiz.duration_minutes + coalesce(v_extra_minutes, 0) + v_quiz.grace_minutes))) returning * into v_attempt;
  return v_attempt;
end;
$$;


--
-- Name: submit_prerequisite_evidence(uuid, uuid, text, text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.submit_prerequisite_evidence(p_training_registration_id uuid, p_prerequisite_id uuid, p_evidence_type text, p_evidence_url text DEFAULT NULL::text, p_evidence_note text DEFAULT NULL::text) RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  v_person_id uuid := public.current_person_id();
  v_registration record;
  v_new_id uuid;
begin
  select training_id, person_id into v_registration from public.training_registrations where id = p_training_registration_id;
  if v_registration.training_id is null then
    raise exception 'Registration not found.';
  end if;
  if v_person_id is null or v_registration.person_id is distinct from v_person_id then
    raise exception 'You may only submit evidence for your own registration.' using errcode = '42501';
  end if;
  if not exists (select 1 from public.training_prerequisites where id = p_prerequisite_id and training_id = v_registration.training_id and active) then
    raise exception 'This prerequisite does not apply to this training.';
  end if;

  insert into public.training_prerequisite_evidence
    (training_registration_id, prerequisite_id, evidence_type, evidence_url, evidence_note, submitted_by)
    values (p_training_registration_id, p_prerequisite_id, p_evidence_type, p_evidence_url, p_evidence_note, auth.uid())
    returning id into v_new_id;
  return v_new_id;
end;
$$;


--
-- Name: submit_training_final_grade(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.submit_training_final_grade(p_registration_id uuid) RETURNS numeric
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_training_id uuid; v_plan_id uuid; v_total numeric; v_count integer; v_expected integer; v_unmarked integer;
begin
  select training_id into v_training_id from public.training_registrations where id = p_registration_id;
  if not public.current_user_is_trainer_for(v_training_id) then raise exception 'Only the assigned trainer may submit a final grade.' using errcode = '42501'; end if;
  select id into v_plan_id from public.training_academic_plans where training_id = v_training_id and status_code = 'approved';
  if v_plan_id is null then raise exception 'This training has no approved academic plan.' using errcode = '42501'; end if;
  if exists (select 1 from public.training_final_grades where training_registration_id = p_registration_id and status_code in ('submitted', 'approved')) then
    raise exception 'This final grade is already submitted or approved.' using errcode = '42501';
  end if;
  select count(*) into v_unmarked
  from public.training_assignments t
  join public.training_assessments a on a.id = t.assessment_id and a.academic_plan_id = v_plan_id
  where t.training_id = v_training_id and t.is_published
    and not exists (select 1 from public.training_task_marks m where m.training_assignment_id = t.id and m.training_registration_id = p_registration_id)
    and not exists (select 1 from public.training_task_assessment_overrides o where o.assessment_id = t.assessment_id and o.training_registration_id = p_registration_id);
  if v_unmarked > 0 then
    raise exception '% linked task(s) are not marked yet. Record a mark, "not submitted" (0) or "excused" for each.', v_unmarked using errcode = '42501';
  end if;
  select count(*) into v_expected from public.training_assessments where academic_plan_id = v_plan_id;
  select count(g.id), coalesce(sum(g.score_percent * a.weight_percent / 100), 0) into v_count, v_total
  from public.training_assessments a left join public.training_assessment_grades g on g.assessment_id = a.id and g.training_registration_id = p_registration_id
  where a.academic_plan_id = v_plan_id;
  if v_expected = 0 or v_count <> v_expected then raise exception 'Every assessment in the approved plan must be graded before final submission.' using errcode = '42501'; end if;
  insert into public.training_final_grades (training_registration_id, academic_plan_id, total_percent, status_code, submitted_by, submitted_at, approved_by, approved_at, decision_note)
  values (p_registration_id, v_plan_id, round(v_total, 2), 'submitted', auth.uid(), now(), null, null, null)
  on conflict (training_registration_id) do update set academic_plan_id = excluded.academic_plan_id, total_percent = excluded.total_percent, status_code = 'submitted', submitted_by = auth.uid(), submitted_at = now(), approved_by = null, approved_at = null, decision_note = null;
  return round(v_total, 2);
end;
$$;


--
-- Name: submit_training_quiz_attempt(uuid, boolean); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.submit_training_quiz_attempt(p_attempt_id uuid, p_auto_submit boolean DEFAULT false) RETURNS numeric
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_attempt public.training_quiz_attempts;
begin
  select * into v_attempt from public.training_quiz_attempts where id = p_attempt_id;
  if v_attempt.id is null or not public.current_user_owns_training_registration(v_attempt.training_registration_id) then
    raise exception 'Quiz attempt not found.' using errcode = '42501';
  end if;
  if v_attempt.status_code = 'in_progress' then
    if now() > v_attempt.due_at and not p_auto_submit then
      raise exception 'This quiz attempt has closed.' using errcode = '42501';
    end if;
    perform public.training_quiz_finish_attempt(p_attempt_id, p_auto_submit and now() > v_attempt.due_at);
  end if;
  if not public.training_quiz_results_released(v_attempt.quiz_id) then return null; end if;
  return (select score_percent from public.training_quiz_attempts where id = p_attempt_id);
end;
$$;


--
-- Name: submit_training_registration(uuid, text, text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.submit_training_registration(p_training_id uuid, p_full_name text, p_email text, p_phone text DEFAULT NULL::text) RETURNS TABLE(registration_id uuid, status_code text, ineligibility_reason text)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  v_person_id uuid := public.current_person_id();
  v_reason text;
  v_new_id uuid;
begin
  v_reason := public.registration_ineligibility_reason(p_training_id, p_email);
  if v_reason is not null then
    return query select null::uuid, null::text, v_reason;
    return;
  end if;

  begin
    insert into public.training_registrations (training_id, person_id, full_name, email, phone, status_code)
      values (p_training_id, v_person_id, p_full_name, p_email, p_phone, 'pending')
      returning id into v_new_id;
  exception when unique_violation then
    return query select null::uuid, null::text, 'already_registered'::text;
    return;
  end;

  return query select v_new_id, 'pending'::text, null::text;
end;
$$;


--
-- Name: support_item_progress(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.support_item_progress(p_support_item_id uuid) RETURNS TABLE(fulfilled_quantity bigint, funding_received_minor_units bigint)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select
    coalesce((
      select sum(quantity) from public.support_item_fulfillments
      where support_item_id = p_support_item_id
        and fulfillment_type in ('purchased', 'in_kind_received', 'distributed')
    ), 0),
    coalesce((
      select sum(da.amount_minor_units)
      from public.donation_allocations da
      join public.donations d on d.id = da.donation_id
      where da.support_item_id = p_support_item_id
        and d.status_code = 'confirmed'
    ), 0);
$$;


--
-- Name: FUNCTION support_item_progress(p_support_item_id uuid); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.support_item_progress(p_support_item_id uuid) IS 'Public-safe aggregate (funded amount + fulfilled quantity) for one support item. Returns only the two numbers, never raw donation/donor rows, so it is safe to grant to anon.';


--
-- Name: sync_registration_fee_paid(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.sync_registration_fee_paid() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  update public.training_registrations
  set fee_paid = (new.status_code in ('paid', 'waived'))
  where id = new.training_registration_id;
  return new;
end;
$$;


--
-- Name: FUNCTION sync_registration_fee_paid(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.sync_registration_fee_paid() IS 'Keeps training_registrations.fee_paid as a maintained cache of the latest payment_records entry, so current_user_is_trainee_for(), get-certificate.ts and every portal that only reads the boolean keep working unchanged while payment_records becomes the actual source of truth going forward.';


--
-- Name: trainee_quiz_attempts(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trainee_quiz_attempts(p_quiz_id uuid) RETURNS TABLE(attempt_number integer, status_code text, started_at timestamp with time zone, submitted_at timestamp with time zone, auto_submitted boolean, score_percent numeric)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select t.attempt_number, t.status_code, t.started_at, t.submitted_at, t.auto_submitted,
         case when public.training_quiz_results_released(t.quiz_id) then t.score_percent end
  from public.training_quiz_attempts t
  where t.quiz_id = p_quiz_id and public.current_user_owns_training_registration(t.training_registration_id)
  order by t.attempt_number;
$$;


--
-- Name: trainee_training_academic_plans(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trainee_training_academic_plans(p_training_id uuid) RETURNS TABLE(academic_plan_id uuid, version integer, status_code text, learning_outcomes text, syllabus text, passing_total_percent numeric, assessment_id uuid, assessment_type text, assessment_title text, assessment_description text, weight_percent numeric, passing_percent numeric, sort_order integer)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select p.id, p.version, p.status_code, p.learning_outcomes, p.syllabus, p.passing_total_percent,
         a.id, a.assessment_type, a.title, a.description, a.weight_percent, a.passing_percent, a.sort_order
  from public.training_academic_plans p
  left join public.training_assessments a on a.academic_plan_id = p.id
  where p.training_id = p_training_id
    and p.status_code in ('approved', 'superseded')
    and exists (
      select 1 from public.training_registrations r
      where r.training_id = p.training_id
        and public.current_user_owns_training_registration(r.id)
    )
  order by p.version desc, a.sort_order, a.created_at;
$$;


--
-- Name: FUNCTION trainee_training_academic_plans(p_training_id uuid); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.trainee_training_academic_plans(p_training_id uuid) IS 'Approved/superseded academic plan versions and their assessments for a training the caller owns a registration on. Column-limited: no decision notes or submitter/decider ids. Empty for anyone without a registration on that training.';


--
-- Name: trainee_training_quizzes(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trainee_training_quizzes(p_training_id uuid) RETURNS TABLE(quiz_id uuid, title text, instructions text, opens_at timestamp with time zone, closes_at timestamp with time zone, duration_minutes integer, attempt_limit integer, status_code text, question_count integer, has_access boolean, attempts_used integer, in_progress_attempt_id uuid, in_progress_due_at timestamp with time zone, awaiting_marking boolean, results_released boolean, best_score_percent numeric, shuffle_choices boolean, server_now timestamp with time zone)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  with reg as (
    select r.id from public.training_registrations r
    where r.training_id = p_training_id and r.status_code = 'approved' and public.current_user_owns_training_registration(r.id)
    limit 1
  )
  select q.id, q.title, q.instructions, q.opens_at, coalesce(acc.closes_at_override, q.closes_at),
         q.duration_minutes + coalesce(acc.extra_minutes, 0), q.attempt_limit, q.status_code,
         (select count(*) from public.training_quiz_questions qq where qq.quiz_id = q.id
            and not exists (select 1 from public.training_quiz_question_adjustments a where a.quiz_question_id = qq.id))::integer,
         public.current_user_is_trainee_for(p_training_id),
         (select count(*) from public.training_quiz_attempts t where t.quiz_id = q.id and t.training_registration_id = reg.id)::integer,
         (select t.id from public.training_quiz_attempts t where t.quiz_id = q.id and t.training_registration_id = reg.id and t.status_code = 'in_progress' and t.due_at > now() limit 1),
         (select t.due_at from public.training_quiz_attempts t where t.quiz_id = q.id and t.training_registration_id = reg.id and t.status_code = 'in_progress' and t.due_at > now() limit 1),
         exists (select 1 from public.training_quiz_attempts t where t.quiz_id = q.id and t.training_registration_id = reg.id and t.status_code = 'awaiting_manual_marking'),
         public.training_quiz_results_released(q.id),
         case when public.training_quiz_results_released(q.id) then
           coalesce((select o.score_percent from public.training_quiz_grade_overrides o where o.quiz_id = q.id and o.training_registration_id = reg.id),
                    (select max(t.score_percent) from public.training_quiz_attempts t where t.quiz_id = q.id and t.training_registration_id = reg.id and t.status_code in ('submitted', 'expired')))
         end,
         q.shuffle_choices,
         now()
  from reg
  join public.training_quizzes q on q.training_id = p_training_id and q.status_code in ('scheduled', 'closed')
  left join public.training_quiz_accommodations acc on acc.quiz_id = q.id and acc.training_registration_id = reg.id
  order by q.opens_at;
$$;


--
-- Name: trainer_get_trainee_profile(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trainer_get_trainee_profile(p_registration_id uuid) RETURNS TABLE(registration_id uuid, person_id uuid, full_name text, preferred_name text, email public.citext, phone text, preferred_locale text, country text, region text, timezone text, education_employment_context text, learning_interests text, learning_goals text)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public', 'pg_temp'
    AS $$
  select
    registration.id,
    person.id,
    person.full_name,
    person.preferred_name,
    person.email,
    person.phone,
    person.preferred_locale,
    person.country,
    person.region,
    person.timezone,
    person.education_employment_context,
    person.learning_interests,
    person.learning_goals
  from public.training_registrations registration
  join public.people person on person.id = registration.person_id
  where registration.id = p_registration_id
    and (
      public.current_user_is_trainer_for(registration.training_id)
      or public.current_user_has_permission('training.manage')
    );
$$;


--
-- Name: FUNCTION trainer_get_trainee_profile(p_registration_id uuid); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.trainer_get_trainee_profile(p_registration_id uuid) IS 'Returns only learning-relevant and contact profile fields for one registration when the caller is the assigned trainer or a training manager. Internal notes and unrelated people remain inaccessible.';


--
-- Name: training_academic_plans_freeze_decided(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_academic_plans_freeze_decided() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if old.status_code not in ('draft', 'pending_approval')
     and (new.passing_total_percent is distinct from old.passing_total_percent
          or new.syllabus is distinct from old.syllabus
          or new.learning_outcomes is distinct from old.learning_outcomes
          or new.training_id is distinct from old.training_id
          or new.version is distinct from old.version) then
    raise exception 'This plan is % and its terms can no longer change; create a new version instead.', old.status_code using errcode = '42501';
  end if;
  return new;
end;
$$;


--
-- Name: training_academic_plans_guard(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_academic_plans_guard() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_weight numeric;
begin
  if tg_op = 'INSERT' then
    new.submitted_by := coalesce(auth.uid(), new.submitted_by);
    new.submitted_at := case when new.status_code = 'pending_approval' then now() else null end;
  elsif new.status_code = 'pending_approval' and old.status_code = 'draft' then
    new.submitted_by := coalesce(auth.uid(), new.submitted_by);
    new.submitted_at := now();
  elsif not public.current_user_can_manage_trainings() then
    new.submitted_by := old.submitted_by;
    new.submitted_at := old.submitted_at;
  end if;

  if new.status_code = 'approved' and (tg_op = 'INSERT' or old.status_code <> 'approved') then
    select coalesce(sum(weight_percent), 0) into v_weight from public.training_assessments where academic_plan_id = new.id;
    if v_weight <> 100 then
      raise exception 'Assessment weights must total exactly 100%% (currently %).', v_weight || '%' using errcode = '22023';
    end if;
  end if;
  return new;
end;
$$;


--
-- Name: training_assessment_is_task_linked(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_assessment_is_task_linked(p_assessment_id uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (select 1 from public.training_assignments where assessment_id = p_assessment_id and is_published);
$$;


--
-- Name: training_assessments_freeze_decided(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_assessments_freeze_decided() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_status text;
begin
  select status_code into v_status from public.training_academic_plans
  where id = case when tg_op = 'DELETE' then old.academic_plan_id else new.academic_plan_id end;
  -- A plan being deleted cascades here after its row is gone: allow that.
  if v_status is not null and v_status not in ('draft', 'pending_approval') then
    raise exception 'This plan is % and its assessments can no longer change; create a new version instead.', v_status using errcode = '42501';
  end if;
  if tg_op = 'UPDATE' and new.academic_plan_id <> old.academic_plan_id then
    select status_code into v_status from public.training_academic_plans where id = old.academic_plan_id;
    if v_status is not null and v_status not in ('draft', 'pending_approval') then
      raise exception 'Assessments of a % plan cannot be moved.', v_status using errcode = '42501';
    end if;
  end if;
  return case when tg_op = 'DELETE' then old else new end;
end;
$$;


--
-- Name: training_capacity_summary(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_capacity_summary(p_training_id uuid) RETURNS TABLE(capacity integer, approved_count bigint, offered_count bigint, waitlist_count bigint)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select
    t.capacity,
    (select count(*) from public.training_registrations where training_id = p_training_id and status_code = 'approved'),
    (select count(*) from public.training_waitlist_entries where training_id = p_training_id and status_code = 'offered'),
    (select count(*) from public.training_waitlist_entries where training_id = p_training_id and status_code = 'active')
  from public.trainings t where t.id = p_training_id;
$$;


--
-- Name: training_certificate_final_grade_eligible(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_certificate_final_grade_eligible(p_registration_id uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select not exists (
    select 1 from public.training_registrations r
    join public.training_academic_plans p on p.training_id = r.training_id and p.status_code = 'approved'
    where r.id = p_registration_id
  ) or exists (
    select 1 from public.training_final_grades fg
    join public.training_registrations r on r.id = fg.training_registration_id
    join public.training_academic_plans p on p.id = fg.academic_plan_id
    where fg.training_registration_id = p_registration_id
      and fg.status_code = 'approved'
      and p.training_id = r.training_id
      and p.status_code = 'approved'
      and fg.total_percent >= p.passing_total_percent
  );
$$;


--
-- Name: FUNCTION training_certificate_final_grade_eligible(p_registration_id uuid); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.training_certificate_final_grade_eligible(p_registration_id uuid) IS 'For an academic-plan training, requires an approved final grade meeting that plan''s passing_total_percent. Legacy courses without a plan remain eligible under their existing rules.';


--
-- Name: training_charge_has_pending_or_accepted_proof_submission(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_charge_has_pending_or_accepted_proof_submission(p_training_charge_id uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (
    select 1 from public.training_fee_proof_submissions
    where training_charge_id = p_training_charge_id and status_code in ('submitted', 'accepted')
  );
$$;


--
-- Name: training_completion_eligibility(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_completion_eligibility(p_registration_id uuid) RETURNS jsonb
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  v_training_id uuid;
  v_can_read boolean;
  v_min_attendance_percent integer;
  v_require_assignments boolean;
  v_require_passing_grade boolean;
  v_require_financial_clearance boolean;
  v_require_manager_approval boolean;
  v_sessions_total integer;
  v_attendance record;
  v_attendance_missing integer;
  v_assignments_total integer;
  v_assignments_graded integer;
  v_assignments_passing integer;
  v_clearance_state text;
  v_current_status text;
  v_reasons text[] := '{}';
  v_attendance_percent numeric;
  v_final_grade_ok boolean;
  v_final_total numeric;
  v_pass_mark numeric;
begin
  select tr.training_id, tr.completion_status_code into v_training_id, v_current_status
  from public.training_registrations tr where tr.id = p_registration_id;

  if v_training_id is null then
    raise exception 'Registration not found.' using errcode = '42501';
  end if;

  select (
    public.current_user_owns_training_registration(p_registration_id)
    or public.current_user_is_trainer_for(v_training_id)
    or public.current_user_has_permission('training.manage')
    or public.current_user_has_permission('training.read')
  ) into v_can_read;
  if not v_can_read then
    raise exception 'Not authorized to view this registration''s completion status.' using errcode = '42501';
  end if;

  select min_attendance_percent, require_assignments, require_passing_grade,
         require_financial_clearance, require_manager_approval
  into v_min_attendance_percent, v_require_assignments, v_require_passing_grade,
       v_require_financial_clearance, v_require_manager_approval
  from public.training_completion_rules where training_id = v_training_id;

  -- No row = documented default baseline: only financial clearance.
  -- "select ... into" leaves every target variable null (not found),
  -- rather than raising, when zero rows match - explicit defaults here.
  if not found then
    v_min_attendance_percent := null;
    v_require_assignments := false;
    v_require_passing_grade := false;
    v_require_financial_clearance := true;
    v_require_manager_approval := false;
  end if;

  -- An approved academic plan replaces the old per-assignment pass/fail
  -- checks: its weighted, manager-approved final grade decides instead.
  if exists (select 1 from public.training_academic_plans where training_id = v_training_id and status_code = 'approved') then
    v_require_assignments := false;
    v_require_passing_grade := false;
  end if;

  -- Denominator is every session scheduled for this training, not just
  -- the ones somebody happened to record attendance for - a session
  -- with no attendance row is missing data, not an implicit 0 or 100.
  select count(*) into v_sessions_total
  from public.training_sessions where training_id = v_training_id;

  select
    count(*) filter (where attendance_status = 'present') as present,
    count(*) as recorded
  into v_attendance
  from public.training_attendance ta
  join public.training_sessions ts on ts.id = ta.training_session_id
  where ta.training_registration_id = p_registration_id and ts.training_id = v_training_id;

  v_attendance_missing := greatest(v_sessions_total - coalesce(v_attendance.recorded, 0), 0);
  v_attendance_percent := case when v_sessions_total > 0
    then round((coalesce(v_attendance.present, 0)::numeric / v_sessions_total) * 100)
    else null end;

  if v_min_attendance_percent is not null then
    if v_sessions_total = 0 then
      v_reasons := array_append(v_reasons, 'No sessions are scheduled yet, so attendance cannot be verified.');
    elsif v_attendance_missing > 0 then
      v_reasons := array_append(v_reasons, format(
        'Attendance has not been recorded for %s of %s session(s) yet.',
        v_attendance_missing, v_sessions_total
      ));
    elsif v_attendance_percent < v_min_attendance_percent then
      v_reasons := array_append(v_reasons, format(
        'Attendance is %s%% (%s of %s sessions), below the required %s%%.',
        v_attendance_percent, coalesce(v_attendance.present, 0), v_sessions_total, v_min_attendance_percent
      ));
    end if;
  end if;

  select count(*) into v_assignments_total
  from public.training_assignments ta where ta.training_id = v_training_id and ta.is_published;

  select
    count(*) filter (where s.status_code = 'graded') as graded,
    count(*) filter (where s.status_code = 'graded' and s.is_passing) as passing
  into v_assignments_graded, v_assignments_passing
  from public.training_assignments ta
  left join public.training_submissions s
    on s.training_assignment_id = ta.id and s.training_registration_id = p_registration_id
  where ta.training_id = v_training_id and ta.is_published;

  if v_require_assignments and v_assignments_total > coalesce(v_assignments_graded, 0) then
    v_reasons := array_append(v_reasons, format(
      '%s of %s required assignments are not yet graded.',
      v_assignments_total - coalesce(v_assignments_graded, 0), v_assignments_total
    ));
  end if;

  if v_require_passing_grade and v_assignments_total > coalesce(v_assignments_passing, 0) then
    v_reasons := array_append(v_reasons, format(
      '%s of %s required assignments do not have a passing grade yet.',
      v_assignments_total - coalesce(v_assignments_passing, 0), v_assignments_total
    ));
  end if;

  select clearance_state into v_clearance_state
  from public.training_registration_clearance where registration_id = p_registration_id;

  if v_require_financial_clearance and coalesce(v_clearance_state, 'due') not in ('not_required', 'cleared', 'waived') then
    v_reasons := array_append(v_reasons, format('Financial clearance is not settled yet (currently "%s").', coalesce(v_clearance_state, 'due')));
  end if;

  -- Academic-plan courses: a DIFFERENT training manager must have approved
  -- the final grade (training_certificate_final_grade_eligible). Legacy
  -- courses with no approved academic plan are unaffected.
  v_final_grade_ok := public.training_certificate_final_grade_eligible(p_registration_id);
  if not v_final_grade_ok then
    select fg.total_percent, p.passing_total_percent into v_final_total, v_pass_mark
    from public.training_final_grades fg
    join public.training_academic_plans p on p.id = fg.academic_plan_id and p.status_code = 'approved' and p.training_id = v_training_id
    where fg.training_registration_id = p_registration_id and fg.status_code = 'approved';
    if v_final_total is not null then
      v_reasons := array_append(v_reasons, format('Final grade %s%% is below the pass mark of %s%%.', v_final_total, v_pass_mark));
    else
      v_reasons := array_append(v_reasons, 'The final grade has not been approved by a training manager yet.');
    end if;
  end if;

  return jsonb_build_object(
    'is_eligible', array_length(v_reasons, 1) is null,
    'reasons', to_jsonb(v_reasons),
    'current_status', v_current_status,
    'attendance_percent', v_attendance_percent,
    'attendance_present', coalesce(v_attendance.present, 0),
    'attendance_sessions_total', v_sessions_total,
    'attendance_recorded', coalesce(v_attendance.recorded, 0),
    'attendance_missing', v_attendance_missing,
    'min_attendance_percent', v_min_attendance_percent,
    'require_assignments', v_require_assignments,
    'require_passing_grade', v_require_passing_grade,
    'assignments_total', v_assignments_total,
    'assignments_graded', coalesce(v_assignments_graded, 0),
    'assignments_passing', coalesce(v_assignments_passing, 0),
    'require_financial_clearance', v_require_financial_clearance,
    'clearance_state', v_clearance_state,
    'require_manager_approval', v_require_manager_approval,
    'final_grade_approved', v_final_grade_ok
  );
end;
$$;


--
-- Name: FUNCTION training_completion_eligibility(p_registration_id uuid); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.training_completion_eligibility(p_registration_id uuid) IS 'Read-only: attendance % (against every SCHEDULED session, missing records block the check with their own reason rather than defaulting either way), required-assignment/passing-grade counts, and financial clearance against training_completion_rules (or the documented default if no row exists). Callable by the trainee themselves, the assigned trainer, or training.read/manage. Never mutates anything, safe to call just to render progress.';


--
-- Name: training_decide_access_exception(uuid, text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_decide_access_exception(p_exception_id uuid, p_decision text, p_note text DEFAULT NULL::text) RETURNS public.training_fee_access_exceptions
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  exception_row public.training_fee_access_exceptions;
begin
  if not public.current_user_has_permission('training.manage') then
    raise exception 'Only a training manager can confirm or reject deferred-payment access.' using errcode = '42501';
  end if;
  if not public.current_user_aal2() then
    raise exception 'Confirming or rejecting deferred-payment access requires a step-up (AAL2) session.' using errcode = '42501';
  end if;
  if p_decision not in ('confirm', 'reject') then
    raise exception 'decision must be ''confirm'' or ''reject''.' using errcode = '22023';
  end if;
  if p_decision = 'reject' and coalesce(length(btrim(p_note)), 0) < 3 then
    raise exception 'A rejection reason of at least three characters is required.' using errcode = '22023';
  end if;

  select * into exception_row from public.training_fee_access_exceptions where id = p_exception_id for update;
  if exception_row.id is null then
    raise exception 'Deferred-access request not found.' using errcode = '22023';
  end if;
  if exception_row.status_code <> 'pending' then
    raise exception 'This request has already been decided or withdrawn.' using errcode = '22023';
  end if;
  if exception_row.requested_by = auth.uid() then
    raise exception 'You cannot confirm a request you made yourself - another training manager must decide it.' using errcode = '42501';
  end if;
  if p_decision = 'confirm' then
    if exception_row.expires_at is not null and exception_row.expires_at <= now() then
      raise exception 'This request''s expiry date has already passed; finance must submit a new request.' using errcode = '22023';
    end if;
    if not exists (select 1 from public.training_registrations where id = exception_row.training_registration_id and status_code = 'approved') then
      raise exception 'The registration is no longer approved.' using errcode = '22023';
    end if;
  end if;

  update public.training_fee_access_exceptions
  set status_code = case when p_decision = 'confirm' then 'active' else 'rejected' end,
      decided_by = auth.uid(),
      decided_at = now(),
      decision_note = nullif(btrim(coalesce(p_note, '')), '')
  where id = p_exception_id
  returning * into exception_row;
  return exception_row;
end;
$$;


--
-- Name: training_final_grade_after_return(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_final_grade_after_return() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if new.status_code = 'rejected' and old.status_code is distinct from 'rejected' then
    perform public.training_task_export_registration(new.training_registration_id);
  end if;
  return null;
end;
$$;


--
-- Name: training_final_grade_locked(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_final_grade_locked(p_registration_id uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (select 1 from public.training_final_grades
                 where training_registration_id = p_registration_id and status_code in ('submitted', 'approved'));
$$;


--
-- Name: training_grade_context_valid(uuid, uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_grade_context_valid(p_registration_id uuid, p_assessment_id uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (
    select 1 from public.training_registrations r
    join public.training_academic_plans p on p.training_id = r.training_id and p.status_code = 'approved'
    join public.training_assessments a on a.id = p_assessment_id and a.academic_plan_id = p.id
    where r.id = p_registration_id
  );
$$;


--
-- Name: training_pending_access_exceptions(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_pending_access_exceptions() RETURNS TABLE(exception_id uuid, training_registration_id uuid, full_name text, email text, training_title text, fee_amount_minor_units bigint, fee_currency_code text, reason text, expires_at timestamp with time zone, requested_by uuid, requested_at timestamp with time zone)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select
    exception.id,
    registration.id,
    registration.full_name::text,
    registration.email::text,
    coalesce(translation.title, training.slug)::text,
    training.fee_amount_minor_units::bigint,
    training.fee_currency_code::text,
    exception.reason,
    exception.expires_at,
    exception.requested_by,
    exception.requested_at
  from public.training_fee_access_exceptions exception
  join public.training_registrations registration on registration.id = exception.training_registration_id
  join public.trainings training on training.id = registration.training_id
  left join public.training_translations translation on translation.training_id = training.id and translation.locale = 'en'
  where exception.status_code = 'pending'
    and public.current_user_has_permission('training.manage')
  order by exception.requested_at;
$$;


--
-- Name: training_quiz_attempt_questions(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_quiz_attempt_questions(p_attempt_id uuid) RETURNS TABLE(id uuid, question_type text, prompt text, choices jsonb, points numeric, sort_order integer, response jsonb)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select q.id, q.question_type, q.prompt, q.choices, q.points, q.sort_order, a.response
  from public.training_quiz_attempts attempt
  join public.training_quiz_questions q on q.quiz_id = attempt.quiz_id
  left join public.training_quiz_answers a on a.quiz_attempt_id = attempt.id and a.quiz_question_id = q.id
  where attempt.id = p_attempt_id and attempt.status_code = 'in_progress'
    and public.current_user_owns_training_registration(attempt.training_registration_id)
  order by case when (select shuffle_questions from public.training_quizzes where id = attempt.quiz_id) then md5(attempt.id::text || q.id::text) else lpad(q.sort_order::text, 12, '0') end;
$$;


--
-- Name: training_quiz_attempt_score(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_quiz_attempt_score(p_attempt_id uuid) RETURNS TABLE(score_points numeric, total_points numeric, score_percent numeric, unmarked_essays integer)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  with counted as (
    select question.id, question.points, question.question_type
    from public.training_quiz_attempts attempt
    join public.training_quiz_questions question on question.quiz_id = attempt.quiz_id
    where attempt.id = p_attempt_id
      and not exists (select 1 from public.training_quiz_question_adjustments adj
                      where adj.quiz_question_id = question.id and adj.adjustment_type = 'cancelled')
  )
  select coalesce(sum(answer.awarded_points), 0),
         coalesce(sum(counted.points), 0),
         case when coalesce(sum(counted.points), 0) = 0 then 0
              else round(coalesce(sum(answer.awarded_points), 0) * 100 / sum(counted.points), 2) end,
         (count(*) filter (where counted.question_type = 'essay' and answer.awarded_points is null))::integer
  from counted
  left join public.training_quiz_answers answer on answer.quiz_attempt_id = p_attempt_id and answer.quiz_question_id = counted.id;
$$;


--
-- Name: training_quiz_export_best(uuid, uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_quiz_export_best(p_quiz_id uuid, p_registration_id uuid) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_quiz public.training_quizzes; v_best numeric;
begin
  select * into v_quiz from public.training_quizzes where id = p_quiz_id;
  select max(score_percent) into v_best from public.training_quiz_attempts
  where quiz_id = p_quiz_id and training_registration_id = p_registration_id
    and status_code in ('submitted', 'expired') and score_percent is not null;
  if v_quiz.id is null or v_best is null
     or exists (select 1 from public.training_quiz_grade_overrides where quiz_id = p_quiz_id and training_registration_id = p_registration_id)
     or public.training_final_grade_locked(p_registration_id)
     or not public.training_grade_context_valid(p_registration_id, v_quiz.assessment_id)
     or not exists (select 1 from public.training_registrations where id = p_registration_id and status_code = 'approved') then
    return;
  end if;
  perform set_config('app.training_quiz_autograde', 'on', true);
  perform set_config('app.training_quiz_autograde_by', v_quiz.created_by::text, true);
  insert into public.training_assessment_grades (training_registration_id, assessment_id, score_percent, feedback)
  values (p_registration_id, v_quiz.assessment_id, v_best, 'Automatically graded quiz (highest attempt)')
  on conflict (training_registration_id, assessment_id) do update set score_percent = excluded.score_percent, feedback = excluded.feedback;
  perform set_config('app.training_quiz_autograde', 'off', true);
end;
$$;


--
-- Name: training_quiz_finish_attempt(uuid, boolean); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_quiz_finish_attempt(p_attempt_id uuid, p_expired boolean) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_attempt public.training_quiz_attempts; v_score record;
begin
  select * into v_attempt from public.training_quiz_attempts where id = p_attempt_id for update;
  if v_attempt.status_code <> 'in_progress' then return; end if;
  select * into v_score from public.training_quiz_attempt_score(p_attempt_id);
  if v_score.unmarked_essays > 0 then
    update public.training_quiz_attempts
    set status_code = 'awaiting_manual_marking', submitted_at = now(), auto_submitted = p_expired, manual_marking_required = true
    where id = p_attempt_id;
    return;
  end if;
  update public.training_quiz_attempts
  set status_code = case when p_expired then 'expired' else 'submitted' end, submitted_at = now(), auto_submitted = p_expired,
      score_points = v_score.score_points, score_percent = v_score.score_percent
  where id = p_attempt_id;
  perform public.training_quiz_export_best(v_attempt.quiz_id, v_attempt.training_registration_id);
end;
$$;


--
-- Name: training_quiz_guard(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_quiz_guard() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_plan_id uuid; v_check_plan boolean;
begin
  if not (public.current_user_is_trainer_for(new.training_id) or public.current_user_can_manage_trainings()) then
    raise exception 'Only the assigned trainer or training manager may manage this quiz.' using errcode = '42501';
  end if;
  -- The plan link is checked when a quiz is created, re-pointed or
  -- scheduled - not on every update, so a quiz from a plan that has since
  -- been superseded can still be closed or cancelled.
  if tg_op = 'INSERT' then
    v_check_plan := true;
  else
    v_check_plan := new.assessment_id is distinct from old.assessment_id
      or (new.status_code = 'scheduled' and old.status_code is distinct from 'scheduled');
  end if;
  if v_check_plan then
    select id into v_plan_id from public.training_academic_plans where training_id = new.training_id and status_code = 'approved';
    if v_plan_id is null or not exists (select 1 from public.training_assessments where id = new.assessment_id and academic_plan_id = v_plan_id and assessment_type = 'quiz') then
      raise exception 'A quiz must be linked to a Quiz assessment in this training''s approved academic plan.' using errcode = '23514';
    end if;
  end if;
  if tg_op = 'UPDATE' and old.status_code in ('scheduled', 'closed', 'cancelled') then
    -- A scheduled quiz may be safely closed or cancelled, but no content,
    -- timing or assessment detail may change. updated_at is ignored because
    -- its normal trigger runs before this guard.
    if not (old.status_code = 'scheduled'
      and new.status_code in ('closed', 'cancelled')
      and (to_jsonb(new) - 'updated_at' - 'status_code') = (to_jsonb(old) - 'updated_at' - 'status_code')) then
      raise exception 'A scheduled, closed or cancelled quiz cannot be changed. Create a new plan version and quiz instead.' using errcode = '42501';
    end if;
  end if;
  if new.status_code = 'scheduled' and not exists (select 1 from public.training_quiz_questions where quiz_id = new.id) then
    raise exception 'Add at least one question before scheduling a quiz.' using errcode = '23514';
  end if;
  return new;
end;
$$;


--
-- Name: training_quiz_numeric_value(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_quiz_numeric_value(p_value text) RETURNS numeric
    LANGUAGE plpgsql IMMUTABLE
    SET search_path TO 'public'
    AS $_$
declare v_normalized text;
begin
  v_normalized := regexp_replace(
    translate(btrim(coalesce(p_value, '')), '٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹٫,', '01234567890123456789..'),
    '\s', '', 'g'
  );
  if v_normalized !~ '^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)$' then return null; end if;
  return v_normalized::numeric;
exception when others then
  return null;
end;
$_$;


--
-- Name: training_quiz_question_guard(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_quiz_question_guard() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_quiz_status text; v_training_id uuid;
begin
  select status_code, training_id into v_quiz_status, v_training_id from public.training_quizzes
    where id = coalesce(new.quiz_id, old.quiz_id);
  -- During ON DELETE CASCADE from a quiz, its parent is already gone. Let
  -- PostgreSQL remove the immutable question snapshots with that quiz.
  if tg_op = 'DELETE' and v_quiz_status is null then return old; end if;
  if not (public.current_user_is_trainer_for(v_training_id) or public.current_user_can_manage_trainings()) then
    raise exception 'Only the assigned trainer or training manager may manage quiz questions.' using errcode = '42501';
  end if;
  if v_quiz_status <> 'draft' then raise exception 'Quiz questions are locked once the quiz is scheduled.' using errcode = '42501'; end if;
  if tg_op = 'DELETE' then return old; end if;
  return new;
end;
$$;


--
-- Name: training_quiz_rescore_attempt(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_quiz_rescore_attempt(p_attempt_id uuid) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_attempt public.training_quiz_attempts; v_score record;
begin
  select * into v_attempt from public.training_quiz_attempts where id = p_attempt_id for update;
  if v_attempt.status_code not in ('submitted', 'expired', 'awaiting_manual_marking') then return; end if;
  select * into v_score from public.training_quiz_attempt_score(p_attempt_id);
  if v_score.unmarked_essays > 0 then return; end if;
  update public.training_quiz_attempts
  set status_code = case when status_code = 'awaiting_manual_marking' then (case when auto_submitted then 'expired' else 'submitted' end) else status_code end,
      score_points = v_score.score_points, score_percent = v_score.score_percent
  where id = p_attempt_id;
  perform public.training_quiz_export_best(v_attempt.quiz_id, v_attempt.training_registration_id);
end;
$$;


--
-- Name: training_quiz_results_released(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_quiz_results_released(p_quiz_id uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select coalesce((
    select now() >= coalesce(q.results_visible_at, q.closes_at)
        or (q.status_code = 'closed' and not exists (
              select 1 from public.training_quiz_attempts a
              where a.quiz_id = q.id and a.status_code = 'in_progress' and a.due_at > now()))
    from public.training_quizzes q where q.id = p_quiz_id), false);
$$;


--
-- Name: training_quizzes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_quizzes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_id uuid NOT NULL,
    assessment_id uuid NOT NULL,
    title text NOT NULL,
    instructions text,
    opens_at timestamp with time zone NOT NULL,
    closes_at timestamp with time zone NOT NULL,
    duration_minutes integer NOT NULL,
    grace_minutes integer DEFAULT 2 NOT NULL,
    attempt_limit integer DEFAULT 1 NOT NULL,
    grade_rule text DEFAULT 'highest'::text NOT NULL,
    shuffle_questions boolean DEFAULT false NOT NULL,
    shuffle_choices boolean DEFAULT false NOT NULL,
    results_visible_at timestamp with time zone,
    status_code text DEFAULT 'draft'::text NOT NULL,
    created_by uuid DEFAULT auth.uid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT training_quizzes_attempt_limit_check CHECK (((attempt_limit >= 1) AND (attempt_limit <= 10))),
    CONSTRAINT training_quizzes_check CHECK ((closes_at > opens_at)),
    CONSTRAINT training_quizzes_check1 CHECK (((results_visible_at IS NULL) OR (results_visible_at >= closes_at))),
    CONSTRAINT training_quizzes_duration_minutes_check CHECK (((duration_minutes >= 1) AND (duration_minutes <= 1440))),
    CONSTRAINT training_quizzes_grace_minutes_check CHECK (((grace_minutes >= 0) AND (grace_minutes <= 30))),
    CONSTRAINT training_quizzes_grade_rule_check CHECK ((grade_rule = 'highest'::text)),
    CONSTRAINT training_quizzes_status_code_check CHECK ((status_code = ANY (ARRAY['draft'::text, 'scheduled'::text, 'closed'::text, 'cancelled'::text]))),
    CONSTRAINT training_quizzes_title_check CHECK (((length(btrim(title)) >= 1) AND (length(btrim(title)) <= 160)))
);


--
-- Name: training_quiz_staff_check(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_quiz_staff_check(p_quiz_id uuid) RETURNS public.training_quizzes
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_quiz public.training_quizzes;
begin
  select * into v_quiz from public.training_quizzes where id = p_quiz_id;
  if v_quiz.id is null or not (public.current_user_is_trainer_for(v_quiz.training_id) or public.current_user_can_manage_trainings()) then
    raise exception 'Only the assigned trainer or a training manager may do this.' using errcode = '42501';
  end if;
  return v_quiz;
end;
$$;


--
-- Name: training_registration_prerequisites_met(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_registration_prerequisites_met(p_training_registration_id uuid) RETURNS boolean
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  v_registration record;
begin
  select training_id, person_id into v_registration
    from public.training_registrations where id = p_training_registration_id;
  if v_registration.training_id is null then
    return false;
  end if;
  return not exists (
    select 1 from public.training_prerequisites tp
    where tp.training_id = v_registration.training_id and tp.active and tp.required
      and not (
        (tp.auto_verifiable and tp.requirement_type = 'course' and tp.source_training_id is not null
          and v_registration.person_id is not null
          and exists (
            select 1 from public.training_registrations tr
            where tr.training_id = tp.source_training_id
              and tr.person_id = v_registration.person_id
              and tr.completion_status_code = 'completed'
          ))
        or
        (not tp.auto_verifiable and exists (
          select 1 from public.training_prerequisite_decisions tpd
          where tpd.training_registration_id = p_training_registration_id
            and tpd.prerequisite_id = tp.id
            and tpd.decision_code in ('met', 'waived')
        ))
      )
  );
end;
$$;


--
-- Name: training_slug_part(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_slug_part(p_title text) RETURNS text
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'public'
    AS $$
  select coalesce(
    nullif(
      trim(both '-' from regexp_replace(lower(btrim(coalesce(p_title, ''))), '[^a-z0-9]+', '-', 'g')),
      ''
    ),
    'training'
  );
$$;


--
-- Name: training_task_after_change(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_task_after_change() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if tg_op in ('UPDATE', 'DELETE') then perform public.training_task_export_all(old.assessment_id); end if;
  if tg_op in ('INSERT', 'UPDATE') and new.assessment_id is distinct from (case when tg_op = 'UPDATE' then old.assessment_id end) then
    perform public.training_task_export_all(new.assessment_id);
  end if;
  return null;
end;
$$;


--
-- Name: training_task_export_all(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_task_export_all(p_assessment_id uuid) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_registration uuid;
begin
  if p_assessment_id is null then return; end if;
  for v_registration in
    select r.id from public.training_registrations r
    join public.training_academic_plans p on p.training_id = r.training_id
    join public.training_assessments a on a.academic_plan_id = p.id and a.id = p_assessment_id
    where r.status_code = 'approved'
  loop
    perform public.training_task_export_assessment(p_assessment_id, v_registration);
  end loop;
end;
$$;


--
-- Name: training_task_export_assessment(uuid, uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_task_export_assessment(p_assessment_id uuid, p_registration_id uuid) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_training uuid; v_tasks integer; v_marked integer; v_earned numeric; v_max numeric; v_by uuid;
begin
  select training_id into v_training from public.training_registrations where id = p_registration_id and status_code = 'approved';
  if v_training is null or p_assessment_id is null
     or not public.training_grade_context_valid(p_registration_id, p_assessment_id)
     or public.training_final_grade_locked(p_registration_id)
     or exists (select 1 from public.training_task_assessment_overrides where assessment_id = p_assessment_id and training_registration_id = p_registration_id) then
    return;
  end if;
  select count(*), count(m.id),
         coalesce(sum(m.marks_earned) filter (where m.status_code in ('marked', 'missing')), 0),
         coalesce(sum(t.max_marks) filter (where m.status_code in ('marked', 'missing')), 0),
         (array_agg(t.created_by) filter (where t.created_by is not null))[1]
  into v_tasks, v_marked, v_earned, v_max, v_by
  from public.training_assignments t
  left join public.training_task_marks m on m.training_assignment_id = t.id and m.training_registration_id = p_registration_id
  where t.assessment_id = p_assessment_id and t.training_id = v_training and t.is_published;
  if v_tasks = 0 then return; end if;

  begin
    perform set_config('app.training_task_export', 'on', true);
    perform set_config('app.training_task_export_by', coalesce(coalesce(auth.uid(), v_by)::text, ''), true);
    if v_marked < v_tasks or v_max = 0 then
      delete from public.training_assessment_grades where training_registration_id = p_registration_id and assessment_id = p_assessment_id;
    else
      insert into public.training_assessment_grades (training_registration_id, assessment_id, score_percent, feedback)
      values (p_registration_id, p_assessment_id, least(round(v_earned * 100 / v_max, 2), 100),
              format('Calculated from %s linked task(s): %s of %s marks', v_tasks, trim_scale(v_earned), trim_scale(v_max)))
      on conflict (training_registration_id, assessment_id) do update set score_percent = excluded.score_percent, feedback = excluded.feedback
      where training_assessment_grades.score_percent is distinct from excluded.score_percent
         or training_assessment_grades.feedback is distinct from excluded.feedback;
    end if;
    perform set_config('app.training_task_export', 'off', true);
  exception when others then
    perform set_config('app.training_task_export', 'off', true);
    raise warning 'Gradebook export skipped for assessment % / registration %: %', p_assessment_id, p_registration_id, sqlerrm;
  end;
end;
$$;


--
-- Name: training_task_export_registration(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_task_export_registration(p_registration_id uuid) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare v_assessment uuid;
begin
  for v_assessment in
    select distinct t.assessment_id from public.training_assignments t
    join public.training_registrations r on r.training_id = t.training_id and r.id = p_registration_id
    where t.assessment_id is not null and t.is_published
  loop
    perform public.training_task_export_assessment(v_assessment, p_registration_id);
  end loop;
end;
$$;


--
-- Name: training_task_is_published(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.training_task_is_published(p_assignment_id uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select coalesce((select is_published from public.training_assignments where id = p_assignment_id), false);
$$;


--
-- Name: user_in_recovery_hold(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.user_in_recovery_hold(p_user_id uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (
    select 1 from public.security_events recovered
    where recovered.subject_user_id = p_user_id
      and recovered.event_type = 'mfa_recovery_started'
      and recovered.created_at > now() - interval '24 hours'
      and not exists (
        select 1 from public.security_events released
        where released.subject_user_id = recovered.subject_user_id
          and released.event_type = 'recovery_hold_released'
          and released.created_at > recovered.created_at
      )
  );
$$;


--
-- Name: validate_role_assignment_scope(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.validate_role_assignment_scope() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  role_supports_scope boolean;
begin
  if (new.scope_type is null) <> (new.scope_id is null) then
    raise exception 'scope_type and scope_id must both be null or both be set.';
  end if;

  if new.scope_type is null then
    return new;
  end if;

  select supports_scope into role_supports_scope from public.roles where code = new.role_code;
  if not coalesce(role_supports_scope, false) then
    raise exception 'Role % cannot be scoped.', new.role_code;
  end if;

  if new.scope_type = 'program' and not exists (select 1 from public.programs where id = new.scope_id) then
    raise exception 'Unknown program scope: %', new.scope_id;
  elsif new.scope_type = 'initiative' and not exists (select 1 from public.initiatives where id = new.scope_id) then
    raise exception 'Unknown initiative scope: %', new.scope_id;
  elsif new.scope_type not in ('program', 'initiative') then
    raise exception 'Unsupported scope type: %', new.scope_type;
  end if;

  return new;
end;
$$;


--
-- Name: verify_certificate(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.verify_certificate(p_verification_token uuid) RETURNS TABLE(certificate_number text, trainee_name text, training_title text, issued_at timestamp with time zone, starts_on date, ends_on date, is_valid boolean)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select
    tc.certificate_number,
    tr.full_name,
    coalesce(tt.title, 'Training'),
    tc.issued_at,
    t.starts_on,
    t.ends_on,
    (tc.revoked_at is null)
  from public.training_certificates tc
  join public.training_registrations tr on tr.id = tc.training_registration_id
  join public.trainings t on t.id = tr.training_id
  left join public.training_translations tt on tt.training_id = t.id and tt.locale = 'en'
  where tc.verification_token = p_verification_token;
$$;


--
-- Name: FUNCTION verify_certificate(p_verification_token uuid); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.verify_certificate(p_verification_token uuid) IS 'Public-safe certificate lookup by verification_token only (never by certificate_number or id, both of which are either guessable or an internal key). Returns zero rows for an unknown or mistyped token - never an error that would distinguish "wrong token" from "revoked".';


--
-- Name: app_modules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.app_modules (
    code text NOT NULL,
    label text NOT NULL,
    nav_group text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    read_permission_code text NOT NULL,
    manage_permission_code text NOT NULL,
    is_navigation boolean DEFAULT true NOT NULL,
    is_active boolean DEFAULT true NOT NULL
);


--
-- Name: TABLE app_modules; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.app_modules IS 'Single source of truth for dashboard visibility. RLS remains the security boundary; this registry prevents role/tab drift in the UI.';


--
-- Name: assessment_instruments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.assessment_instruments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    code text NOT NULL,
    domain text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: assessment_scores; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.assessment_scores (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    assessment_session_id uuid NOT NULL,
    participant_code text NOT NULL,
    score numeric,
    completed boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE assessment_scores; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.assessment_scores IS 'participant_code is a pseudonym, never a name — the identity behind it lives only in restricted.beneficiary_records.';


--
-- Name: assessment_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.assessment_sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    instrument_version_id uuid NOT NULL,
    cohort_id uuid,
    session_type text NOT NULL,
    administered_on date DEFAULT CURRENT_DATE NOT NULL,
    administered_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT assessment_sessions_session_type_check CHECK ((session_type = ANY (ARRAY['baseline'::text, 'midline'::text, 'endline'::text])))
);


--
-- Name: assignments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.assignments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    submission_table text NOT NULL,
    submission_id uuid NOT NULL,
    assigned_to uuid NOT NULL,
    assigned_by uuid,
    assigned_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT assignments_submission_table_check CHECK ((submission_table = ANY (ARRAY['contact_submissions'::text, 'volunteer_applications'::text, 'partnership_inquiries'::text])))
);


--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    actor_user_id uuid,
    action text NOT NULL,
    table_name text NOT NULL,
    record_id uuid,
    before_data jsonb,
    after_data jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: cohorts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cohorts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    program_cycle_id uuid NOT NULL,
    site_id uuid,
    label text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: consent_records; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.consent_records (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    person_id uuid NOT NULL,
    consent_type text NOT NULL,
    granted boolean NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    source text,
    CONSTRAINT consent_records_consent_type_check CHECK ((consent_type = ANY (ARRAY['data_processing'::text, 'marketing_email'::text, 'image_use'::text])))
);


--
-- Name: contact_submissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.contact_submissions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    category text NOT NULL,
    full_name text NOT NULL,
    email public.citext NOT NULL,
    subject text,
    message text NOT NULL,
    locale text DEFAULT 'en'::text NOT NULL,
    status_code text DEFAULT 'pending'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT contact_submissions_category_check CHECK ((category = ANY (ARRAY['general'::text, 'programs'::text, 'partnership'::text, 'volunteering'::text, 'media'::text, 'donations'::text, 'support'::text]))),
    CONSTRAINT contact_submissions_locale_check CHECK ((locale = ANY (ARRAY['en'::text, 'ar'::text, 'fr'::text])))
);


--
-- Name: currencies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.currencies (
    code text NOT NULL,
    label text NOT NULL,
    minor_unit integer DEFAULT 2 NOT NULL
);


--
-- Name: data_quality_assessments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.data_quality_assessments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    indicator_observation_id uuid NOT NULL,
    completeness_ok boolean DEFAULT true NOT NULL,
    accuracy_ok boolean DEFAULT true NOT NULL,
    duplicates_found integer DEFAULT 0 NOT NULL,
    missing_data_note text,
    assessed_by uuid,
    assessed_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: donation_allocations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.donation_allocations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    donation_id uuid NOT NULL,
    fund_id uuid NOT NULL,
    amount_minor_units bigint NOT NULL,
    support_item_id uuid,
    CONSTRAINT donation_allocations_amount_minor_units_check CHECK ((amount_minor_units > 0))
);


--
-- Name: TABLE donation_allocations; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.donation_allocations IS 'A single donation may be split across several funds; the sum of allocations for a donation should equal its amount_minor_units.';


--
-- Name: donation_frequencies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.donation_frequencies (
    code text NOT NULL,
    label text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    is_active boolean DEFAULT true NOT NULL
);


--
-- Name: donation_intents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.donation_intents (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    person_id uuid,
    fund_id uuid NOT NULL,
    frequency_code text NOT NULL,
    amount_minor_units bigint NOT NULL,
    currency_code text NOT NULL,
    donor_name text,
    donor_email public.citext,
    is_anonymous boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT donation_intents_amount_minor_units_check CHECK ((amount_minor_units > 0))
);


--
-- Name: TABLE donation_intents; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.donation_intents IS 'What a donor selected before checkout (fund, frequency, amount). Never proof of payment on its own.';


--
-- Name: donation_statuses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.donation_statuses (
    code text NOT NULL,
    label text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    is_active boolean DEFAULT true NOT NULL
);


--
-- Name: donations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.donations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    payment_transaction_id uuid NOT NULL,
    person_id uuid,
    status_code text DEFAULT 'pending'::text NOT NULL,
    amount_minor_units bigint NOT NULL,
    currency_code text NOT NULL,
    is_anonymous boolean DEFAULT false NOT NULL,
    confirmed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT donations_amount_minor_units_check CHECK ((amount_minor_units > 0))
);


--
-- Name: evidence_artifacts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.evidence_artifacts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    indicator_observation_id uuid,
    artifact_type text NOT NULL,
    storage_path text,
    description text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT evidence_artifacts_artifact_type_check CHECK ((artifact_type = ANY (ARRAY['attendance_record'::text, 'assessment'::text, 'observation'::text, 'feedback'::text, 'photo'::text, 'document'::text])))
);


--
-- Name: training_registrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_registrations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_id uuid NOT NULL,
    person_id uuid,
    full_name text NOT NULL,
    email public.citext NOT NULL,
    phone text,
    status_code text DEFAULT 'pending'::text NOT NULL,
    fee_paid boolean DEFAULT false NOT NULL,
    reviewed_by uuid,
    reviewed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    completion_status_code text DEFAULT 'not_yet'::text NOT NULL,
    CONSTRAINT training_registrations_completion_status_code_check CHECK ((completion_status_code = ANY (ARRAY['not_yet'::text, 'incomplete'::text, 'pending_manager_approval'::text, 'completed'::text]))),
    CONSTRAINT training_registrations_status_code_check CHECK ((status_code = ANY (ARRAY['pending'::text, 'approved'::text, 'waitlisted'::text, 'rejected'::text, 'withdrawn'::text, 'cancelled'::text])))
);


--
-- Name: TABLE training_registrations; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.training_registrations IS 'A person is "on the roster" (a trainee) once status_code = approved and, for a paid training, fee_paid = true - computed at read time, not a separate flag.';


--
-- Name: COLUMN training_registrations.completion_status_code; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.training_registrations.completion_status_code IS 'Set by the assigned trainer (or training_manager/admin/super_admin) once the training has run - same training_registrations_approval_update RLS as status_code/fee_paid, no new policy needed. get-certificate.ts requires this to be ''completed'', not just an approved+paid registration on a finished training.';


--
-- Name: training_translations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_translations (
    training_id uuid NOT NULL,
    locale text NOT NULL,
    title text NOT NULL,
    description text,
    CONSTRAINT training_translations_locale_check CHECK ((locale = ANY (ARRAY['en'::text, 'ar'::text, 'fr'::text])))
);


--
-- Name: trainings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.trainings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    slug text NOT NULL,
    starts_on date NOT NULL,
    ends_on date NOT NULL,
    publication_status_code text DEFAULT 'draft'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    trainer_id uuid NOT NULL,
    registration_closes_on date,
    fee_amount_minor_units bigint,
    fee_currency_code text,
    public_number bigint,
    registration_opens_on date,
    capacity integer,
    waitlist_enabled boolean DEFAULT false NOT NULL,
    publish_requested_at timestamp with time zone,
    publish_error text,
    CONSTRAINT trainings_capacity_check CHECK (((capacity IS NULL) OR (capacity >= 0))),
    CONSTRAINT trainings_check CHECK ((ends_on >= starts_on)),
    CONSTRAINT trainings_fee_amount_minor_units_check CHECK ((fee_amount_minor_units > 0)),
    CONSTRAINT trainings_registration_date_order_check CHECK (((registration_closes_on IS NULL) OR (registration_closes_on <= ends_on))),
    CONSTRAINT trainings_registration_window_check CHECK (((registration_opens_on IS NULL) OR (registration_closes_on IS NULL) OR (registration_opens_on <= registration_closes_on)))
);


--
-- Name: TABLE trainings; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.trainings IS 'A single training session/cohort. Whether it shows as upcoming, current or past on the public site is computed from starts_on/ends_on against the current date, not stored.';


--
-- Name: COLUMN trainings.public_number; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.trainings.public_number IS 'System-assigned URL discriminator for trainings created after 20260910000004. Null on legacy rows so their published URLs remain stable.';


--
-- Name: COLUMN trainings.publish_error; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.trainings.publish_error IS 'Set by finalize-training-publications.ts when a locale detail page did not return 200 after a build - cleared on the next request_training_publication() call. Null while draft/published/archived/publish_pending.';


--
-- Name: finance_payment_queue; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.finance_payment_queue AS
 SELECT tr.id AS registration_id,
    tr.training_id,
    COALESCE(tt.title, t.slug) AS training_title,
    tr.full_name,
    tr.email,
    tr.status_code,
    tr.fee_paid,
    t.fee_amount_minor_units,
    t.fee_currency_code,
    tr.created_at
   FROM ((public.training_registrations tr
     JOIN public.trainings t ON ((t.id = tr.training_id)))
     LEFT JOIN public.training_translations tt ON (((tt.training_id = t.id) AND (tt.locale = 'en'::text))))
  WHERE ((t.fee_amount_minor_units > 0) AND (tr.status_code = 'approved'::text) AND public.current_user_has_permission('finance.read'::text));


--
-- Name: VIEW finance_payment_queue; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON VIEW public.finance_payment_queue IS 'Finance-scoped projection of approved, fee-bearing registrations: name, email, training, fee amount, paid status. Deliberately excludes phone and completion_status_code - not finance''s concern. Gated by finance.read inside the view definition itself (see comment above), not a training_registrations RLS policy, which would expose every column to anyone who qualifies.';


--
-- Name: fund_types; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.fund_types (
    code text NOT NULL,
    label text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    is_active boolean DEFAULT true NOT NULL
);


--
-- Name: funds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.funds (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    code text NOT NULL,
    label text NOT NULL,
    fund_type_code text NOT NULL,
    program_id uuid,
    initiative_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    archived_at timestamp with time zone
);


--
-- Name: governance_appointments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.governance_appointments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    person_id uuid NOT NULL,
    role_code text NOT NULL,
    starts_on date DEFAULT CURRENT_DATE NOT NULL,
    ends_on date,
    is_current boolean GENERATED ALWAYS AS ((ends_on IS NULL)) STORED,
    note text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE governance_appointments; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.governance_appointments IS 'Founders, board members and committee members over time. One person may hold several appointments across their tenure.';


--
-- Name: governance_roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.governance_roles (
    code text NOT NULL,
    label text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    is_active boolean DEFAULT true NOT NULL
);


--
-- Name: indicator_definitions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.indicator_definitions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    code text NOT NULL,
    result_level_code text NOT NULL,
    unit text NOT NULL,
    improvement_direction text NOT NULL,
    calculation_formula text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT indicator_definitions_improvement_direction_check CHECK ((improvement_direction = ANY (ARRAY['increase'::text, 'decrease'::text])))
);


--
-- Name: TABLE indicator_definitions; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.indicator_definitions IS 'A reusable indicator, e.g. "attendance rate". Its target and reporting frequency belong to a program cycle via measurement_plans, not here.';


--
-- Name: indicator_observations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.indicator_observations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    measurement_plan_id uuid NOT NULL,
    reporting_period_id uuid NOT NULL,
    cohort_id uuid,
    indicator_version_id uuid NOT NULL,
    value numeric,
    verification_status_code text DEFAULT 'planned'::text NOT NULL,
    entered_by uuid,
    verified_by uuid,
    verified_at timestamp with time zone,
    is_suppressed boolean DEFAULT false NOT NULL,
    suppression_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE indicator_observations; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.indicator_observations IS 'value is nullable: null means "not yet measured", which the public site must render differently from a genuine measured value of 0.';


--
-- Name: indicator_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.indicator_versions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    indicator_definition_id uuid NOT NULL,
    version_number integer NOT NULL,
    change_note text,
    effective_from date DEFAULT CURRENT_DATE NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE indicator_versions; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.indicator_versions IS 'Changing how an indicator is calculated creates a new version so historical observations stay comparable and auditable.';


--
-- Name: homepage_impact_stats; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.homepage_impact_stats WITH (security_invoker='true') AS
 SELECT id.code,
    COALESCE(sum(io.value), (0)::numeric) AS total
   FROM ((public.indicator_definitions id
     LEFT JOIN public.indicator_versions iv ON ((iv.indicator_definition_id = id.id)))
     LEFT JOIN public.indicator_observations io ON (((io.indicator_version_id = iv.id) AND (io.verification_status_code = 'published'::text) AND (io.is_suppressed = false))))
  WHERE (id.code = ANY (ARRAY['children_reached'::text, 'teachers_trained'::text, 'learning_sessions_delivered'::text, 'communities_reached'::text]))
  GROUP BY id.code;


--
-- Name: VIEW homepage_impact_stats; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON VIEW public.homepage_impact_stats IS 'One row per homepage counter (code, total). security_invoker so it respects the querying role''s own RLS on indicator_observations rather than the view owner''s.';


--
-- Name: indicator_baselines; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.indicator_baselines (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    measurement_plan_id uuid NOT NULL,
    value numeric NOT NULL,
    measured_on date NOT NULL,
    data_source text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: indicator_disaggregations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.indicator_disaggregations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    measurement_plan_id uuid NOT NULL,
    dimension text NOT NULL,
    CONSTRAINT indicator_disaggregations_dimension_check CHECK ((dimension = ANY (ARRAY['sex'::text, 'age_group'::text, 'disability'::text, 'location'::text, 'language'::text, 'displacement_status'::text])))
);


--
-- Name: indicator_scopes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.indicator_scopes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    indicator_definition_id uuid NOT NULL,
    program_id uuid,
    initiative_id uuid,
    result_node_id uuid,
    CONSTRAINT indicator_scopes_check CHECK (((program_id IS NOT NULL) OR (initiative_id IS NOT NULL)))
);


--
-- Name: indicator_targets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.indicator_targets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    measurement_plan_id uuid NOT NULL,
    reporting_period_id uuid NOT NULL,
    target_value numeric NOT NULL,
    rationale text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: indicator_translations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.indicator_translations (
    indicator_definition_id uuid NOT NULL,
    locale text NOT NULL,
    name text NOT NULL,
    definition text NOT NULL,
    CONSTRAINT indicator_translations_locale_check CHECK ((locale = ANY (ARRAY['en'::text, 'ar'::text, 'fr'::text])))
);


--
-- Name: initiative_program_links; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.initiative_program_links (
    initiative_id uuid NOT NULL,
    program_id uuid NOT NULL
);


--
-- Name: TABLE initiative_program_links; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.initiative_program_links IS 'Many-to-many: one initiative (e.g. My Tablet) can support several program components.';


--
-- Name: initiative_translations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.initiative_translations (
    initiative_id uuid NOT NULL,
    locale text NOT NULL,
    title text NOT NULL,
    tagline text,
    summary text NOT NULL,
    CONSTRAINT initiative_translations_locale_check CHECK ((locale = ANY (ARRAY['en'::text, 'ar'::text, 'fr'::text])))
);


--
-- Name: initiatives; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.initiatives (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    slug text NOT NULL,
    publication_status_code text DEFAULT 'draft'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    archived_at timestamp with time zone
);


--
-- Name: instrument_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.instrument_versions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    assessment_instrument_id uuid NOT NULL,
    version_number integer NOT NULL,
    storage_path text,
    effective_from date DEFAULT CURRENT_DATE NOT NULL
);


--
-- Name: internal_notes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.internal_notes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    submission_table text NOT NULL,
    submission_id uuid NOT NULL,
    author_id uuid,
    note text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT internal_notes_submission_table_check CHECK ((submission_table = ANY (ARRAY['contact_submissions'::text, 'volunteer_applications'::text, 'partnership_inquiries'::text])))
);


--
-- Name: learning_actions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.learning_actions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    program_cycle_id uuid,
    indicator_observation_id uuid,
    what_the_evidence_showed text NOT NULL,
    what_changed text NOT NULL,
    decided_by uuid,
    decided_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE learning_actions; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.learning_actions IS 'Completes the "Learn" step of the measurement cycle: what management actually changed because of the evidence.';


--
-- Name: measurement_plans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.measurement_plans (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    indicator_scope_id uuid NOT NULL,
    program_cycle_id uuid,
    data_source text NOT NULL,
    collection_instrument text,
    collection_frequency text NOT NULL,
    responsible_user_id uuid,
    limitations text,
    privacy_classification text DEFAULT 'restricted'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT measurement_plans_privacy_classification_check CHECK ((privacy_classification = ANY (ARRAY['public'::text, 'restricted'::text, 'confidential'::text])))
);


--
-- Name: media_assets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.media_assets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    storage_path text NOT NULL,
    alt_text text,
    program_id uuid,
    initiative_id uuid,
    organization_id uuid,
    uploaded_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    person_id uuid
);


--
-- Name: membership_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.membership_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    membership_id uuid NOT NULL,
    event_type text NOT NULL,
    event_date date DEFAULT CURRENT_DATE NOT NULL,
    note text,
    recorded_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT membership_events_event_type_check CHECK ((event_type = ANY (ARRAY['joined'::text, 'renewed'::text, 'suspended'::text, 'resigned'::text, 'reinstated'::text])))
);


--
-- Name: membership_statuses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.membership_statuses (
    code text NOT NULL,
    label text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    is_active boolean DEFAULT true NOT NULL
);


--
-- Name: membership_types; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.membership_types (
    code text NOT NULL,
    label text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    is_active boolean DEFAULT true NOT NULL
);


--
-- Name: memberships; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.memberships (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    person_id uuid NOT NULL,
    membership_number text NOT NULL,
    membership_type_code text NOT NULL,
    status_code text NOT NULL,
    joined_on date DEFAULT CURRENT_DATE NOT NULL,
    renewed_on date,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    archived_at timestamp with time zone
);


--
-- Name: observation_breakdowns; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.observation_breakdowns (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    indicator_observation_id uuid NOT NULL,
    dimension text NOT NULL,
    dimension_value text NOT NULL,
    value numeric,
    is_suppressed boolean DEFAULT false NOT NULL
);


--
-- Name: observation_rubrics; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.observation_rubrics (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    code text NOT NULL,
    locale text NOT NULL,
    criteria text NOT NULL,
    CONSTRAINT observation_rubrics_locale_check CHECK ((locale = ANY (ARRAY['en'::text, 'ar'::text, 'fr'::text])))
);


--
-- Name: organization_types; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organization_types (
    code text NOT NULL,
    label text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    is_active boolean DEFAULT true NOT NULL
);


--
-- Name: organizations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organizations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    organization_type_code text NOT NULL,
    country text,
    website text,
    logo_publication_permitted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    archived_at timestamp with time zone
);


--
-- Name: partner_relationships; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.partner_relationships (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid NOT NULL,
    partner_role_code text NOT NULL,
    program_id uuid,
    initiative_id uuid,
    starts_on date DEFAULT CURRENT_DATE NOT NULL,
    ends_on date,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: partner_roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.partner_roles (
    code text NOT NULL,
    label text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    is_active boolean DEFAULT true NOT NULL
);


--
-- Name: partnership_inquiries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.partnership_inquiries (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_name text NOT NULL,
    country text,
    contact_person text,
    email public.citext NOT NULL,
    organization_type text,
    proposed_collaboration text,
    program_of_interest_id uuid,
    message text NOT NULL,
    status_code text DEFAULT 'pending'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    contact_phone text
);


--
-- Name: COLUMN partnership_inquiries.contact_phone; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.partnership_inquiries.contact_phone IS 'Normalized as "<dial code> <digits>" by src/lib/validation.ts (normalizePhoneNumber) before submission, same convention as every other public form''s phone field. Optional, since not every inquiry includes one.';


--
-- Name: payment_customers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.payment_customers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    person_id uuid,
    provider_code text NOT NULL,
    provider_customer_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: payment_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.payment_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    payment_transaction_id uuid,
    provider_code text NOT NULL,
    provider_event_id text NOT NULL,
    event_type text NOT NULL,
    raw_payload jsonb NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE payment_events; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.payment_events IS 'Immutable, signature-verified webhook events exactly as received. Never edited or deleted; the audit trail behind every payment_transactions status change.';


--
-- Name: payment_providers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.payment_providers (
    code text NOT NULL,
    label text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    is_active boolean DEFAULT true NOT NULL
);


--
-- Name: payment_records; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.payment_records (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_registration_id uuid NOT NULL,
    status_code text NOT NULL,
    amount_minor_units bigint DEFAULT 0 NOT NULL,
    currency_code text,
    method text,
    reference text,
    note text,
    recorded_by uuid DEFAULT auth.uid(),
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT payment_records_amount_minor_units_check CHECK ((amount_minor_units >= 0)),
    CONSTRAINT payment_records_status_code_check CHECK ((status_code = ANY (ARRAY['due'::text, 'partial'::text, 'paid'::text, 'waived'::text, 'refunded'::text, 'not_required'::text])))
);


--
-- Name: TABLE payment_records; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.payment_records IS 'Append-only: every entry is a transition (due/partial/paid/waived/refunded/not_required) with who recorded it and when, not a single mutable balance. The most recent row by recorded_at for a registration is its current status; training_registrations.fee_paid mirrors that via sync_registration_fee_paid() below for every existing reader that only needs the boolean.';


--
-- Name: payment_transaction_statuses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.payment_transaction_statuses (
    code text NOT NULL,
    label text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    is_active boolean DEFAULT true NOT NULL
);


--
-- Name: payment_transactions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.payment_transactions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    donation_intent_id uuid,
    recurring_agreement_id uuid,
    provider_code text NOT NULL,
    provider_transaction_id text NOT NULL,
    status_code text DEFAULT 'pending'::text NOT NULL,
    amount_minor_units bigint NOT NULL,
    currency_code text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT payment_transactions_amount_minor_units_check CHECK ((amount_minor_units > 0))
);


--
-- Name: TABLE payment_transactions; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.payment_transactions IS 'One row per attempted charge. The (provider_code, provider_transaction_id) uniqueness constraint is what makes retried webhooks idempotent.';


--
-- Name: people; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.people (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    full_name text NOT NULL,
    preferred_locale text DEFAULT 'en'::text NOT NULL,
    email public.citext,
    phone text,
    country text,
    notes text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    archived_at timestamp with time zone,
    public_slug text,
    preferred_name text,
    region text,
    timezone text,
    education_employment_context text,
    learning_interests text,
    learning_goals text,
    CONSTRAINT people_preferred_locale_check CHECK ((preferred_locale = ANY (ARRAY['en'::text, 'ar'::text, 'fr'::text])))
);


--
-- Name: COLUMN people.public_slug; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.people.public_slug IS 'Matches a slug in src/content/team.ts founderSlugs. Null (the default) means this person is never shown publicly, regardless of any other field.';


--
-- Name: people_translations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.people_translations (
    person_id uuid NOT NULL,
    locale text NOT NULL,
    bio text,
    CONSTRAINT people_translations_locale_check CHECK ((locale = ANY (ARRAY['en'::text, 'ar'::text, 'fr'::text])))
);


--
-- Name: TABLE people_translations; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.people_translations IS 'Localized public biography for a person, matching the translations-table pattern used everywhere else in this schema (program_translations, initiative_translations, etc.).';


--
-- Name: permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.permissions (
    code text NOT NULL,
    label text NOT NULL,
    description text
);


--
-- Name: person_accessibility_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.person_accessibility_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    person_id uuid NOT NULL,
    training_registration_id uuid,
    request_details text NOT NULL,
    status_code text DEFAULT 'submitted'::text NOT NULL,
    reviewed_by uuid,
    reviewed_at timestamp with time zone,
    staff_notes text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT person_accessibility_requests_status_code_check CHECK ((status_code = ANY (ARRAY['submitted'::text, 'in_review'::text, 'approved'::text, 'declined'::text, 'fulfilled'::text])))
);


--
-- Name: person_consent_records; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.person_consent_records (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    person_id uuid NOT NULL,
    consent_type text NOT NULL,
    granted boolean NOT NULL,
    granted_by_person_id uuid,
    method text DEFAULT 'self_service'::text NOT NULL,
    notes text,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT person_consent_records_consent_type_check CHECK ((consent_type = ANY (ARRAY['photo_media'::text, 'data_processing'::text, 'communications'::text, 'program_participation'::text]))),
    CONSTRAINT person_consent_records_method_check CHECK ((method = ANY (ARRAY['self_service'::text, 'staff_recorded'::text, 'paper_form'::text])))
);


--
-- Name: TABLE person_consent_records; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.person_consent_records IS 'Append-only - a withdrawal is a new granted=false row, never an edit to a previous one. There is no self-update/delete policy at all, by design.';


--
-- Name: person_emergency_contacts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.person_emergency_contacts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    person_id uuid NOT NULL,
    contact_name text NOT NULL,
    relationship text,
    phone text,
    email public.citext,
    is_primary boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: person_guardian_relationships; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.person_guardian_relationships (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    guardian_person_id uuid NOT NULL,
    dependent_person_id uuid NOT NULL,
    relationship_type text NOT NULL,
    verified boolean DEFAULT false NOT NULL,
    verified_by uuid,
    verified_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT person_guardian_relationships_check CHECK ((guardian_person_id <> dependent_person_id)),
    CONSTRAINT person_guardian_relationships_relationship_type_check CHECK ((relationship_type = ANY (ARRAY['parent'::text, 'legal_guardian'::text, 'other'::text])))
);


--
-- Name: professional_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.professional_credentials (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    trainer_id uuid NOT NULL,
    credential_type text NOT NULL,
    title text NOT NULL,
    issuer text,
    issued_on date,
    expires_on date,
    verification_status_code text DEFAULT 'draft'::text NOT NULL,
    submitted_at timestamp with time zone,
    reviewed_by uuid,
    reviewed_at timestamp with time zone,
    review_notes text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT professional_credentials_credential_type_check CHECK ((credential_type = ANY (ARRAY['degree'::text, 'certificate'::text, 'license'::text, 'training'::text, 'other'::text]))),
    CONSTRAINT professional_credentials_verification_status_code_check CHECK ((verification_status_code = ANY (ARRAY['draft'::text, 'submitted'::text, 'verified'::text, 'rejected'::text, 'expired'::text])))
);


--
-- Name: COLUMN professional_credentials.verification_status_code; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.professional_credentials.verification_status_code IS 'draft (trainer still editing) -> submitted (awaiting staff review) -> verified/rejected (staff decision) - or expired, set by a future scheduled process once expires_on has passed. A trainer can move their own credential between draft and submitted only; verified/rejected/expired require training.manage.';


--
-- Name: profile_documents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.profile_documents (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    trainer_id uuid NOT NULL,
    credential_id uuid,
    document_type text NOT NULL,
    storage_path text NOT NULL,
    uploaded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT profile_documents_document_type_check CHECK ((document_type = ANY (ARRAY['cv'::text, 'certificate'::text, 'degree'::text, 'license'::text, 'other'::text])))
);


--
-- Name: COLUMN profile_documents.storage_path; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.profile_documents.storage_path IS 'A private Supabase Storage object path in the trainer-documents bucket, under a {trainer_id}/... prefix - never a public URL, same convention as trainer-photos'' {person_id}/... prefix.';


--
-- Name: program_activities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.program_activities (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    program_id uuid NOT NULL,
    locale text NOT NULL,
    label text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    CONSTRAINT program_activities_locale_check CHECK ((locale = ANY (ARRAY['en'::text, 'ar'::text, 'fr'::text])))
);


--
-- Name: program_cycles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.program_cycles (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    program_id uuid NOT NULL,
    label text NOT NULL,
    starts_on date NOT NULL,
    ends_on date,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: program_indicators; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.program_indicators (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    program_id uuid NOT NULL,
    locale text NOT NULL,
    label text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    CONSTRAINT program_indicators_locale_check CHECK ((locale = ANY (ARRAY['en'::text, 'ar'::text, 'fr'::text])))
);


--
-- Name: program_statuses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.program_statuses (
    code text NOT NULL,
    label text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    is_active boolean DEFAULT true NOT NULL
);


--
-- Name: program_translations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.program_translations (
    program_id uuid NOT NULL,
    locale text NOT NULL,
    title text NOT NULL,
    summary text NOT NULL,
    objective text,
    funding_description text,
    CONSTRAINT program_translations_locale_check CHECK ((locale = ANY (ARRAY['en'::text, 'ar'::text, 'fr'::text])))
);


--
-- Name: programs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.programs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    slug text NOT NULL,
    parent_program_id uuid,
    status_code text NOT NULL,
    publication_status_code text DEFAULT 'draft'::text NOT NULL,
    target_age text,
    geography text,
    starts_on date,
    ends_on date,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    archived_at timestamp with time zone
);


--
-- Name: TABLE programs; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.programs IS 'Umbrella programs and their components, self-referencing via parent_program_id. Localized copy lives in program_translations.';


--
-- Name: public_founders_directory; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.public_founders_directory AS
 SELECT id,
    public_slug,
    full_name
   FROM public.people p
  WHERE ((public_slug IS NOT NULL) AND (EXISTS ( SELECT 1
           FROM public.governance_appointments ga
          WHERE ((ga.person_id = p.id) AND (ga.is_current = true)))));


--
-- Name: VIEW public_founders_directory; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON VIEW public.public_founders_directory IS 'Safe public projection (id, public_slug, full_name only) of people currently serving a governance role and opted in via public_slug. Query this, not people directly, from any public-facing code.';


--
-- Name: trainers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.trainers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    person_id uuid NOT NULL,
    specialty text,
    status_code text DEFAULT 'pending'::text NOT NULL,
    applied_at timestamp with time zone DEFAULT now() NOT NULL,
    reviewed_by uuid,
    reviewed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    experience text,
    location text,
    education text,
    languages text,
    availability text,
    cv_storage_path text,
    certificate_storage_paths text[],
    CONSTRAINT trainers_status_code_check CHECK ((status_code = ANY (ARRAY['pending'::text, 'approved'::text, 'rejected'::text])))
);


--
-- Name: COLUMN trainers.cv_storage_path; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.trainers.cv_storage_path IS 'A private Supabase Storage object path in the trainer-documents bucket, never a public URL - same convention as volunteer_applications.cv_storage_path.';


--
-- Name: public_trainers_directory; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.public_trainers_directory AS
 SELECT tr.id,
    p.full_name,
    tr.specialty,
    p.id AS person_id,
    tr.experience,
    tr.location,
    tr.education,
    tr.languages,
    tr.availability,
    ( SELECT ma.storage_path
           FROM public.media_assets ma
          WHERE (ma.person_id = p.id)
          ORDER BY ma.created_at DESC
         LIMIT 1) AS photo_storage_path
   FROM (public.trainers tr
     JOIN public.people p ON ((p.id = tr.person_id)))
  WHERE (tr.status_code = 'approved'::text);


--
-- Name: volunteer_applications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.volunteer_applications (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    person_id uuid,
    full_name text NOT NULL,
    email public.citext NOT NULL,
    phone text,
    location text,
    age_range text,
    education text,
    profession text,
    skills text,
    languages text,
    availability text,
    areas_of_interest text,
    cv_storage_path text,
    status_code text DEFAULT 'pending'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    is_public_volunteer boolean DEFAULT false NOT NULL,
    public_role text
);


--
-- Name: TABLE volunteer_applications; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.volunteer_applications IS 'cv_storage_path is a private Supabase Storage object path, never a public URL.';


--
-- Name: COLUMN volunteer_applications.is_public_volunteer; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.volunteer_applications.is_public_volunteer IS 'Staff-set only. Default false. True means this person consented to and was approved for public listing on the team page.';


--
-- Name: COLUMN volunteer_applications.public_role; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.volunteer_applications.public_role IS 'Short public-facing descriptor (e.g. "Community Outreach Volunteer"), distinct from the free-text areas_of_interest intake field. Null falls back to a generic label in the UI.';


--
-- Name: public_volunteers_directory; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.public_volunteers_directory AS
 SELECT id,
    full_name,
    public_role
   FROM public.volunteer_applications
  WHERE (is_public_volunteer = true);


--
-- Name: VIEW public_volunteers_directory; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON VIEW public.public_volunteers_directory IS 'Safe public projection (id, full_name, public_role only) of volunteer_applications rows staff have opted in via is_public_volunteer. Query this, not volunteer_applications directly, from any public-facing code. Volunteers have no separate approval status (unlike trainers) - this toggle is the approval.';


--
-- Name: publication_approvals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.publication_approvals (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    indicator_observation_id uuid NOT NULL,
    approved_by uuid,
    approved_at timestamp with time zone DEFAULT now() NOT NULL,
    note text
);


--
-- Name: publication_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.publication_snapshots (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    indicator_observation_id uuid NOT NULL,
    snapshot jsonb NOT NULL,
    published_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE publication_snapshots; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.publication_snapshots IS 'Frozen copy of exactly what was shown publicly, retained even if the underlying observation is later revised.';


--
-- Name: publication_statuses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.publication_statuses (
    code text NOT NULL,
    label text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    is_active boolean DEFAULT true NOT NULL
);


--
-- Name: TABLE publication_statuses; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.publication_statuses IS 'Draft/published/archived lifecycle for public-facing content: programs, initiatives, resources.';


--
-- Name: receipt_deliveries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.receipt_deliveries (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    receipt_id uuid NOT NULL,
    delivered_to public.citext NOT NULL,
    status_code text DEFAULT 'queued'::text NOT NULL,
    attempted_at timestamp with time zone DEFAULT now() NOT NULL,
    error_message text
);


--
-- Name: receipt_delivery_statuses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.receipt_delivery_statuses (
    code text NOT NULL,
    label text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    is_active boolean DEFAULT true NOT NULL
);


--
-- Name: receipts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.receipts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    donation_id uuid NOT NULL,
    receipt_number text NOT NULL,
    storage_path text,
    checksum text,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    superseded_by uuid
);


--
-- Name: TABLE receipts; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.receipts IS 'Immutable once issued. A correction or refund creates a new row referenced via superseded_by — an issued receipt is never edited in place.';


--
-- Name: recurring_agreements; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.recurring_agreements (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    donation_intent_id uuid,
    payment_customer_id uuid,
    provider_code text NOT NULL,
    provider_subscription_id text NOT NULL,
    frequency_code text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT recurring_agreements_status_check CHECK ((status = ANY (ARRAY['active'::text, 'paused'::text, 'cancelled'::text])))
);


--
-- Name: refunds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.refunds (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    donation_id uuid NOT NULL,
    amount_minor_units bigint NOT NULL,
    reason text,
    provider_refund_id text,
    processed_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    CONSTRAINT refunds_amount_minor_units_check CHECK ((amount_minor_units > 0))
);


--
-- Name: reporting_periods; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.reporting_periods (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    label text NOT NULL,
    starts_on date NOT NULL,
    ends_on date NOT NULL,
    CONSTRAINT reporting_periods_check CHECK ((ends_on >= starts_on))
);


--
-- Name: resource_translations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.resource_translations (
    resource_id uuid NOT NULL,
    locale text NOT NULL,
    title text NOT NULL,
    description text,
    CONSTRAINT resource_translations_locale_check CHECK ((locale = ANY (ARRAY['en'::text, 'ar'::text, 'fr'::text])))
);


--
-- Name: resources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.resources (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    slug text NOT NULL,
    publication_status_code text DEFAULT 'draft'::text NOT NULL,
    storage_path text,
    published_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    archived_at timestamp with time zone
);


--
-- Name: result_levels; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.result_levels (
    code text NOT NULL,
    label text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL
);


--
-- Name: result_links; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.result_links (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    from_result_node_id uuid NOT NULL,
    to_result_node_id uuid NOT NULL,
    CONSTRAINT result_links_check CHECK ((from_result_node_id <> to_result_node_id))
);


--
-- Name: TABLE result_links; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.result_links IS 'Directed edges connecting one result-chain step to the next, e.g. a specific activity feeding a specific output.';


--
-- Name: result_node_translations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.result_node_translations (
    result_node_id uuid NOT NULL,
    locale text NOT NULL,
    label text NOT NULL,
    description text,
    CONSTRAINT result_node_translations_locale_check CHECK ((locale = ANY (ARRAY['en'::text, 'ar'::text, 'fr'::text])))
);


--
-- Name: result_nodes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.result_nodes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    program_id uuid NOT NULL,
    result_level_code text NOT NULL,
    code text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: role_permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.role_permissions (
    role_code text NOT NULL,
    permission_code text NOT NULL
);


--
-- Name: roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.roles (
    code text NOT NULL,
    label text NOT NULL,
    description text,
    is_staff boolean DEFAULT false NOT NULL,
    is_assignable boolean DEFAULT false NOT NULL,
    supports_scope boolean DEFAULT false NOT NULL
);


--
-- Name: security_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.security_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    actor_user_id uuid,
    subject_user_id uuid,
    event_type text NOT NULL,
    result text DEFAULT 'success'::text NOT NULL,
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT security_events_event_type_check CHECK ((event_type = ANY (ARRAY['role_granted'::text, 'role_revoked'::text, 'sessions_revoked'::text, 'mfa_enrolled'::text, 'mfa_removed'::text, 'recovery_hold_released'::text, 'mfa_recovery_started'::text, 'mfa_recovery_completed'::text, 'mfa_recovery_failed'::text]))),
    CONSTRAINT security_events_result_check CHECK ((result = ANY (ARRAY['success'::text, 'failure'::text])))
);


--
-- Name: TABLE security_events; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.security_events IS 'Security-relevant event log, separate from the general-purpose audit_log table. metadata must never contain a password, access token, refresh token, OTP value, or full request body - only safe, already-non-secret context (a role code, a scope type/id, a boolean).';


--
-- Name: sites; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sites (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    locality text,
    country text DEFAULT 'Lebanon'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: submission_status_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.submission_status_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    submission_table text NOT NULL,
    submission_id uuid NOT NULL,
    from_status_code text,
    to_status_code text NOT NULL,
    changed_by uuid,
    changed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT submission_status_history_submission_table_check CHECK ((submission_table = ANY (ARRAY['contact_submissions'::text, 'volunteer_applications'::text, 'partnership_inquiries'::text])))
);


--
-- Name: submission_statuses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.submission_statuses (
    code text NOT NULL,
    label text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL
);


--
-- Name: support_item_fulfillments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.support_item_fulfillments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    support_item_id uuid NOT NULL,
    donation_id uuid,
    quantity integer NOT NULL,
    fulfillment_type text NOT NULL,
    source text NOT NULL,
    fulfilled_at timestamp with time zone DEFAULT now() NOT NULL,
    notes text,
    created_by uuid,
    CONSTRAINT support_item_fulfillments_fulfillment_type_check CHECK ((fulfillment_type = ANY (ARRAY['purchased'::text, 'in_kind_received'::text, 'donor_paid'::text, 'distributed'::text]))),
    CONSTRAINT support_item_fulfillments_quantity_check CHECK ((quantity > 0)),
    CONSTRAINT support_item_fulfillments_source_check CHECK ((source = ANY (ARRAY['donor'::text, 'partner'::text, 'internal_purchase'::text])))
);


--
-- Name: support_item_translations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.support_item_translations (
    support_item_id uuid NOT NULL,
    locale text NOT NULL,
    title text NOT NULL,
    description text,
    CONSTRAINT support_item_translations_locale_check CHECK ((locale = ANY (ARRAY['en'::text, 'ar'::text, 'fr'::text])))
);


--
-- Name: support_items; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.support_items (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    initiative_id uuid NOT NULL,
    fund_id uuid,
    slug text NOT NULL,
    item_type text NOT NULL,
    unit_price_minor_units bigint,
    currency_code text NOT NULL,
    target_quantity integer,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT support_items_item_type_check CHECK ((item_type = ANY (ARRAY['money_goal'::text, 'physical_item'::text, 'service'::text, 'in_kind_goal'::text]))),
    CONSTRAINT support_items_status_check CHECK ((status = ANY (ARRAY['active'::text, 'paused'::text, 'complete'::text, 'closed'::text]))),
    CONSTRAINT support_items_target_quantity_check CHECK ((target_quantity > 0)),
    CONSTRAINT support_items_unit_price_minor_units_check CHECK ((unit_price_minor_units > 0))
);


--
-- Name: TABLE support_items; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.support_items IS 'A tangible, purchasable unit within an initiative (e.g. "One Book" under My Book). item_type distinguishes a funding goal priced in money from an actual physical/in-kind item being tracked.';


--
-- Name: survey_responses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.survey_responses (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    measurement_plan_id uuid NOT NULL,
    participant_code text,
    question_code text NOT NULL,
    response text,
    submitted_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: theories_of_change; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.theories_of_change (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    program_id uuid NOT NULL,
    locale text NOT NULL,
    narrative text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT theories_of_change_locale_check CHECK ((locale = ANY (ARRAY['en'::text, 'ar'::text, 'fr'::text])))
);


--
-- Name: trainer_application_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.trainer_application_snapshots (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    trainer_id uuid NOT NULL,
    submitted_at timestamp with time zone DEFAULT now() NOT NULL,
    full_name text NOT NULL,
    email public.citext NOT NULL,
    phone text,
    country text,
    location text,
    education text,
    languages text,
    specialty text,
    availability text,
    experience text,
    bio text,
    cv_storage_path text,
    certificate_storage_paths text[],
    photo_storage_path text,
    consent_given boolean NOT NULL,
    consent_text text NOT NULL
);


--
-- Name: TABLE trainer_application_snapshots; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.trainer_application_snapshots IS 'One immutable row per trainer application, written once by trainer-application.ts (the only insert policy that exists) and never updated or deleted by anyone thereafter - a permanent record of exactly what was submitted, independent of later self-service edits to trainers/people_translations.';


--
-- Name: training_academic_plans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_academic_plans (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_id uuid NOT NULL,
    version integer NOT NULL,
    learning_outcomes text NOT NULL,
    syllabus text NOT NULL,
    status_code text DEFAULT 'draft'::text NOT NULL,
    submitted_by uuid DEFAULT auth.uid(),
    submitted_at timestamp with time zone,
    decided_by uuid,
    decided_at timestamp with time zone,
    decision_note text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    passing_total_percent numeric(5,2) DEFAULT 60 NOT NULL,
    CONSTRAINT training_academic_plans_check CHECK ((((status_code = ANY (ARRAY['draft'::text, 'pending_approval'::text])) AND (decided_at IS NULL) AND (decided_by IS NULL)) OR ((status_code = ANY (ARRAY['approved'::text, 'rejected'::text, 'superseded'::text])) AND (decided_at IS NOT NULL) AND (decided_by IS NOT NULL)))),
    CONSTRAINT training_academic_plans_learning_outcomes_check CHECK ((length(btrim(learning_outcomes)) > 0)),
    CONSTRAINT training_academic_plans_passing_total_percent_check CHECK (((passing_total_percent > (0)::numeric) AND (passing_total_percent <= (100)::numeric))),
    CONSTRAINT training_academic_plans_status_code_check CHECK ((status_code = ANY (ARRAY['draft'::text, 'pending_approval'::text, 'approved'::text, 'rejected'::text, 'superseded'::text]))),
    CONSTRAINT training_academic_plans_syllabus_check CHECK ((length(btrim(syllabus)) > 0))
);


--
-- Name: training_assessment_grade_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_assessment_grade_history (
    id bigint NOT NULL,
    training_registration_id uuid CONSTRAINT training_assessment_grade_his_training_registration_id_not_null NOT NULL,
    assessment_id uuid NOT NULL,
    old_score_percent numeric(5,2),
    new_score_percent numeric(5,2),
    source text NOT NULL,
    note text,
    changed_by uuid,
    changed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT training_assessment_grade_history_source_check CHECK ((source = ANY (ARRAY['manual'::text, 'quiz'::text, 'tasks'::text, 'override'::text])))
);


--
-- Name: training_assessment_grade_history_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.training_assessment_grade_history ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.training_assessment_grade_history_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: training_assessment_grades; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_assessment_grades (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_registration_id uuid NOT NULL,
    assessment_id uuid NOT NULL,
    score_percent numeric(5,2) NOT NULL,
    feedback text,
    graded_by uuid DEFAULT auth.uid() NOT NULL,
    graded_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT training_assessment_grades_score_percent_check CHECK (((score_percent >= (0)::numeric) AND (score_percent <= (100)::numeric)))
);


--
-- Name: training_assessments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_assessments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    academic_plan_id uuid NOT NULL,
    assessment_type text NOT NULL,
    title text NOT NULL,
    description text,
    weight_percent numeric(5,2) NOT NULL,
    passing_percent numeric(5,2),
    sort_order integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT training_assessments_assessment_type_check CHECK ((assessment_type = ANY (ARRAY['quiz'::text, 'assignment'::text, 'midterm_exam'::text, 'final_exam'::text, 'practical'::text, 'participation'::text]))),
    CONSTRAINT training_assessments_passing_percent_check CHECK (((passing_percent >= (0)::numeric) AND (passing_percent <= (100)::numeric))),
    CONSTRAINT training_assessments_title_check CHECK (((length(btrim(title)) >= 1) AND (length(btrim(title)) <= 200))),
    CONSTRAINT training_assessments_weight_percent_check CHECK (((weight_percent > (0)::numeric) AND (weight_percent <= (100)::numeric)))
);


--
-- Name: training_assignments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_assignments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_id uuid NOT NULL,
    title text NOT NULL,
    instructions text,
    due_at timestamp with time zone,
    is_published boolean DEFAULT false NOT NULL,
    created_by uuid DEFAULT auth.uid(),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    task_type text DEFAULT 'assignment'::text NOT NULL,
    assessment_id uuid,
    max_marks numeric(8,2),
    is_grade_only boolean DEFAULT false NOT NULL,
    CONSTRAINT training_assignments_linked_max_marks CHECK (((assessment_id IS NULL) OR (max_marks IS NOT NULL))),
    CONSTRAINT training_assignments_max_marks_check CHECK (((max_marks > (0)::numeric) AND (max_marks <= (10000)::numeric))),
    CONSTRAINT training_assignments_task_type_check CHECK ((task_type = ANY (ARRAY['assignment'::text, 'midterm_exam'::text, 'final_exam'::text]))),
    CONSTRAINT training_assignments_title_check CHECK (((length(btrim(title)) >= 1) AND (length(btrim(title)) <= 200)))
);


--
-- Name: TABLE training_assignments; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.training_assignments IS 'A trainer-authored piece of work for their training, matching the training_materials draft/publish pattern (is_published) rather than a separate review workflow.';


--
-- Name: COLUMN training_assignments.task_type; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.training_assignments.task_type IS 'assignment, midterm_exam or final_exam; must equal the linked assessment''s type.';


--
-- Name: COLUMN training_assignments.assessment_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.training_assignments.assessment_id IS 'The approved-plan assessment this task counts towards (null = not counted in the Gradebook).';


--
-- Name: COLUMN training_assignments.max_marks; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.training_assignments.max_marks IS 'Maximum marks; locked once any trainee has a mark, zero or excused status.';


--
-- Name: COLUMN training_assignments.is_grade_only; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.training_assignments.is_grade_only IS 'A paper/in-class task: marked by the trainer, no online submission.';


--
-- Name: training_attendance; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_attendance (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_session_id uuid NOT NULL,
    training_registration_id uuid NOT NULL,
    attendance_status text DEFAULT 'present'::text NOT NULL,
    notes text,
    recorded_by uuid DEFAULT auth.uid(),
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT training_attendance_attendance_status_check CHECK ((attendance_status = ANY (ARRAY['present'::text, 'absent'::text, 'late'::text, 'excused'::text])))
);


--
-- Name: training_certificate_number_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.training_certificate_number_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: training_certificate_reissue_authorizations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_certificate_reissue_authorizations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_registration_id uuid CONSTRAINT training_certificate_reissue__training_registration_id_not_null NOT NULL,
    revoked_certificate_id uuid CONSTRAINT training_certificate_reissue_au_revoked_certificate_id_not_null NOT NULL,
    authorized_by uuid DEFAULT auth.uid(),
    authorized_at timestamp with time zone DEFAULT now() CONSTRAINT training_certificate_reissue_authorizati_authorized_at_not_null NOT NULL,
    reason text NOT NULL,
    consumed_at timestamp with time zone,
    consumed_certificate_id uuid,
    CONSTRAINT training_certificate_reissue_authorizations_check CHECK (((consumed_at IS NULL) = (consumed_certificate_id IS NULL))),
    CONSTRAINT training_certificate_reissue_authorizations_reason_check CHECK ((length(btrim(reason)) > 0))
);


--
-- Name: TABLE training_certificate_reissue_authorizations; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.training_certificate_reissue_authorizations IS 'One row per authorized reissue attempt, tied to the specific revoked certificate it follows. get-certificate.ts consumes the most recent unconsumed row for a registration exactly once, then refuses further reissue until a training.manage account authorizes another one - revocation stays meaningful instead of being undone by the trainee simply asking again.';


--
-- Name: training_certificates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_certificates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_registration_id uuid NOT NULL,
    storage_path text NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    certificate_number text DEFAULT ((('USL-'::text || to_char(now(), 'YYYY'::text)) || '-'::text) || lpad((nextval('public.training_certificate_number_seq'::regclass))::text, 6, '0'::text)) NOT NULL,
    verification_token uuid DEFAULT gen_random_uuid() NOT NULL,
    revoked_at timestamp with time zone,
    revoked_reason text,
    replaces_certificate_id uuid,
    completion_snapshot jsonb,
    CONSTRAINT training_certificates_revoked_reason_check CHECK (((revoked_reason IS NULL) OR (revoked_at IS NOT NULL)))
);


--
-- Name: TABLE training_certificates; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.training_certificates IS 'One row per issued certificate PDF, keyed to the registration it was generated for. Eligibility (approved, fee settled, training actually finished) is re-checked by get-certificate.ts on every request, not just at issuance time - this table only caches the generated file so it is not regenerated on every view.';


--
-- Name: COLUMN training_certificates.certificate_number; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.training_certificates.certificate_number IS 'Human-readable, printed on the certificate and safe to quote/cite - not the verification lookup key (that is verification_token), so guessing a nearby number does not let anyone look up someone else''s certificate.';


--
-- Name: COLUMN training_certificates.verification_token; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.training_certificates.verification_token IS 'Unguessable (122-bit) key used only by verify_certificate() below - embedded as a link/QR on the certificate PDF, never displayed as text a human would casually type.';


--
-- Name: COLUMN training_certificates.completion_snapshot; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.training_certificates.completion_snapshot IS 'A snapshot, at issuance time, of the ad-hoc eligibility checks get-certificate.ts actually ran (approved, fee settled, training ended, completion_status_code) - training_completion_rules does not exist yet, so this is what "explain the decision from stored data" means until it does. Null for certificates issued before this column existed.';


--
-- Name: training_charges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_charges (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_registration_id uuid NOT NULL,
    amount_minor_units bigint NOT NULL,
    currency_code text NOT NULL,
    receipt_number text,
    receipt_storage_path text,
    receipt_issued_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    receipt_type text,
    receipt_checksum text,
    CONSTRAINT training_charges_amount_minor_units_check CHECK ((amount_minor_units > 0)),
    CONSTRAINT training_charges_receipt_type_check CHECK ((receipt_type = ANY (ARRAY['receipt'::text, 'waiver_confirmation'::text])))
);


--
-- Name: TABLE training_charges; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.training_charges IS 'One immutable charge snapshot per fee-bearing approved registration, created automatically (create_training_charge_on_approval) at the amount/currency on trainings when the registration was approved - never edited afterward, so a later fee change on the training does not retroactively alter an already-issued charge. receipt_number/receipt_storage_path/receipt_issued_at are populated once decide_payment_transaction() verifies enough training_fee_transactions to clear it.';


--
-- Name: COLUMN training_charges.receipt_type; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.training_charges.receipt_type IS 'Set alongside receipt_number at the moment a charge clears (decide_payment_transaction()) - ''waiver_confirmation'' only when every verified transaction covering the charge has method = ''waiver'' (no real money moved); ''receipt'' otherwise, including a mix of a waiver and a real payment. Null until the charge actually clears, same as receipt_number.';


--
-- Name: COLUMN training_charges.receipt_checksum; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.training_charges.receipt_checksum IS 'SHA-256 hex digest of the generated receipt/waiver-confirmation PDF bytes, computed once by get-receipt.ts at the same moment receipt_storage_path is set - lets anyone holding a copy of the PDF verify it matches what this system actually issued.';


--
-- Name: training_completion_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_completion_rules (
    training_id uuid NOT NULL,
    min_attendance_percent integer,
    require_assignments boolean DEFAULT false NOT NULL,
    require_passing_grade boolean DEFAULT false NOT NULL,
    require_financial_clearance boolean DEFAULT true NOT NULL,
    require_manager_approval boolean DEFAULT false NOT NULL,
    created_by uuid DEFAULT auth.uid(),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT training_completion_rules_min_attendance_percent_check CHECK (((min_attendance_percent >= 0) AND (min_attendance_percent <= 100)))
);


--
-- Name: TABLE training_completion_rules; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.training_completion_rules IS 'What "completed" requires for one training, checked by training_completion_eligibility() and enforced by decide_training_completion(). A missing row means no attendance/assignment/grade requirement and financial clearance still required - the same bar get-certificate.ts always enforced before this table existed.';


--
-- Name: training_feedback; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_feedback (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_registration_id uuid NOT NULL,
    rating smallint NOT NULL,
    comments text,
    submitted_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT training_feedback_rating_check CHECK (((rating >= 1) AND (rating <= 5)))
);


--
-- Name: training_final_grades; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_final_grades (
    training_registration_id uuid NOT NULL,
    academic_plan_id uuid NOT NULL,
    total_percent numeric(5,2) NOT NULL,
    status_code text DEFAULT 'draft'::text NOT NULL,
    submitted_by uuid,
    submitted_at timestamp with time zone,
    approved_by uuid,
    approved_at timestamp with time zone,
    decision_note text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT training_final_grades_check CHECK ((((status_code = ANY (ARRAY['draft'::text, 'submitted'::text])) AND (approved_at IS NULL) AND (approved_by IS NULL)) OR ((status_code = ANY (ARRAY['approved'::text, 'rejected'::text])) AND (approved_at IS NOT NULL) AND (approved_by IS NOT NULL)))),
    CONSTRAINT training_final_grades_status_code_check CHECK ((status_code = ANY (ARRAY['draft'::text, 'submitted'::text, 'approved'::text, 'rejected'::text]))),
    CONSTRAINT training_final_grades_total_percent_check CHECK (((total_percent >= (0)::numeric) AND (total_percent <= (100)::numeric)))
);


--
-- Name: training_materials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_materials (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_id uuid NOT NULL,
    title text NOT NULL,
    resource_url text,
    material_type text DEFAULT 'resource'::text NOT NULL,
    is_published boolean DEFAULT false NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    created_by uuid DEFAULT auth.uid(),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    storage_path text,
    CONSTRAINT training_materials_material_type_check CHECK ((material_type = ANY (ARRAY['resource'::text, 'slides'::text, 'worksheet'::text, 'video'::text, 'assessment'::text, 'reading'::text]))),
    CONSTRAINT training_materials_one_source CHECK (((resource_url IS NOT NULL) <> (storage_path IS NOT NULL))),
    CONSTRAINT training_materials_resource_url_check CHECK ((resource_url ~* '^https://'::text)),
    CONSTRAINT training_materials_storage_path_own_training CHECK (((storage_path IS NULL) OR ((storage_path ~~ ((training_id)::text || '/%'::text)) AND (POSITION(('..'::text) IN (storage_path)) = 0)))),
    CONSTRAINT training_materials_title_check CHECK (((length(btrim(title)) >= 1) AND (length(btrim(title)) <= 200)))
);


--
-- Name: training_prerequisite_decisions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_prerequisite_decisions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_registration_id uuid CONSTRAINT training_prerequisite_decisio_training_registration_id_not_null NOT NULL,
    prerequisite_id uuid NOT NULL,
    decision_code text NOT NULL,
    recommendation_text text,
    reviewed_by uuid,
    requested_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    reviewed_at timestamp with time zone,
    CONSTRAINT training_prerequisite_decisions_decision_code_check CHECK ((decision_code = ANY (ARRAY['met'::text, 'not_met'::text, 'review_required'::text, 'waived'::text, 'rejected'::text])))
);


--
-- Name: TABLE training_prerequisite_decisions; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.training_prerequisite_decisions IS 'Stores trainer or manager recommendations and final decisions for prerequisites that need human review.';


--
-- Name: training_prerequisite_evidence; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_prerequisite_evidence (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_registration_id uuid CONSTRAINT training_prerequisite_evidenc_training_registration_id_not_null NOT NULL,
    prerequisite_id uuid NOT NULL,
    evidence_type text NOT NULL,
    evidence_url text,
    evidence_note text,
    submitted_by uuid,
    status_code text DEFAULT 'pending'::text NOT NULL,
    reviewed_by uuid,
    reviewed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT training_prerequisite_evidence_evidence_type_check CHECK ((evidence_type = ANY (ARRAY['certificate'::text, 'document'::text, 'statement'::text, 'recommendation'::text, 'other'::text]))),
    CONSTRAINT training_prerequisite_evidence_status_code_check CHECK ((status_code = ANY (ARRAY['pending'::text, 'accepted'::text, 'rejected'::text, 'needs_more_info'::text])))
);


--
-- Name: TABLE training_prerequisite_evidence; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.training_prerequisite_evidence IS 'Stores the evidence a trainee submitted to satisfy a prerequisite requirement.';


--
-- Name: training_prerequisites; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_prerequisites (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_id uuid NOT NULL,
    label text NOT NULL,
    description text,
    requirement_type text NOT NULL,
    source_training_id uuid,
    required boolean DEFAULT true NOT NULL,
    auto_verifiable boolean DEFAULT false NOT NULL,
    needs_evidence boolean DEFAULT false NOT NULL,
    needs_recommendation boolean DEFAULT false NOT NULL,
    requires_manager_decision boolean DEFAULT false NOT NULL,
    active boolean DEFAULT true NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT training_prerequisites_check CHECK ((((requirement_type = 'course'::text) AND (source_training_id IS NOT NULL)) OR (requirement_type <> 'course'::text))),
    CONSTRAINT training_prerequisites_requirement_type_check CHECK ((requirement_type = ANY (ARRAY['course'::text, 'role'::text, 'document'::text, 'manual'::text, 'custom'::text])))
);


--
-- Name: TABLE training_prerequisites; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.training_prerequisites IS 'Defines flexible prerequisite requirements for a training. This can capture prior courses, evidence, recommendations, or manager review without hard-coding a single linear model.';


--
-- Name: training_public_number_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.training_public_number_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: training_public_number_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.training_public_number_seq OWNED BY public.trainings.public_number;


--
-- Name: training_question_bank_questions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_question_bank_questions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    question_bank_id uuid NOT NULL,
    question_type text NOT NULL,
    prompt text NOT NULL,
    choices jsonb DEFAULT '[]'::jsonb NOT NULL,
    correct_answer jsonb NOT NULL,
    explanation text,
    default_points numeric(7,2) DEFAULT 1 NOT NULL,
    category text,
    archived_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    numerical_tolerance numeric(12,6) DEFAULT 0 NOT NULL,
    CONSTRAINT training_question_bank_questions_choices_check CHECK ((jsonb_typeof(choices) = 'array'::text)),
    CONSTRAINT training_question_bank_questions_correct_answer_check CHECK ((jsonb_typeof(correct_answer) = ANY (ARRAY['array'::text, 'object'::text, 'string'::text, 'number'::text, 'boolean'::text]))),
    CONSTRAINT training_question_bank_questions_default_points_check CHECK (((default_points > (0)::numeric) AND (default_points <= (10000)::numeric))),
    CONSTRAINT training_question_bank_questions_numerical_tolerance_check CHECK (((numerical_tolerance >= (0)::numeric) AND (numerical_tolerance <= (1000000)::numeric))),
    CONSTRAINT training_question_bank_questions_prompt_check CHECK (((length(btrim(prompt)) >= 1) AND (length(btrim(prompt)) <= 10000))),
    CONSTRAINT training_question_bank_questions_question_type_check CHECK ((question_type = ANY (ARRAY['multiple_choice'::text, 'true_false'::text, 'numerical'::text, 'short_answer'::text, 'matching'::text, 'essay'::text])))
);


--
-- Name: training_question_banks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_question_banks (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    owner_id uuid DEFAULT auth.uid() NOT NULL,
    title text NOT NULL,
    description text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT training_question_banks_title_check CHECK (((length(btrim(title)) >= 1) AND (length(btrim(title)) <= 160)))
);


--
-- Name: training_quiz_accommodations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_quiz_accommodations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    quiz_id uuid NOT NULL,
    training_registration_id uuid NOT NULL,
    extra_minutes integer DEFAULT 0 NOT NULL,
    closes_at_override timestamp with time zone,
    reason text NOT NULL,
    created_by uuid DEFAULT auth.uid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT training_quiz_accommodations_extra_minutes_check CHECK (((extra_minutes >= 0) AND (extra_minutes <= 1440))),
    CONSTRAINT training_quiz_accommodations_reason_check CHECK (((length(btrim(reason)) >= 3) AND (length(btrim(reason)) <= 1000)))
);


--
-- Name: training_quiz_answers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_quiz_answers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    quiz_attempt_id uuid NOT NULL,
    quiz_question_id uuid NOT NULL,
    response jsonb NOT NULL,
    is_correct boolean,
    awarded_points numeric(7,2),
    grader_feedback text,
    graded_by uuid,
    graded_at timestamp with time zone,
    answered_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: training_quiz_grade_overrides; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_quiz_grade_overrides (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    quiz_id uuid NOT NULL,
    training_registration_id uuid NOT NULL,
    score_percent numeric(5,2) NOT NULL,
    reason text NOT NULL,
    overridden_by uuid DEFAULT auth.uid() NOT NULL,
    overridden_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT training_quiz_grade_overrides_reason_check CHECK (((length(btrim(reason)) >= 3) AND (length(btrim(reason)) <= 2000))),
    CONSTRAINT training_quiz_grade_overrides_score_percent_check CHECK (((score_percent >= (0)::numeric) AND (score_percent <= (100)::numeric)))
);


--
-- Name: training_quiz_question_adjustments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_quiz_question_adjustments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    quiz_question_id uuid NOT NULL,
    adjustment_type text NOT NULL,
    reason text NOT NULL,
    decided_by uuid DEFAULT auth.uid() NOT NULL,
    decided_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT training_quiz_question_adjustments_adjustment_type_check CHECK ((adjustment_type = 'cancelled'::text)),
    CONSTRAINT training_quiz_question_adjustments_reason_check CHECK (((length(btrim(reason)) >= 3) AND (length(btrim(reason)) <= 2000)))
);


--
-- Name: training_quiz_questions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_quiz_questions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    quiz_id uuid NOT NULL,
    source_question_id uuid,
    question_type text NOT NULL,
    prompt text NOT NULL,
    choices jsonb DEFAULT '[]'::jsonb NOT NULL,
    correct_answer jsonb NOT NULL,
    points numeric(7,2) NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    numerical_tolerance numeric(12,6) DEFAULT 0 NOT NULL,
    CONSTRAINT training_quiz_questions_choices_check CHECK ((jsonb_typeof(choices) = 'array'::text)),
    CONSTRAINT training_quiz_questions_correct_answer_check CHECK ((jsonb_typeof(correct_answer) = ANY (ARRAY['array'::text, 'object'::text, 'string'::text, 'number'::text, 'boolean'::text]))),
    CONSTRAINT training_quiz_questions_numerical_tolerance_check CHECK (((numerical_tolerance >= (0)::numeric) AND (numerical_tolerance <= (1000000)::numeric))),
    CONSTRAINT training_quiz_questions_points_check CHECK (((points > (0)::numeric) AND (points <= (10000)::numeric))),
    CONSTRAINT training_quiz_questions_question_type_check CHECK ((question_type = ANY (ARRAY['multiple_choice'::text, 'true_false'::text, 'numerical'::text, 'short_answer'::text, 'matching'::text, 'essay'::text]))),
    CONSTRAINT training_quiz_questions_sort_order_check CHECK ((sort_order >= 0))
);


--
-- Name: training_receipt_number_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.training_receipt_number_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: training_registration_clearance; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.training_registration_clearance AS
 SELECT tr.id AS registration_id,
        CASE
            WHEN ((t.fee_amount_minor_units IS NULL) OR (t.fee_amount_minor_units <= 0)) THEN 'not_required'::text
            WHEN (tc.id IS NULL) THEN
            CASE
                WHEN tr.fee_paid THEN 'cleared'::text
                ELSE 'due'::text
            END
            WHEN ((COALESCE(verified.total, (0)::numeric) - COALESCE(refunded.total, (0)::numeric)) >= (tc.amount_minor_units)::numeric) THEN
            CASE
                WHEN (tc.receipt_type = 'waiver_confirmation'::text) THEN 'waived'::text
                ELSE 'cleared'::text
            END
            WHEN ((COALESCE(verified.total, (0)::numeric) - COALESCE(refunded.total, (0)::numeric)) > (0)::numeric) THEN 'partial'::text
            ELSE 'due'::text
        END AS clearance_state
   FROM ((((public.training_registrations tr
     JOIN public.trainings t ON ((t.id = tr.training_id)))
     LEFT JOIN public.training_charges tc ON ((tc.training_registration_id = tr.id)))
     LEFT JOIN LATERAL ( SELECT sum(training_fee_transactions.amount_minor_units) AS total
           FROM public.training_fee_transactions
          WHERE ((training_fee_transactions.training_charge_id = tc.id) AND (training_fee_transactions.status_code = 'verified'::text))) verified ON (true))
     LEFT JOIN LATERAL ( SELECT sum(training_fee_refunds.amount_minor_units) AS total
           FROM public.training_fee_refunds
          WHERE ((training_fee_refunds.training_charge_id = tc.id) AND (training_fee_refunds.status_code = 'approved'::text))) refunded ON (true))
  WHERE (public.current_user_is_trainer_for(tr.training_id) OR public.current_user_can_manage_trainings() OR public.current_user_has_permission('finance.read'::text) OR public.current_user_has_permission('finance.manage'::text) OR public.current_user_owns_training_registration(tr.id));


--
-- Name: VIEW training_registration_clearance; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON VIEW public.training_registration_clearance IS 'registration_id + clearance_state only (not_required/due/partial/cleared/waived) - no amount, method, proof or other financial detail. Readable by exactly the same parties who could already read the underlying training_registrations row (its own RLS policies), re-implemented in the WHERE clause here because a view runs as its owner, bypassing RLS, unless it re-checks itself - same "elevated read, narrow projection" pattern as finance_payment_queue.';


--
-- Name: training_registration_status_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_registration_status_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_registration_id uuid CONSTRAINT training_registration_status__training_registration_id_not_null NOT NULL,
    from_status text,
    to_status text NOT NULL,
    reason_code text,
    reason_note text,
    actor_user_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE training_registration_status_history; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.training_registration_status_history IS 'Immutable timeline of enrollment status transitions for auditing and governance.';


--
-- Name: training_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_id uuid NOT NULL,
    title text NOT NULL,
    starts_at timestamp with time zone NOT NULL,
    ends_at timestamp with time zone NOT NULL,
    delivery_mode text DEFAULT 'in_person'::text NOT NULL,
    location_or_link text,
    notes text,
    created_by uuid DEFAULT auth.uid(),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT training_sessions_check CHECK ((ends_at > starts_at)),
    CONSTRAINT training_sessions_delivery_mode_check CHECK ((delivery_mode = ANY (ARRAY['in_person'::text, 'online'::text, 'hybrid'::text]))),
    CONSTRAINT training_sessions_title_check CHECK (((length(btrim(title)) >= 1) AND (length(btrim(title)) <= 200)))
);


--
-- Name: training_submissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_submissions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_assignment_id uuid NOT NULL,
    training_registration_id uuid NOT NULL,
    content text,
    link_url text,
    status_code text DEFAULT 'submitted'::text NOT NULL,
    grade text,
    feedback text,
    submitted_at timestamp with time zone DEFAULT now() NOT NULL,
    graded_by uuid,
    graded_at timestamp with time zone,
    is_passing boolean,
    CONSTRAINT training_submissions_status_code_check CHECK ((status_code = ANY (ARRAY['submitted'::text, 'graded'::text, 'returned'::text])))
);


--
-- Name: TABLE training_submissions; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.training_submissions IS 'One row per trainee per assignment (enforced by the unique constraint) - a resubmission updates this row rather than creating a new one, so history is "was this ever returned for revision," not a growing pile of drafts. status_code: submitted (trainee-owned, editable) -> graded (trainer-owned, locked) or returned (trainer sends back, re-opens trainee editing).';


--
-- Name: COLUMN training_submissions.is_passing; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.training_submissions.is_passing IS 'Set by the grader alongside grade/feedback (enforce_submission_columns already restricts this whole row to the grader path) - null until graded. Distinct from grade itself: a numeric/letter grade is free text, this is the one bit training_completion_eligibility() actually reads.';


--
-- Name: training_task_assessment_overrides; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_task_assessment_overrides (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    assessment_id uuid NOT NULL,
    training_registration_id uuid CONSTRAINT training_task_assessment_over_training_registration_id_not_null NOT NULL,
    score_percent numeric(5,2) NOT NULL,
    reason text NOT NULL,
    overridden_by uuid DEFAULT auth.uid(),
    overridden_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT training_task_assessment_overrides_reason_check CHECK (((length(btrim(reason)) >= 3) AND (length(btrim(reason)) <= 2000))),
    CONSTRAINT training_task_assessment_overrides_score_percent_check CHECK (((score_percent >= (0)::numeric) AND (score_percent <= (100)::numeric)))
);


--
-- Name: training_task_mark_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_task_mark_history (
    id bigint NOT NULL,
    training_assignment_id uuid NOT NULL,
    training_registration_id uuid NOT NULL,
    old_status_code text,
    old_marks_earned numeric(8,2),
    new_status_code text,
    new_marks_earned numeric(8,2),
    excused_reason text,
    changed_by uuid,
    changed_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: training_task_mark_history_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.training_task_mark_history ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.training_task_mark_history_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: training_task_marks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_task_marks (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_assignment_id uuid NOT NULL,
    training_registration_id uuid NOT NULL,
    status_code text NOT NULL,
    marks_earned numeric(8,2),
    excused_reason text,
    feedback text,
    marked_by uuid DEFAULT auth.uid(),
    marked_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT training_task_marks_check CHECK ((((status_code = 'marked'::text) AND (marks_earned IS NOT NULL) AND (excused_reason IS NULL)) OR ((status_code = 'missing'::text) AND (marks_earned = (0)::numeric) AND (excused_reason IS NULL)) OR ((status_code = 'excused'::text) AND (marks_earned IS NULL) AND ((length(btrim(excused_reason)) >= 3) AND (length(btrim(excused_reason)) <= 2000))))),
    CONSTRAINT training_task_marks_feedback_check CHECK (((feedback IS NULL) OR (length(feedback) <= 5000))),
    CONSTRAINT training_task_marks_marks_earned_check CHECK ((marks_earned >= (0)::numeric)),
    CONSTRAINT training_task_marks_status_code_check CHECK ((status_code = ANY (ARRAY['marked'::text, 'missing'::text, 'excused'::text])))
);


--
-- Name: TABLE training_task_marks; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.training_task_marks IS 'One mark per trainee per linked task: marked (numeric), missing (not submitted, counts as 0) or excused (left out of both sums). Written only by record_training_task_mark().';


--
-- Name: training_waitlist_entries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.training_waitlist_entries (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    training_id uuid NOT NULL,
    training_registration_id uuid NOT NULL,
    queue_position integer NOT NULL,
    status_code text DEFAULT 'active'::text NOT NULL,
    offered_at timestamp with time zone,
    offer_expires_at timestamp with time zone,
    accepted_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT training_waitlist_entries_status_code_check CHECK ((status_code = ANY (ARRAY['active'::text, 'offered'::text, 'accepted'::text, 'expired'::text, 'cancelled'::text])))
);


--
-- Name: TABLE training_waitlist_entries; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.training_waitlist_entries IS 'Waitlist queue and offer state for a training with limited capacity.';


--
-- Name: training_waiver_confirmation_number_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.training_waiver_confirmation_number_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: user_invitations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_invitations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email public.citext NOT NULL,
    person_id uuid,
    role_code text,
    invited_by uuid,
    token text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    accepted_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: user_profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_profiles (
    user_id uuid NOT NULL,
    person_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    invite_last_sent_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: COLUMN user_profiles.invite_last_sent_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.user_profiles.invite_last_sent_at IS 'When this account''s activation invite email was last sent (initial approval, or a manual resend). Used only to rate-limit resend-registration-invitation.ts/resend-trainer-invitation.ts - not itself a security boundary.';


--
-- Name: user_role_assignments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_role_assignments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    role_code text NOT NULL,
    scope_type text,
    scope_id uuid,
    granted_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT user_role_assignments_scope_pair_check CHECK ((((scope_type IS NULL) AND (scope_id IS NULL)) OR ((scope_type IS NOT NULL) AND (scope_id IS NOT NULL)))),
    CONSTRAINT user_role_assignments_scope_type_check CHECK ((scope_type = ANY (ARRAY['program'::text, 'initiative'::text])))
);


--
-- Name: TABLE user_role_assignments; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.user_role_assignments IS 'A user holds a role either globally (scope_type/scope_id null) or scoped to one program or initiative.';


--
-- Name: verification_reviews; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.verification_reviews (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    indicator_observation_id uuid NOT NULL,
    reviewer_id uuid,
    outcome text NOT NULL,
    notes text,
    reviewed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT verification_reviews_outcome_check CHECK ((outcome = ANY (ARRAY['approved'::text, 'rejected'::text, 'needs_revision'::text])))
);


--
-- Name: verification_statuses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.verification_statuses (
    code text NOT NULL,
    label text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL
);


--
-- Name: attendance_records; Type: TABLE; Schema: restricted; Owner: -
--

CREATE TABLE restricted.attendance_records (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    enrollment_id uuid NOT NULL,
    session_date date NOT NULL,
    attended boolean NOT NULL
);


--
-- Name: beneficiary_records; Type: TABLE; Schema: restricted; Owner: -
--

CREATE TABLE restricted.beneficiary_records (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    participant_code text NOT NULL,
    full_name text,
    date_of_birth date,
    sex text,
    disability_status text,
    displacement_status text,
    site_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: guardian_relationships; Type: TABLE; Schema: restricted; Owner: -
--

CREATE TABLE restricted.guardian_relationships (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    beneficiary_id uuid NOT NULL,
    guardian_person_id uuid NOT NULL,
    relationship text NOT NULL
);


--
-- Name: participation_consents; Type: TABLE; Schema: restricted; Owner: -
--

CREATE TABLE restricted.participation_consents (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    beneficiary_id uuid NOT NULL,
    consent_type text NOT NULL,
    granted boolean NOT NULL,
    granted_by_person_id uuid,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT participation_consents_consent_type_check CHECK ((consent_type = ANY (ARRAY['program_participation'::text, 'photo_video'::text, 'assessment_data_sharing'::text])))
);


--
-- Name: program_enrollments; Type: TABLE; Schema: restricted; Owner: -
--

CREATE TABLE restricted.program_enrollments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    beneficiary_id uuid NOT NULL,
    cohort_id uuid NOT NULL,
    enrolled_on date DEFAULT CURRENT_DATE NOT NULL,
    exit_reason text,
    exited_on date
);


--
-- Name: referrals; Type: TABLE; Schema: restricted; Owner: -
--

CREATE TABLE restricted.referrals (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    beneficiary_id uuid NOT NULL,
    referral_type text NOT NULL,
    referred_to text,
    referred_by uuid,
    referred_at timestamp with time zone DEFAULT now() NOT NULL,
    response_at timestamp with time zone,
    outcome text
);


--
-- Name: app_modules app_modules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.app_modules
    ADD CONSTRAINT app_modules_pkey PRIMARY KEY (code);


--
-- Name: assessment_instruments assessment_instruments_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assessment_instruments
    ADD CONSTRAINT assessment_instruments_code_key UNIQUE (code);


--
-- Name: assessment_instruments assessment_instruments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assessment_instruments
    ADD CONSTRAINT assessment_instruments_pkey PRIMARY KEY (id);


--
-- Name: assessment_scores assessment_scores_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assessment_scores
    ADD CONSTRAINT assessment_scores_pkey PRIMARY KEY (id);


--
-- Name: assessment_sessions assessment_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assessment_sessions
    ADD CONSTRAINT assessment_sessions_pkey PRIMARY KEY (id);


--
-- Name: assignments assignments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assignments
    ADD CONSTRAINT assignments_pkey PRIMARY KEY (id);


--
-- Name: audit_log audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (id);


--
-- Name: cohorts cohorts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cohorts
    ADD CONSTRAINT cohorts_pkey PRIMARY KEY (id);


--
-- Name: consent_records consent_records_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.consent_records
    ADD CONSTRAINT consent_records_pkey PRIMARY KEY (id);


--
-- Name: contact_submissions contact_submissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contact_submissions
    ADD CONSTRAINT contact_submissions_pkey PRIMARY KEY (id);


--
-- Name: currencies currencies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.currencies
    ADD CONSTRAINT currencies_pkey PRIMARY KEY (code);


--
-- Name: data_quality_assessments data_quality_assessments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.data_quality_assessments
    ADD CONSTRAINT data_quality_assessments_pkey PRIMARY KEY (id);


--
-- Name: donation_allocations donation_allocations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.donation_allocations
    ADD CONSTRAINT donation_allocations_pkey PRIMARY KEY (id);


--
-- Name: donation_frequencies donation_frequencies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.donation_frequencies
    ADD CONSTRAINT donation_frequencies_pkey PRIMARY KEY (code);


--
-- Name: donation_intents donation_intents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.donation_intents
    ADD CONSTRAINT donation_intents_pkey PRIMARY KEY (id);


--
-- Name: donation_statuses donation_statuses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.donation_statuses
    ADD CONSTRAINT donation_statuses_pkey PRIMARY KEY (code);


--
-- Name: donations donations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.donations
    ADD CONSTRAINT donations_pkey PRIMARY KEY (id);


--
-- Name: evidence_artifacts evidence_artifacts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_artifacts
    ADD CONSTRAINT evidence_artifacts_pkey PRIMARY KEY (id);


--
-- Name: fund_types fund_types_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fund_types
    ADD CONSTRAINT fund_types_pkey PRIMARY KEY (code);


--
-- Name: funds funds_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.funds
    ADD CONSTRAINT funds_code_key UNIQUE (code);


--
-- Name: funds funds_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.funds
    ADD CONSTRAINT funds_pkey PRIMARY KEY (id);


--
-- Name: governance_appointments governance_appointments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.governance_appointments
    ADD CONSTRAINT governance_appointments_pkey PRIMARY KEY (id);


--
-- Name: governance_roles governance_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.governance_roles
    ADD CONSTRAINT governance_roles_pkey PRIMARY KEY (code);


--
-- Name: indicator_baselines indicator_baselines_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_baselines
    ADD CONSTRAINT indicator_baselines_pkey PRIMARY KEY (id);


--
-- Name: indicator_definitions indicator_definitions_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_definitions
    ADD CONSTRAINT indicator_definitions_code_key UNIQUE (code);


--
-- Name: indicator_definitions indicator_definitions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_definitions
    ADD CONSTRAINT indicator_definitions_pkey PRIMARY KEY (id);


--
-- Name: indicator_disaggregations indicator_disaggregations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_disaggregations
    ADD CONSTRAINT indicator_disaggregations_pkey PRIMARY KEY (id);


--
-- Name: indicator_observations indicator_observations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_observations
    ADD CONSTRAINT indicator_observations_pkey PRIMARY KEY (id);


--
-- Name: indicator_scopes indicator_scopes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_scopes
    ADD CONSTRAINT indicator_scopes_pkey PRIMARY KEY (id);


--
-- Name: indicator_targets indicator_targets_measurement_plan_id_reporting_period_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_targets
    ADD CONSTRAINT indicator_targets_measurement_plan_id_reporting_period_id_key UNIQUE (measurement_plan_id, reporting_period_id);


--
-- Name: indicator_targets indicator_targets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_targets
    ADD CONSTRAINT indicator_targets_pkey PRIMARY KEY (id);


--
-- Name: indicator_translations indicator_translations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_translations
    ADD CONSTRAINT indicator_translations_pkey PRIMARY KEY (indicator_definition_id, locale);


--
-- Name: indicator_versions indicator_versions_indicator_definition_id_version_number_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_versions
    ADD CONSTRAINT indicator_versions_indicator_definition_id_version_number_key UNIQUE (indicator_definition_id, version_number);


--
-- Name: indicator_versions indicator_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_versions
    ADD CONSTRAINT indicator_versions_pkey PRIMARY KEY (id);


--
-- Name: initiative_program_links initiative_program_links_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.initiative_program_links
    ADD CONSTRAINT initiative_program_links_pkey PRIMARY KEY (initiative_id, program_id);


--
-- Name: initiative_translations initiative_translations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.initiative_translations
    ADD CONSTRAINT initiative_translations_pkey PRIMARY KEY (initiative_id, locale);


--
-- Name: initiatives initiatives_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.initiatives
    ADD CONSTRAINT initiatives_pkey PRIMARY KEY (id);


--
-- Name: initiatives initiatives_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.initiatives
    ADD CONSTRAINT initiatives_slug_key UNIQUE (slug);


--
-- Name: instrument_versions instrument_versions_assessment_instrument_id_version_number_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.instrument_versions
    ADD CONSTRAINT instrument_versions_assessment_instrument_id_version_number_key UNIQUE (assessment_instrument_id, version_number);


--
-- Name: instrument_versions instrument_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.instrument_versions
    ADD CONSTRAINT instrument_versions_pkey PRIMARY KEY (id);


--
-- Name: internal_notes internal_notes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.internal_notes
    ADD CONSTRAINT internal_notes_pkey PRIMARY KEY (id);


--
-- Name: learning_actions learning_actions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.learning_actions
    ADD CONSTRAINT learning_actions_pkey PRIMARY KEY (id);


--
-- Name: measurement_plans measurement_plans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.measurement_plans
    ADD CONSTRAINT measurement_plans_pkey PRIMARY KEY (id);


--
-- Name: media_assets media_assets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.media_assets
    ADD CONSTRAINT media_assets_pkey PRIMARY KEY (id);


--
-- Name: membership_events membership_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.membership_events
    ADD CONSTRAINT membership_events_pkey PRIMARY KEY (id);


--
-- Name: membership_statuses membership_statuses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.membership_statuses
    ADD CONSTRAINT membership_statuses_pkey PRIMARY KEY (code);


--
-- Name: membership_types membership_types_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.membership_types
    ADD CONSTRAINT membership_types_pkey PRIMARY KEY (code);


--
-- Name: memberships memberships_membership_number_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.memberships
    ADD CONSTRAINT memberships_membership_number_key UNIQUE (membership_number);


--
-- Name: memberships memberships_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.memberships
    ADD CONSTRAINT memberships_pkey PRIMARY KEY (id);


--
-- Name: observation_breakdowns observation_breakdowns_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.observation_breakdowns
    ADD CONSTRAINT observation_breakdowns_pkey PRIMARY KEY (id);


--
-- Name: observation_rubrics observation_rubrics_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.observation_rubrics
    ADD CONSTRAINT observation_rubrics_code_key UNIQUE (code);


--
-- Name: observation_rubrics observation_rubrics_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.observation_rubrics
    ADD CONSTRAINT observation_rubrics_pkey PRIMARY KEY (id);


--
-- Name: organization_types organization_types_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_types
    ADD CONSTRAINT organization_types_pkey PRIMARY KEY (code);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);


--
-- Name: partner_relationships partner_relationships_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.partner_relationships
    ADD CONSTRAINT partner_relationships_pkey PRIMARY KEY (id);


--
-- Name: partner_roles partner_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.partner_roles
    ADD CONSTRAINT partner_roles_pkey PRIMARY KEY (code);


--
-- Name: partnership_inquiries partnership_inquiries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.partnership_inquiries
    ADD CONSTRAINT partnership_inquiries_pkey PRIMARY KEY (id);


--
-- Name: payment_customers payment_customers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_customers
    ADD CONSTRAINT payment_customers_pkey PRIMARY KEY (id);


--
-- Name: payment_customers payment_customers_provider_code_provider_customer_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_customers
    ADD CONSTRAINT payment_customers_provider_code_provider_customer_id_key UNIQUE (provider_code, provider_customer_id);


--
-- Name: payment_events payment_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_events
    ADD CONSTRAINT payment_events_pkey PRIMARY KEY (id);


--
-- Name: payment_events payment_events_provider_code_provider_event_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_events
    ADD CONSTRAINT payment_events_provider_code_provider_event_id_key UNIQUE (provider_code, provider_event_id);


--
-- Name: payment_providers payment_providers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_providers
    ADD CONSTRAINT payment_providers_pkey PRIMARY KEY (code);


--
-- Name: payment_records payment_records_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_records
    ADD CONSTRAINT payment_records_pkey PRIMARY KEY (id);


--
-- Name: payment_transaction_statuses payment_transaction_statuses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_transaction_statuses
    ADD CONSTRAINT payment_transaction_statuses_pkey PRIMARY KEY (code);


--
-- Name: payment_transactions payment_transactions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_transactions
    ADD CONSTRAINT payment_transactions_pkey PRIMARY KEY (id);


--
-- Name: payment_transactions payment_transactions_provider_code_provider_transaction_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_transactions
    ADD CONSTRAINT payment_transactions_provider_code_provider_transaction_id_key UNIQUE (provider_code, provider_transaction_id);


--
-- Name: people people_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.people
    ADD CONSTRAINT people_pkey PRIMARY KEY (id);


--
-- Name: people people_public_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.people
    ADD CONSTRAINT people_public_slug_key UNIQUE (public_slug);


--
-- Name: people_translations people_translations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.people_translations
    ADD CONSTRAINT people_translations_pkey PRIMARY KEY (person_id, locale);


--
-- Name: permissions permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_pkey PRIMARY KEY (code);


--
-- Name: person_accessibility_requests person_accessibility_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.person_accessibility_requests
    ADD CONSTRAINT person_accessibility_requests_pkey PRIMARY KEY (id);


--
-- Name: person_consent_records person_consent_records_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.person_consent_records
    ADD CONSTRAINT person_consent_records_pkey PRIMARY KEY (id);


--
-- Name: person_emergency_contacts person_emergency_contacts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.person_emergency_contacts
    ADD CONSTRAINT person_emergency_contacts_pkey PRIMARY KEY (id);


--
-- Name: person_guardian_relationships person_guardian_relationships_guardian_person_id_dependent__key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.person_guardian_relationships
    ADD CONSTRAINT person_guardian_relationships_guardian_person_id_dependent__key UNIQUE (guardian_person_id, dependent_person_id);


--
-- Name: person_guardian_relationships person_guardian_relationships_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.person_guardian_relationships
    ADD CONSTRAINT person_guardian_relationships_pkey PRIMARY KEY (id);


--
-- Name: professional_credentials professional_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.professional_credentials
    ADD CONSTRAINT professional_credentials_pkey PRIMARY KEY (id);


--
-- Name: profile_documents profile_documents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.profile_documents
    ADD CONSTRAINT profile_documents_pkey PRIMARY KEY (id);


--
-- Name: program_activities program_activities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.program_activities
    ADD CONSTRAINT program_activities_pkey PRIMARY KEY (id);


--
-- Name: program_cycles program_cycles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.program_cycles
    ADD CONSTRAINT program_cycles_pkey PRIMARY KEY (id);


--
-- Name: program_indicators program_indicators_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.program_indicators
    ADD CONSTRAINT program_indicators_pkey PRIMARY KEY (id);


--
-- Name: program_statuses program_statuses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.program_statuses
    ADD CONSTRAINT program_statuses_pkey PRIMARY KEY (code);


--
-- Name: program_translations program_translations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.program_translations
    ADD CONSTRAINT program_translations_pkey PRIMARY KEY (program_id, locale);


--
-- Name: programs programs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.programs
    ADD CONSTRAINT programs_pkey PRIMARY KEY (id);


--
-- Name: programs programs_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.programs
    ADD CONSTRAINT programs_slug_key UNIQUE (slug);


--
-- Name: publication_approvals publication_approvals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.publication_approvals
    ADD CONSTRAINT publication_approvals_pkey PRIMARY KEY (id);


--
-- Name: publication_snapshots publication_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.publication_snapshots
    ADD CONSTRAINT publication_snapshots_pkey PRIMARY KEY (id);


--
-- Name: publication_statuses publication_statuses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.publication_statuses
    ADD CONSTRAINT publication_statuses_pkey PRIMARY KEY (code);


--
-- Name: receipt_deliveries receipt_deliveries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.receipt_deliveries
    ADD CONSTRAINT receipt_deliveries_pkey PRIMARY KEY (id);


--
-- Name: receipt_delivery_statuses receipt_delivery_statuses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.receipt_delivery_statuses
    ADD CONSTRAINT receipt_delivery_statuses_pkey PRIMARY KEY (code);


--
-- Name: receipts receipts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.receipts
    ADD CONSTRAINT receipts_pkey PRIMARY KEY (id);


--
-- Name: receipts receipts_receipt_number_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.receipts
    ADD CONSTRAINT receipts_receipt_number_key UNIQUE (receipt_number);


--
-- Name: recurring_agreements recurring_agreements_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recurring_agreements
    ADD CONSTRAINT recurring_agreements_pkey PRIMARY KEY (id);


--
-- Name: recurring_agreements recurring_agreements_provider_code_provider_subscription_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recurring_agreements
    ADD CONSTRAINT recurring_agreements_provider_code_provider_subscription_id_key UNIQUE (provider_code, provider_subscription_id);


--
-- Name: refunds refunds_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refunds
    ADD CONSTRAINT refunds_pkey PRIMARY KEY (id);


--
-- Name: reporting_periods reporting_periods_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reporting_periods
    ADD CONSTRAINT reporting_periods_pkey PRIMARY KEY (id);


--
-- Name: resource_translations resource_translations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_translations
    ADD CONSTRAINT resource_translations_pkey PRIMARY KEY (resource_id, locale);


--
-- Name: resources resources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resources
    ADD CONSTRAINT resources_pkey PRIMARY KEY (id);


--
-- Name: resources resources_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resources
    ADD CONSTRAINT resources_slug_key UNIQUE (slug);


--
-- Name: result_levels result_levels_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.result_levels
    ADD CONSTRAINT result_levels_pkey PRIMARY KEY (code);


--
-- Name: result_links result_links_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.result_links
    ADD CONSTRAINT result_links_pkey PRIMARY KEY (id);


--
-- Name: result_node_translations result_node_translations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.result_node_translations
    ADD CONSTRAINT result_node_translations_pkey PRIMARY KEY (result_node_id, locale);


--
-- Name: result_nodes result_nodes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.result_nodes
    ADD CONSTRAINT result_nodes_pkey PRIMARY KEY (id);


--
-- Name: result_nodes result_nodes_program_id_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.result_nodes
    ADD CONSTRAINT result_nodes_program_id_code_key UNIQUE (program_id, code);


--
-- Name: role_permissions role_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_pkey PRIMARY KEY (role_code, permission_code);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (code);


--
-- Name: security_events security_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_events
    ADD CONSTRAINT security_events_pkey PRIMARY KEY (id);


--
-- Name: sites sites_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sites
    ADD CONSTRAINT sites_pkey PRIMARY KEY (id);


--
-- Name: submission_status_history submission_status_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.submission_status_history
    ADD CONSTRAINT submission_status_history_pkey PRIMARY KEY (id);


--
-- Name: submission_statuses submission_statuses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.submission_statuses
    ADD CONSTRAINT submission_statuses_pkey PRIMARY KEY (code);


--
-- Name: support_item_fulfillments support_item_fulfillments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.support_item_fulfillments
    ADD CONSTRAINT support_item_fulfillments_pkey PRIMARY KEY (id);


--
-- Name: support_item_translations support_item_translations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.support_item_translations
    ADD CONSTRAINT support_item_translations_pkey PRIMARY KEY (support_item_id, locale);


--
-- Name: support_items support_items_initiative_id_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.support_items
    ADD CONSTRAINT support_items_initiative_id_slug_key UNIQUE (initiative_id, slug);


--
-- Name: support_items support_items_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.support_items
    ADD CONSTRAINT support_items_pkey PRIMARY KEY (id);


--
-- Name: survey_responses survey_responses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.survey_responses
    ADD CONSTRAINT survey_responses_pkey PRIMARY KEY (id);


--
-- Name: theories_of_change theories_of_change_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.theories_of_change
    ADD CONSTRAINT theories_of_change_pkey PRIMARY KEY (id);


--
-- Name: trainer_application_snapshots trainer_application_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trainer_application_snapshots
    ADD CONSTRAINT trainer_application_snapshots_pkey PRIMARY KEY (id);


--
-- Name: trainers trainers_person_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trainers
    ADD CONSTRAINT trainers_person_id_key UNIQUE (person_id);


--
-- Name: trainers trainers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trainers
    ADD CONSTRAINT trainers_pkey PRIMARY KEY (id);


--
-- Name: training_academic_plans training_academic_plans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_academic_plans
    ADD CONSTRAINT training_academic_plans_pkey PRIMARY KEY (id);


--
-- Name: training_academic_plans training_academic_plans_training_id_version_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_academic_plans
    ADD CONSTRAINT training_academic_plans_training_id_version_key UNIQUE (training_id, version);


--
-- Name: training_assessment_grade_history training_assessment_grade_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_assessment_grade_history
    ADD CONSTRAINT training_assessment_grade_history_pkey PRIMARY KEY (id);


--
-- Name: training_assessment_grades training_assessment_grades_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_assessment_grades
    ADD CONSTRAINT training_assessment_grades_pkey PRIMARY KEY (id);


--
-- Name: training_assessment_grades training_assessment_grades_training_registration_id_assessm_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_assessment_grades
    ADD CONSTRAINT training_assessment_grades_training_registration_id_assessm_key UNIQUE (training_registration_id, assessment_id);


--
-- Name: training_assessments training_assessments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_assessments
    ADD CONSTRAINT training_assessments_pkey PRIMARY KEY (id);


--
-- Name: training_assignments training_assignments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_assignments
    ADD CONSTRAINT training_assignments_pkey PRIMARY KEY (id);


--
-- Name: training_attendance training_attendance_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_attendance
    ADD CONSTRAINT training_attendance_pkey PRIMARY KEY (id);


--
-- Name: training_attendance training_attendance_training_session_id_training_registrati_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_attendance
    ADD CONSTRAINT training_attendance_training_session_id_training_registrati_key UNIQUE (training_session_id, training_registration_id);


--
-- Name: training_certificate_reissue_authorizations training_certificate_reissue_authorizations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_certificate_reissue_authorizations
    ADD CONSTRAINT training_certificate_reissue_authorizations_pkey PRIMARY KEY (id);


--
-- Name: training_certificates training_certificates_certificate_number_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_certificates
    ADD CONSTRAINT training_certificates_certificate_number_key UNIQUE (certificate_number);


--
-- Name: training_certificates training_certificates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_certificates
    ADD CONSTRAINT training_certificates_pkey PRIMARY KEY (id);


--
-- Name: training_certificates training_certificates_verification_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_certificates
    ADD CONSTRAINT training_certificates_verification_token_key UNIQUE (verification_token);


--
-- Name: training_charges training_charges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_charges
    ADD CONSTRAINT training_charges_pkey PRIMARY KEY (id);


--
-- Name: training_charges training_charges_receipt_number_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_charges
    ADD CONSTRAINT training_charges_receipt_number_key UNIQUE (receipt_number);


--
-- Name: training_charges training_charges_training_registration_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_charges
    ADD CONSTRAINT training_charges_training_registration_id_key UNIQUE (training_registration_id);


--
-- Name: training_completion_rules training_completion_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_completion_rules
    ADD CONSTRAINT training_completion_rules_pkey PRIMARY KEY (training_id);


--
-- Name: training_fee_access_exceptions training_fee_access_exceptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_fee_access_exceptions
    ADD CONSTRAINT training_fee_access_exceptions_pkey PRIMARY KEY (id);


--
-- Name: training_fee_proof_submissions training_fee_proof_submissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_fee_proof_submissions
    ADD CONSTRAINT training_fee_proof_submissions_pkey PRIMARY KEY (id);


--
-- Name: training_fee_refunds training_fee_refunds_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_fee_refunds
    ADD CONSTRAINT training_fee_refunds_pkey PRIMARY KEY (id);


--
-- Name: training_fee_transactions training_fee_transactions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_fee_transactions
    ADD CONSTRAINT training_fee_transactions_pkey PRIMARY KEY (id);


--
-- Name: training_feedback training_feedback_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_feedback
    ADD CONSTRAINT training_feedback_pkey PRIMARY KEY (id);


--
-- Name: training_feedback training_feedback_training_registration_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_feedback
    ADD CONSTRAINT training_feedback_training_registration_id_key UNIQUE (training_registration_id);


--
-- Name: training_final_grades training_final_grades_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_final_grades
    ADD CONSTRAINT training_final_grades_pkey PRIMARY KEY (training_registration_id);


--
-- Name: training_materials training_materials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_materials
    ADD CONSTRAINT training_materials_pkey PRIMARY KEY (id);


--
-- Name: training_prerequisite_decisions training_prerequisite_decisio_training_registration_id_prer_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_prerequisite_decisions
    ADD CONSTRAINT training_prerequisite_decisio_training_registration_id_prer_key UNIQUE (training_registration_id, prerequisite_id);


--
-- Name: training_prerequisite_decisions training_prerequisite_decisions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_prerequisite_decisions
    ADD CONSTRAINT training_prerequisite_decisions_pkey PRIMARY KEY (id);


--
-- Name: training_prerequisite_evidence training_prerequisite_evidenc_training_registration_id_prer_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_prerequisite_evidence
    ADD CONSTRAINT training_prerequisite_evidenc_training_registration_id_prer_key UNIQUE (training_registration_id, prerequisite_id, evidence_type);


--
-- Name: training_prerequisite_evidence training_prerequisite_evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_prerequisite_evidence
    ADD CONSTRAINT training_prerequisite_evidence_pkey PRIMARY KEY (id);


--
-- Name: training_prerequisites training_prerequisites_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_prerequisites
    ADD CONSTRAINT training_prerequisites_pkey PRIMARY KEY (id);


--
-- Name: training_prerequisites training_prerequisites_training_id_label_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_prerequisites
    ADD CONSTRAINT training_prerequisites_training_id_label_key UNIQUE (training_id, label);


--
-- Name: training_question_bank_questions training_question_bank_questions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_question_bank_questions
    ADD CONSTRAINT training_question_bank_questions_pkey PRIMARY KEY (id);


--
-- Name: training_question_banks training_question_banks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_question_banks
    ADD CONSTRAINT training_question_banks_pkey PRIMARY KEY (id);


--
-- Name: training_quiz_accommodations training_quiz_accommodations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_accommodations
    ADD CONSTRAINT training_quiz_accommodations_pkey PRIMARY KEY (id);


--
-- Name: training_quiz_accommodations training_quiz_accommodations_quiz_id_training_registration__key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_accommodations
    ADD CONSTRAINT training_quiz_accommodations_quiz_id_training_registration__key UNIQUE (quiz_id, training_registration_id);


--
-- Name: training_quiz_answers training_quiz_answers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_answers
    ADD CONSTRAINT training_quiz_answers_pkey PRIMARY KEY (id);


--
-- Name: training_quiz_answers training_quiz_answers_quiz_attempt_id_quiz_question_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_answers
    ADD CONSTRAINT training_quiz_answers_quiz_attempt_id_quiz_question_id_key UNIQUE (quiz_attempt_id, quiz_question_id);


--
-- Name: training_quiz_attempts training_quiz_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_attempts
    ADD CONSTRAINT training_quiz_attempts_pkey PRIMARY KEY (id);


--
-- Name: training_quiz_attempts training_quiz_attempts_quiz_id_training_registration_id_att_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_attempts
    ADD CONSTRAINT training_quiz_attempts_quiz_id_training_registration_id_att_key UNIQUE (quiz_id, training_registration_id, attempt_number);


--
-- Name: training_quiz_grade_overrides training_quiz_grade_overrides_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_grade_overrides
    ADD CONSTRAINT training_quiz_grade_overrides_pkey PRIMARY KEY (id);


--
-- Name: training_quiz_grade_overrides training_quiz_grade_overrides_quiz_id_training_registration_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_grade_overrides
    ADD CONSTRAINT training_quiz_grade_overrides_quiz_id_training_registration_key UNIQUE (quiz_id, training_registration_id);


--
-- Name: training_quiz_question_adjustments training_quiz_question_adjustments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_question_adjustments
    ADD CONSTRAINT training_quiz_question_adjustments_pkey PRIMARY KEY (id);


--
-- Name: training_quiz_question_adjustments training_quiz_question_adjustments_quiz_question_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_question_adjustments
    ADD CONSTRAINT training_quiz_question_adjustments_quiz_question_id_key UNIQUE (quiz_question_id);


--
-- Name: training_quiz_questions training_quiz_questions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_questions
    ADD CONSTRAINT training_quiz_questions_pkey PRIMARY KEY (id);


--
-- Name: training_quiz_questions training_quiz_questions_quiz_id_sort_order_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_questions
    ADD CONSTRAINT training_quiz_questions_quiz_id_sort_order_key UNIQUE (quiz_id, sort_order);


--
-- Name: training_quizzes training_quizzes_assessment_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quizzes
    ADD CONSTRAINT training_quizzes_assessment_id_key UNIQUE (assessment_id);


--
-- Name: training_quizzes training_quizzes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quizzes
    ADD CONSTRAINT training_quizzes_pkey PRIMARY KEY (id);


--
-- Name: training_registration_status_history training_registration_status_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_registration_status_history
    ADD CONSTRAINT training_registration_status_history_pkey PRIMARY KEY (id);


--
-- Name: training_registrations training_registrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_registrations
    ADD CONSTRAINT training_registrations_pkey PRIMARY KEY (id);


--
-- Name: training_registrations training_registrations_training_email_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_registrations
    ADD CONSTRAINT training_registrations_training_email_unique UNIQUE (training_id, email);


--
-- Name: CONSTRAINT training_registrations_training_email_unique ON training_registrations; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON CONSTRAINT training_registrations_training_email_unique ON public.training_registrations IS 'One registration per training per email - re-registering should update the existing pending/rejected row, not create a second one.';


--
-- Name: training_sessions training_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_sessions
    ADD CONSTRAINT training_sessions_pkey PRIMARY KEY (id);


--
-- Name: training_submissions training_submissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_submissions
    ADD CONSTRAINT training_submissions_pkey PRIMARY KEY (id);


--
-- Name: training_submissions training_submissions_training_assignment_id_training_regist_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_submissions
    ADD CONSTRAINT training_submissions_training_assignment_id_training_regist_key UNIQUE (training_assignment_id, training_registration_id);


--
-- Name: training_task_assessment_overrides training_task_assessment_over_assessment_id_training_regist_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_task_assessment_overrides
    ADD CONSTRAINT training_task_assessment_over_assessment_id_training_regist_key UNIQUE (assessment_id, training_registration_id);


--
-- Name: training_task_assessment_overrides training_task_assessment_overrides_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_task_assessment_overrides
    ADD CONSTRAINT training_task_assessment_overrides_pkey PRIMARY KEY (id);


--
-- Name: training_task_mark_history training_task_mark_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_task_mark_history
    ADD CONSTRAINT training_task_mark_history_pkey PRIMARY KEY (id);


--
-- Name: training_task_marks training_task_marks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_task_marks
    ADD CONSTRAINT training_task_marks_pkey PRIMARY KEY (id);


--
-- Name: training_task_marks training_task_marks_training_assignment_id_training_registr_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_task_marks
    ADD CONSTRAINT training_task_marks_training_assignment_id_training_registr_key UNIQUE (training_assignment_id, training_registration_id);


--
-- Name: training_translations training_translations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_translations
    ADD CONSTRAINT training_translations_pkey PRIMARY KEY (training_id, locale);


--
-- Name: training_waitlist_entries training_waitlist_entries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_waitlist_entries
    ADD CONSTRAINT training_waitlist_entries_pkey PRIMARY KEY (id);


--
-- Name: training_waitlist_entries training_waitlist_entries_training_id_queue_position_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_waitlist_entries
    ADD CONSTRAINT training_waitlist_entries_training_id_queue_position_key UNIQUE (training_id, queue_position);


--
-- Name: training_waitlist_entries training_waitlist_entries_training_registration_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_waitlist_entries
    ADD CONSTRAINT training_waitlist_entries_training_registration_id_key UNIQUE (training_registration_id);


--
-- Name: trainings trainings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trainings
    ADD CONSTRAINT trainings_pkey PRIMARY KEY (id);


--
-- Name: trainings trainings_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trainings
    ADD CONSTRAINT trainings_slug_key UNIQUE (slug);


--
-- Name: user_invitations user_invitations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_invitations
    ADD CONSTRAINT user_invitations_pkey PRIMARY KEY (id);


--
-- Name: user_invitations user_invitations_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_invitations
    ADD CONSTRAINT user_invitations_token_key UNIQUE (token);


--
-- Name: user_profiles user_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_profiles
    ADD CONSTRAINT user_profiles_pkey PRIMARY KEY (user_id);


--
-- Name: user_role_assignments user_role_assignments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_role_assignments
    ADD CONSTRAINT user_role_assignments_pkey PRIMARY KEY (id);


--
-- Name: user_role_assignments user_role_assignments_user_id_role_code_scope_type_scope_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_role_assignments
    ADD CONSTRAINT user_role_assignments_user_id_role_code_scope_type_scope_id_key UNIQUE (user_id, role_code, scope_type, scope_id);


--
-- Name: verification_reviews verification_reviews_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.verification_reviews
    ADD CONSTRAINT verification_reviews_pkey PRIMARY KEY (id);


--
-- Name: verification_statuses verification_statuses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.verification_statuses
    ADD CONSTRAINT verification_statuses_pkey PRIMARY KEY (code);


--
-- Name: volunteer_applications volunteer_applications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.volunteer_applications
    ADD CONSTRAINT volunteer_applications_pkey PRIMARY KEY (id);


--
-- Name: attendance_records attendance_records_pkey; Type: CONSTRAINT; Schema: restricted; Owner: -
--

ALTER TABLE ONLY restricted.attendance_records
    ADD CONSTRAINT attendance_records_pkey PRIMARY KEY (id);


--
-- Name: beneficiary_records beneficiary_records_participant_code_key; Type: CONSTRAINT; Schema: restricted; Owner: -
--

ALTER TABLE ONLY restricted.beneficiary_records
    ADD CONSTRAINT beneficiary_records_participant_code_key UNIQUE (participant_code);


--
-- Name: beneficiary_records beneficiary_records_pkey; Type: CONSTRAINT; Schema: restricted; Owner: -
--

ALTER TABLE ONLY restricted.beneficiary_records
    ADD CONSTRAINT beneficiary_records_pkey PRIMARY KEY (id);


--
-- Name: guardian_relationships guardian_relationships_pkey; Type: CONSTRAINT; Schema: restricted; Owner: -
--

ALTER TABLE ONLY restricted.guardian_relationships
    ADD CONSTRAINT guardian_relationships_pkey PRIMARY KEY (id);


--
-- Name: participation_consents participation_consents_pkey; Type: CONSTRAINT; Schema: restricted; Owner: -
--

ALTER TABLE ONLY restricted.participation_consents
    ADD CONSTRAINT participation_consents_pkey PRIMARY KEY (id);


--
-- Name: program_enrollments program_enrollments_pkey; Type: CONSTRAINT; Schema: restricted; Owner: -
--

ALTER TABLE ONLY restricted.program_enrollments
    ADD CONSTRAINT program_enrollments_pkey PRIMARY KEY (id);


--
-- Name: referrals referrals_pkey; Type: CONSTRAINT; Schema: restricted; Owner: -
--

ALTER TABLE ONLY restricted.referrals
    ADD CONSTRAINT referrals_pkey PRIMARY KEY (id);


--
-- Name: assessment_scores_session_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX assessment_scores_session_idx ON public.assessment_scores USING btree (assessment_session_id);


--
-- Name: assignments_lookup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX assignments_lookup_idx ON public.assignments USING btree (submission_table, submission_id);


--
-- Name: audit_log_actor_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_actor_created_idx ON public.audit_log USING btree (actor_user_id, created_at DESC);


--
-- Name: audit_log_table_record_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_table_record_idx ON public.audit_log USING btree (table_name, record_id);


--
-- Name: cohorts_program_cycle_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX cohorts_program_cycle_id_idx ON public.cohorts USING btree (program_cycle_id);


--
-- Name: donation_allocations_donation_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX donation_allocations_donation_id_idx ON public.donation_allocations USING btree (donation_id);


--
-- Name: donation_allocations_fund_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX donation_allocations_fund_id_idx ON public.donation_allocations USING btree (fund_id);


--
-- Name: donation_allocations_support_item_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX donation_allocations_support_item_idx ON public.donation_allocations USING btree (support_item_id);


--
-- Name: donation_intents_person_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX donation_intents_person_created_idx ON public.donation_intents USING btree (person_id, created_at DESC);


--
-- Name: donations_payment_transaction_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX donations_payment_transaction_unique ON public.donations USING btree (payment_transaction_id);


--
-- Name: donations_person_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX donations_person_created_idx ON public.donations USING btree (person_id, created_at DESC);


--
-- Name: donations_person_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX donations_person_id_idx ON public.donations USING btree (person_id);


--
-- Name: donations_status_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX donations_status_created_idx ON public.donations USING btree (status_code, created_at DESC);


--
-- Name: funds_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX funds_active_idx ON public.funds USING btree (id) WHERE (archived_at IS NULL);


--
-- Name: funds_initiative_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX funds_initiative_idx ON public.funds USING btree (initiative_id) WHERE (initiative_id IS NOT NULL);


--
-- Name: funds_program_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX funds_program_idx ON public.funds USING btree (program_id) WHERE (program_id IS NOT NULL);


--
-- Name: governance_appointments_person_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX governance_appointments_person_id_idx ON public.governance_appointments USING btree (person_id);


--
-- Name: indicator_observations_plan_period_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX indicator_observations_plan_period_idx ON public.indicator_observations USING btree (measurement_plan_id, reporting_period_id);


--
-- Name: indicator_observations_public_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX indicator_observations_public_idx ON public.indicator_observations USING btree (measurement_plan_id) WHERE ((verification_status_code = 'published'::text) AND (is_suppressed = false));


--
-- Name: indicator_scopes_initiative_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX indicator_scopes_initiative_idx ON public.indicator_scopes USING btree (initiative_id) WHERE (initiative_id IS NOT NULL);


--
-- Name: indicator_scopes_program_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX indicator_scopes_program_idx ON public.indicator_scopes USING btree (program_id) WHERE (program_id IS NOT NULL);


--
-- Name: indicator_targets_period_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX indicator_targets_period_idx ON public.indicator_targets USING btree (reporting_period_id);


--
-- Name: indicator_translations_locale_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX indicator_translations_locale_idx ON public.indicator_translations USING btree (locale, indicator_definition_id);


--
-- Name: initiative_program_links_program_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX initiative_program_links_program_idx ON public.initiative_program_links USING btree (program_id, initiative_id);


--
-- Name: initiative_translations_locale_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX initiative_translations_locale_idx ON public.initiative_translations USING btree (locale, initiative_id);


--
-- Name: initiatives_published_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX initiatives_published_idx ON public.initiatives USING btree (id) WHERE ((publication_status_code = 'published'::text) AND (archived_at IS NULL));


--
-- Name: internal_notes_lookup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX internal_notes_lookup_idx ON public.internal_notes USING btree (submission_table, submission_id);


--
-- Name: measurement_plans_scope_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX measurement_plans_scope_idx ON public.measurement_plans USING btree (indicator_scope_id);


--
-- Name: media_assets_person_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX media_assets_person_id_idx ON public.media_assets USING btree (person_id);


--
-- Name: membership_events_membership_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX membership_events_membership_id_idx ON public.membership_events USING btree (membership_id);


--
-- Name: memberships_person_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX memberships_person_id_idx ON public.memberships USING btree (person_id);


--
-- Name: observation_breakdowns_observation_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX observation_breakdowns_observation_idx ON public.observation_breakdowns USING btree (indicator_observation_id);


--
-- Name: observation_breakdowns_public_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX observation_breakdowns_public_idx ON public.observation_breakdowns USING btree (indicator_observation_id) WHERE (is_suppressed = false);


--
-- Name: organizations_logo_permitted_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX organizations_logo_permitted_idx ON public.organizations USING btree (id) WHERE (logo_publication_permitted = true);


--
-- Name: partner_relationships_initiative_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX partner_relationships_initiative_idx ON public.partner_relationships USING btree (initiative_id) WHERE (initiative_id IS NOT NULL);


--
-- Name: partner_relationships_organization_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX partner_relationships_organization_id_idx ON public.partner_relationships USING btree (organization_id);


--
-- Name: partner_relationships_program_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX partner_relationships_program_idx ON public.partner_relationships USING btree (program_id) WHERE (program_id IS NOT NULL);


--
-- Name: payment_records_registration_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payment_records_registration_idx ON public.payment_records USING btree (training_registration_id, recorded_at DESC);


--
-- Name: payment_transactions_intent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payment_transactions_intent_idx ON public.payment_transactions USING btree (donation_intent_id) WHERE (donation_intent_id IS NOT NULL);


--
-- Name: payment_transactions_provider_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payment_transactions_provider_status_idx ON public.payment_transactions USING btree (provider_code, status_code);


--
-- Name: payment_transactions_status_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payment_transactions_status_created_idx ON public.payment_transactions USING btree (status_code, created_at DESC);


--
-- Name: people_email_unique_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX people_email_unique_idx ON public.people USING btree (email) WHERE ((email IS NOT NULL) AND (archived_at IS NULL));


--
-- Name: person_accessibility_requests_person_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX person_accessibility_requests_person_id_idx ON public.person_accessibility_requests USING btree (person_id);


--
-- Name: person_consent_records_person_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX person_consent_records_person_id_idx ON public.person_consent_records USING btree (person_id);


--
-- Name: person_emergency_contacts_person_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX person_emergency_contacts_person_id_idx ON public.person_emergency_contacts USING btree (person_id);


--
-- Name: person_guardian_relationships_dependent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX person_guardian_relationships_dependent_idx ON public.person_guardian_relationships USING btree (dependent_person_id);


--
-- Name: person_guardian_relationships_guardian_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX person_guardian_relationships_guardian_idx ON public.person_guardian_relationships USING btree (guardian_person_id);


--
-- Name: professional_credentials_trainer_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX professional_credentials_trainer_id_idx ON public.professional_credentials USING btree (trainer_id);


--
-- Name: profile_documents_credential_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX profile_documents_credential_id_idx ON public.profile_documents USING btree (credential_id);


--
-- Name: profile_documents_trainer_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX profile_documents_trainer_id_idx ON public.profile_documents USING btree (trainer_id);


--
-- Name: program_activities_locale_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX program_activities_locale_idx ON public.program_activities USING btree (locale, program_id);


--
-- Name: program_activities_program_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX program_activities_program_id_idx ON public.program_activities USING btree (program_id);


--
-- Name: program_cycles_program_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX program_cycles_program_id_idx ON public.program_cycles USING btree (program_id);


--
-- Name: program_indicators_program_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX program_indicators_program_id_idx ON public.program_indicators USING btree (program_id);


--
-- Name: program_translations_locale_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX program_translations_locale_idx ON public.program_translations USING btree (locale, program_id);


--
-- Name: programs_parent_program_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX programs_parent_program_id_idx ON public.programs USING btree (parent_program_id);


--
-- Name: programs_published_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX programs_published_idx ON public.programs USING btree (id) WHERE ((publication_status_code = 'published'::text) AND (archived_at IS NULL));


--
-- Name: receipt_deliveries_receipt_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX receipt_deliveries_receipt_id_idx ON public.receipt_deliveries USING btree (receipt_id);


--
-- Name: receipts_donation_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX receipts_donation_id_idx ON public.receipts USING btree (donation_id);


--
-- Name: receipts_donation_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX receipts_donation_idx ON public.receipts USING btree (donation_id);


--
-- Name: refunds_donation_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX refunds_donation_id_idx ON public.refunds USING btree (donation_id);


--
-- Name: resource_translations_locale_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX resource_translations_locale_idx ON public.resource_translations USING btree (locale, resource_id);


--
-- Name: resources_published_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX resources_published_idx ON public.resources USING btree (id) WHERE ((publication_status_code = 'published'::text) AND (archived_at IS NULL));


--
-- Name: result_node_translations_locale_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX result_node_translations_locale_idx ON public.result_node_translations USING btree (locale, result_node_id);


--
-- Name: role_permissions_permission_role_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX role_permissions_permission_role_idx ON public.role_permissions USING btree (permission_code, role_code);


--
-- Name: security_events_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX security_events_created_at_idx ON public.security_events USING btree (created_at DESC);


--
-- Name: security_events_subject_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX security_events_subject_user_id_idx ON public.security_events USING btree (subject_user_id, created_at DESC);


--
-- Name: submission_status_history_lookup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX submission_status_history_lookup_idx ON public.submission_status_history USING btree (submission_table, submission_id);


--
-- Name: support_item_fulfillments_donation_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX support_item_fulfillments_donation_idx ON public.support_item_fulfillments USING btree (donation_id);


--
-- Name: support_item_fulfillments_item_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX support_item_fulfillments_item_idx ON public.support_item_fulfillments USING btree (support_item_id);


--
-- Name: support_items_initiative_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX support_items_initiative_id_idx ON public.support_items USING btree (initiative_id);


--
-- Name: trainer_application_snapshots_trainer_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX trainer_application_snapshots_trainer_id_idx ON public.trainer_application_snapshots USING btree (trainer_id);


--
-- Name: training_academic_plans_one_approved; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX training_academic_plans_one_approved ON public.training_academic_plans USING btree (training_id) WHERE (status_code = 'approved'::text);


--
-- Name: training_assessment_grade_history_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX training_assessment_grade_history_idx ON public.training_assessment_grade_history USING btree (training_registration_id, assessment_id);


--
-- Name: training_assignments_assessment_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX training_assignments_assessment_idx ON public.training_assignments USING btree (assessment_id) WHERE (assessment_id IS NOT NULL);


--
-- Name: training_assignments_training_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX training_assignments_training_idx ON public.training_assignments USING btree (training_id);


--
-- Name: training_attendance_registration_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX training_attendance_registration_idx ON public.training_attendance USING btree (training_registration_id);


--
-- Name: training_certificate_reissue_auth_registration_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX training_certificate_reissue_auth_registration_idx ON public.training_certificate_reissue_authorizations USING btree (training_registration_id);


--
-- Name: training_certificates_one_current_per_registration; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX training_certificates_one_current_per_registration ON public.training_certificates USING btree (training_registration_id) WHERE (revoked_at IS NULL);


--
-- Name: training_fee_access_exceptions_one_open; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX training_fee_access_exceptions_one_open ON public.training_fee_access_exceptions USING btree (training_registration_id) WHERE (status_code = ANY (ARRAY['pending'::text, 'active'::text]));


--
-- Name: training_fee_proof_submissions_charge_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX training_fee_proof_submissions_charge_idx ON public.training_fee_proof_submissions USING btree (training_charge_id, status_code);


--
-- Name: training_fee_refunds_charge_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX training_fee_refunds_charge_idx ON public.training_fee_refunds USING btree (training_charge_id);


--
-- Name: training_fee_transactions_charge_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX training_fee_transactions_charge_idx ON public.training_fee_transactions USING btree (training_charge_id);


--
-- Name: training_materials_training_order_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX training_materials_training_order_idx ON public.training_materials USING btree (training_id, sort_order, created_at);


--
-- Name: training_prerequisite_decisions_registration_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX training_prerequisite_decisions_registration_idx ON public.training_prerequisite_decisions USING btree (training_registration_id, decision_code);


--
-- Name: training_prerequisite_evidence_registration_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX training_prerequisite_evidence_registration_idx ON public.training_prerequisite_evidence USING btree (training_registration_id, status_code);


--
-- Name: training_prerequisites_training_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX training_prerequisites_training_idx ON public.training_prerequisites USING btree (training_id, active, sort_order);


--
-- Name: training_quiz_attempts_registration_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX training_quiz_attempts_registration_idx ON public.training_quiz_attempts USING btree (training_registration_id, quiz_id);


--
-- Name: training_registration_status_history_registration_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX training_registration_status_history_registration_idx ON public.training_registration_status_history USING btree (training_registration_id, created_at DESC);


--
-- Name: training_registrations_status_code_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX training_registrations_status_code_idx ON public.training_registrations USING btree (status_code);


--
-- Name: training_registrations_training_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX training_registrations_training_id_idx ON public.training_registrations USING btree (training_id);


--
-- Name: training_registrations_training_person_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX training_registrations_training_person_unique ON public.training_registrations USING btree (training_id, person_id) WHERE (person_id IS NOT NULL);


--
-- Name: INDEX training_registrations_training_person_unique; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON INDEX public.training_registrations_training_person_unique IS 'One registration per training per identity-linked person - training_registrations_training_email_unique alone does not catch this, since it keys on the raw email a registration was created under, not the person it later gets linked to. approve-registration.ts checks for this explicitly before linking (see its comment) so a conflict there is a clear warning, not a raw constraint-violation error.';


--
-- Name: training_sessions_training_time_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX training_sessions_training_time_idx ON public.training_sessions USING btree (training_id, starts_at);


--
-- Name: training_submissions_assignment_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX training_submissions_assignment_idx ON public.training_submissions USING btree (training_assignment_id);


--
-- Name: training_submissions_registration_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX training_submissions_registration_idx ON public.training_submissions USING btree (training_registration_id);


--
-- Name: training_task_mark_history_task_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX training_task_mark_history_task_idx ON public.training_task_mark_history USING btree (training_assignment_id, training_registration_id);


--
-- Name: training_task_marks_registration_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX training_task_marks_registration_idx ON public.training_task_marks USING btree (training_registration_id);


--
-- Name: training_waitlist_entries_training_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX training_waitlist_entries_training_idx ON public.training_waitlist_entries USING btree (training_id, status_code, queue_position);


--
-- Name: trainings_dates_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX trainings_dates_idx ON public.trainings USING btree (starts_on, ends_on);


--
-- Name: trainings_public_number_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX trainings_public_number_unique ON public.trainings USING btree (public_number) WHERE (public_number IS NOT NULL);


--
-- Name: trainings_trainer_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX trainings_trainer_id_idx ON public.trainings USING btree (trainer_id);


--
-- Name: user_profiles_person_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX user_profiles_person_id_idx ON public.user_profiles USING btree (person_id);


--
-- Name: user_role_assignments_access_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_role_assignments_access_idx ON public.user_role_assignments USING btree (user_id, role_code, scope_type, scope_id);


--
-- Name: user_role_assignments_global_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX user_role_assignments_global_unique ON public.user_role_assignments USING btree (user_id, role_code) WHERE ((scope_type IS NULL) AND (scope_id IS NULL));


--
-- Name: user_role_assignments_scope_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_role_assignments_scope_idx ON public.user_role_assignments USING btree (scope_type, scope_id, role_code, user_id) WHERE (scope_type IS NOT NULL);


--
-- Name: user_role_assignments_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_role_assignments_user_id_idx ON public.user_role_assignments USING btree (user_id, role_code);


--
-- Name: attendance_records_enrollment_idx; Type: INDEX; Schema: restricted; Owner: -
--

CREATE INDEX attendance_records_enrollment_idx ON restricted.attendance_records USING btree (enrollment_id);


--
-- Name: program_enrollments_cohort_idx; Type: INDEX; Schema: restricted; Owner: -
--

CREATE INDEX program_enrollments_cohort_idx ON restricted.program_enrollments USING btree (cohort_id);


--
-- Name: training_assessment_grade_history append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER append_only BEFORE DELETE OR UPDATE ON public.training_assessment_grade_history FOR EACH ROW EXECUTE FUNCTION public.prevent_history_change();


--
-- Name: training_task_mark_history append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER append_only BEFORE DELETE OR UPDATE ON public.training_task_mark_history FOR EACH ROW EXECUTE FUNCTION public.prevent_history_change();


--
-- Name: trainings assign_training_system_identity; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER assign_training_system_identity BEFORE INSERT ON public.trainings FOR EACH ROW EXECUTE FUNCTION public.assign_training_system_identity();


--
-- Name: training_registrations create_training_charge_on_approval; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER create_training_charge_on_approval AFTER UPDATE OF status_code ON public.training_registrations FOR EACH ROW EXECUTE FUNCTION public.create_training_charge_on_approval();


--
-- Name: training_attendance enforce_attendance_same_training; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER enforce_attendance_same_training BEFORE INSERT OR UPDATE ON public.training_attendance FOR EACH ROW EXECUTE FUNCTION public.enforce_attendance_same_training();


--
-- Name: training_registrations enforce_completion_status_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER enforce_completion_status_guard BEFORE UPDATE ON public.training_registrations FOR EACH ROW EXECUTE FUNCTION public.enforce_completion_status_guard();


--
-- Name: professional_credentials enforce_credential_self_service_columns; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER enforce_credential_self_service_columns BEFORE UPDATE ON public.professional_credentials FOR EACH ROW EXECUTE FUNCTION public.enforce_credential_self_service_columns();


--
-- Name: training_fee_proof_submissions enforce_fee_proof_submission_recorder; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER enforce_fee_proof_submission_recorder BEFORE INSERT ON public.training_fee_proof_submissions FOR EACH ROW EXECUTE FUNCTION public.enforce_fee_proof_submission_recorder();


--
-- Name: training_fee_refunds enforce_fee_refund_recorder; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER enforce_fee_refund_recorder BEFORE INSERT ON public.training_fee_refunds FOR EACH ROW EXECUTE FUNCTION public.enforce_fee_refund_recorder();


--
-- Name: training_submissions enforce_grade_only_submission; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER enforce_grade_only_submission BEFORE INSERT ON public.training_submissions FOR EACH ROW EXECUTE FUNCTION public.enforce_grade_only_submission();


--
-- Name: payment_records enforce_payment_record_immutable_fields; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER enforce_payment_record_immutable_fields BEFORE INSERT ON public.payment_records FOR EACH ROW EXECUTE FUNCTION public.enforce_payment_record_immutable_fields();


--
-- Name: training_fee_transactions enforce_payment_transaction_recorder; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER enforce_payment_transaction_recorder BEFORE INSERT ON public.training_fee_transactions FOR EACH ROW EXECUTE FUNCTION public.enforce_payment_transaction_recorder();


--
-- Name: people enforce_people_self_service_columns; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER enforce_people_self_service_columns BEFORE UPDATE ON public.people FOR EACH ROW EXECUTE FUNCTION public.enforce_people_self_service_columns();


--
-- Name: trainings enforce_publish_transition_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER enforce_publish_transition_guard BEFORE INSERT OR UPDATE ON public.trainings FOR EACH ROW EXECUTE FUNCTION public.enforce_publish_transition_guard();


--
-- Name: training_submissions enforce_submission_columns; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER enforce_submission_columns BEFORE INSERT OR UPDATE ON public.training_submissions FOR EACH ROW EXECUTE FUNCTION public.enforce_submission_columns();


--
-- Name: trainers enforce_trainer_profile_columns; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER enforce_trainer_profile_columns BEFORE UPDATE ON public.trainers FOR EACH ROW EXECUTE FUNCTION public.enforce_trainer_profile_columns();


--
-- Name: training_registrations enforce_trainer_registration_columns; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER enforce_trainer_registration_columns BEFORE UPDATE ON public.training_registrations FOR EACH ROW EXECUTE FUNCTION public.enforce_trainer_registration_columns();


--
-- Name: training_assessment_grades enforce_training_assessment_grade; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER enforce_training_assessment_grade BEFORE INSERT OR UPDATE ON public.training_assessment_grades FOR EACH ROW EXECUTE FUNCTION public.enforce_training_assessment_grade();


--
-- Name: trainings enforce_training_publish_approval; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER enforce_training_publish_approval BEFORE INSERT OR UPDATE ON public.trainings FOR EACH ROW EXECUTE FUNCTION public.enforce_training_publish_approval();


--
-- Name: trainings enforce_training_system_identity; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER enforce_training_system_identity BEFORE UPDATE OF slug, public_number, starts_on ON public.trainings FOR EACH ROW EXECUTE FUNCTION public.enforce_training_system_identity();


--
-- Name: training_assignments enforce_training_task_link; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER enforce_training_task_link BEFORE INSERT OR UPDATE ON public.training_assignments FOR EACH ROW EXECUTE FUNCTION public.enforce_training_task_link();


--
-- Name: training_registrations handle_registration_status_side_effects; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER handle_registration_status_side_effects AFTER UPDATE OF status_code ON public.training_registrations FOR EACH ROW EXECUTE FUNCTION public.handle_registration_status_side_effects();


--
-- Name: training_registrations log_completion_status_change; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER log_completion_status_change AFTER INSERT OR UPDATE ON public.training_registrations FOR EACH ROW EXECUTE FUNCTION public.log_status_change_to_audit_log('completion_status_code');


--
-- Name: contact_submissions log_status_change; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER log_status_change AFTER INSERT OR UPDATE ON public.contact_submissions FOR EACH ROW EXECUTE FUNCTION public.log_submission_status_change();


--
-- Name: partnership_inquiries log_status_change; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER log_status_change AFTER INSERT OR UPDATE ON public.partnership_inquiries FOR EACH ROW EXECUTE FUNCTION public.log_submission_status_change();


--
-- Name: professional_credentials log_status_change; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER log_status_change AFTER INSERT OR UPDATE ON public.professional_credentials FOR EACH ROW EXECUTE FUNCTION public.log_status_change_to_audit_log('verification_status_code');


--
-- Name: trainers log_status_change; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER log_status_change AFTER INSERT OR UPDATE ON public.trainers FOR EACH ROW EXECUTE FUNCTION public.log_status_change_to_audit_log('status_code');


--
-- Name: training_registrations log_status_change; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER log_status_change AFTER INSERT OR UPDATE ON public.training_registrations FOR EACH ROW EXECUTE FUNCTION public.log_status_change_to_audit_log('status_code');


--
-- Name: trainings log_status_change; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER log_status_change AFTER INSERT OR UPDATE ON public.trainings FOR EACH ROW EXECUTE FUNCTION public.log_status_change_to_audit_log('publication_status_code');


--
-- Name: volunteer_applications log_status_change; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER log_status_change AFTER INSERT OR UPDATE ON public.volunteer_applications FOR EACH ROW EXECUTE FUNCTION public.log_submission_status_change();


--
-- Name: training_assessment_grades log_training_assessment_grade; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER log_training_assessment_grade AFTER INSERT OR DELETE OR UPDATE ON public.training_assessment_grades FOR EACH ROW EXECUTE FUNCTION public.log_training_assessment_grade();


--
-- Name: training_task_marks log_training_task_mark; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER log_training_task_mark AFTER INSERT OR DELETE OR UPDATE ON public.training_task_marks FOR EACH ROW EXECUTE FUNCTION public.log_training_task_mark();


--
-- Name: training_assessment_grades prevent_linked_training_grade_delete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER prevent_linked_training_grade_delete BEFORE DELETE ON public.training_assessment_grades FOR EACH ROW EXECUTE FUNCTION public.prevent_linked_training_grade_delete();


--
-- Name: training_assessment_grades prevent_locked_training_grade_delete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER prevent_locked_training_grade_delete BEFORE DELETE ON public.training_assessment_grades FOR EACH ROW EXECUTE FUNCTION public.prevent_locked_training_grade_delete();


--
-- Name: training_assignments prevent_marked_task_delete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER prevent_marked_task_delete BEFORE DELETE ON public.training_assignments FOR EACH ROW EXECUTE FUNCTION public.prevent_marked_task_delete();


--
-- Name: training_translations refresh_training_slug_from_english_title_delete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER refresh_training_slug_from_english_title_delete AFTER DELETE ON public.training_translations FOR EACH ROW EXECUTE FUNCTION public.refresh_training_slug_from_english_title();


--
-- Name: training_translations refresh_training_slug_from_english_title_write; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER refresh_training_slug_from_english_title_write AFTER INSERT OR UPDATE ON public.training_translations FOR EACH ROW EXECUTE FUNCTION public.refresh_training_slug_from_english_title();


--
-- Name: contact_submissions set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.contact_submissions FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: donations set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.donations FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: funds set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.funds FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: governance_appointments set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.governance_appointments FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: indicator_definitions set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.indicator_definitions FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: indicator_observations set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.indicator_observations FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: initiatives set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.initiatives FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: measurement_plans set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.measurement_plans FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: memberships set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.memberships FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: organizations set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.organizations FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: partner_relationships set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.partner_relationships FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: partnership_inquiries set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.partnership_inquiries FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: payment_transactions set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.payment_transactions FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: people set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.people FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: person_accessibility_requests set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.person_accessibility_requests FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: person_emergency_contacts set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.person_emergency_contacts FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: professional_credentials set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.professional_credentials FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: programs set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.programs FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: recurring_agreements set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.recurring_agreements FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: resources set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.resources FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: support_items set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.support_items FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: theories_of_change set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.theories_of_change FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: trainers set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.trainers FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: training_academic_plans set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.training_academic_plans FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: training_assessment_grades set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.training_assessment_grades FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: training_assessments set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.training_assessments FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: training_assignments set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.training_assignments FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: training_attendance set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.training_attendance FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: training_completion_rules set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.training_completion_rules FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: training_feedback set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.training_feedback FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: training_final_grades set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.training_final_grades FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: training_materials set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.training_materials FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: training_prerequisite_evidence set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.training_prerequisite_evidence FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: training_prerequisites set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.training_prerequisites FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: training_question_bank_questions set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.training_question_bank_questions FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: training_question_banks set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.training_question_banks FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: training_quiz_accommodations set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.training_quiz_accommodations FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: training_quizzes set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.training_quizzes FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: training_registrations set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.training_registrations FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: training_sessions set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.training_sessions FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: training_waitlist_entries set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.training_waitlist_entries FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: trainings set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.trainings FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: user_profiles set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.user_profiles FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: volunteer_applications set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.volunteer_applications FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: professional_credentials stamp_credential_status_dates; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER stamp_credential_status_dates BEFORE INSERT OR UPDATE ON public.professional_credentials FOR EACH ROW EXECUTE FUNCTION public.stamp_credential_status_dates();


--
-- Name: payment_records sync_registration_fee_paid; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sync_registration_fee_paid AFTER INSERT ON public.payment_records FOR EACH ROW EXECUTE FUNCTION public.sync_registration_fee_paid();


--
-- Name: training_academic_plans training_academic_plans_freeze_decided; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER training_academic_plans_freeze_decided BEFORE UPDATE ON public.training_academic_plans FOR EACH ROW EXECUTE FUNCTION public.training_academic_plans_freeze_decided();


--
-- Name: training_academic_plans training_academic_plans_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER training_academic_plans_guard BEFORE INSERT OR UPDATE ON public.training_academic_plans FOR EACH ROW EXECUTE FUNCTION public.training_academic_plans_guard();


--
-- Name: training_assessments training_assessments_freeze_decided; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER training_assessments_freeze_decided BEFORE INSERT OR DELETE OR UPDATE ON public.training_assessments FOR EACH ROW EXECUTE FUNCTION public.training_assessments_freeze_decided();


--
-- Name: training_final_grades training_final_grade_after_return; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER training_final_grade_after_return AFTER UPDATE OF status_code ON public.training_final_grades FOR EACH ROW EXECUTE FUNCTION public.training_final_grade_after_return();


--
-- Name: training_quizzes training_quiz_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER training_quiz_guard BEFORE INSERT OR UPDATE ON public.training_quizzes FOR EACH ROW EXECUTE FUNCTION public.training_quiz_guard();


--
-- Name: training_quiz_questions training_quiz_question_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER training_quiz_question_guard BEFORE INSERT OR DELETE OR UPDATE ON public.training_quiz_questions FOR EACH ROW EXECUTE FUNCTION public.training_quiz_question_guard();


--
-- Name: training_registrations training_registration_status_history_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER training_registration_status_history_trigger AFTER INSERT OR UPDATE OF status_code ON public.training_registrations FOR EACH ROW EXECUTE FUNCTION public.record_training_registration_status_history();


--
-- Name: training_assignments training_task_after_change; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER training_task_after_change AFTER INSERT OR DELETE OR UPDATE OF assessment_id, is_published, max_marks, training_id ON public.training_assignments FOR EACH ROW EXECUTE FUNCTION public.training_task_after_change();


--
-- Name: user_role_assignments validate_role_assignment_scope; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER validate_role_assignment_scope BEFORE INSERT OR UPDATE OF role_code, scope_type, scope_id ON public.user_role_assignments FOR EACH ROW EXECUTE FUNCTION public.validate_role_assignment_scope();


--
-- Name: beneficiary_records set_updated_at; Type: TRIGGER; Schema: restricted; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON restricted.beneficiary_records FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: app_modules app_modules_manage_permission_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.app_modules
    ADD CONSTRAINT app_modules_manage_permission_code_fkey FOREIGN KEY (manage_permission_code) REFERENCES public.permissions(code) ON DELETE RESTRICT;


--
-- Name: app_modules app_modules_read_permission_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.app_modules
    ADD CONSTRAINT app_modules_read_permission_code_fkey FOREIGN KEY (read_permission_code) REFERENCES public.permissions(code) ON DELETE RESTRICT;


--
-- Name: assessment_scores assessment_scores_assessment_session_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assessment_scores
    ADD CONSTRAINT assessment_scores_assessment_session_id_fkey FOREIGN KEY (assessment_session_id) REFERENCES public.assessment_sessions(id) ON DELETE CASCADE;


--
-- Name: assessment_sessions assessment_sessions_administered_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assessment_sessions
    ADD CONSTRAINT assessment_sessions_administered_by_fkey FOREIGN KEY (administered_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: assessment_sessions assessment_sessions_cohort_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assessment_sessions
    ADD CONSTRAINT assessment_sessions_cohort_id_fkey FOREIGN KEY (cohort_id) REFERENCES public.cohorts(id) ON DELETE SET NULL;


--
-- Name: assessment_sessions assessment_sessions_instrument_version_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assessment_sessions
    ADD CONSTRAINT assessment_sessions_instrument_version_id_fkey FOREIGN KEY (instrument_version_id) REFERENCES public.instrument_versions(id) ON DELETE RESTRICT;


--
-- Name: assignments assignments_assigned_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assignments
    ADD CONSTRAINT assignments_assigned_by_fkey FOREIGN KEY (assigned_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: assignments assignments_assigned_to_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assignments
    ADD CONSTRAINT assignments_assigned_to_fkey FOREIGN KEY (assigned_to) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: audit_log audit_log_actor_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: cohorts cohorts_program_cycle_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cohorts
    ADD CONSTRAINT cohorts_program_cycle_id_fkey FOREIGN KEY (program_cycle_id) REFERENCES public.program_cycles(id) ON DELETE CASCADE;


--
-- Name: cohorts cohorts_site_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cohorts
    ADD CONSTRAINT cohorts_site_id_fkey FOREIGN KEY (site_id) REFERENCES public.sites(id) ON DELETE SET NULL;


--
-- Name: consent_records consent_records_person_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.consent_records
    ADD CONSTRAINT consent_records_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(id) ON DELETE CASCADE;


--
-- Name: contact_submissions contact_submissions_status_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contact_submissions
    ADD CONSTRAINT contact_submissions_status_code_fkey FOREIGN KEY (status_code) REFERENCES public.submission_statuses(code);


--
-- Name: data_quality_assessments data_quality_assessments_assessed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.data_quality_assessments
    ADD CONSTRAINT data_quality_assessments_assessed_by_fkey FOREIGN KEY (assessed_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: data_quality_assessments data_quality_assessments_indicator_observation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.data_quality_assessments
    ADD CONSTRAINT data_quality_assessments_indicator_observation_id_fkey FOREIGN KEY (indicator_observation_id) REFERENCES public.indicator_observations(id) ON DELETE CASCADE;


--
-- Name: donation_allocations donation_allocations_donation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.donation_allocations
    ADD CONSTRAINT donation_allocations_donation_id_fkey FOREIGN KEY (donation_id) REFERENCES public.donations(id) ON DELETE CASCADE;


--
-- Name: donation_allocations donation_allocations_fund_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.donation_allocations
    ADD CONSTRAINT donation_allocations_fund_id_fkey FOREIGN KEY (fund_id) REFERENCES public.funds(id) ON DELETE RESTRICT;


--
-- Name: donation_allocations donation_allocations_support_item_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.donation_allocations
    ADD CONSTRAINT donation_allocations_support_item_id_fkey FOREIGN KEY (support_item_id) REFERENCES public.support_items(id) ON DELETE SET NULL;


--
-- Name: donation_intents donation_intents_currency_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.donation_intents
    ADD CONSTRAINT donation_intents_currency_code_fkey FOREIGN KEY (currency_code) REFERENCES public.currencies(code);


--
-- Name: donation_intents donation_intents_frequency_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.donation_intents
    ADD CONSTRAINT donation_intents_frequency_code_fkey FOREIGN KEY (frequency_code) REFERENCES public.donation_frequencies(code);


--
-- Name: donation_intents donation_intents_fund_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.donation_intents
    ADD CONSTRAINT donation_intents_fund_id_fkey FOREIGN KEY (fund_id) REFERENCES public.funds(id) ON DELETE RESTRICT;


--
-- Name: donation_intents donation_intents_person_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.donation_intents
    ADD CONSTRAINT donation_intents_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(id) ON DELETE SET NULL;


--
-- Name: donations donations_currency_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.donations
    ADD CONSTRAINT donations_currency_code_fkey FOREIGN KEY (currency_code) REFERENCES public.currencies(code);


--
-- Name: donations donations_payment_transaction_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.donations
    ADD CONSTRAINT donations_payment_transaction_id_fkey FOREIGN KEY (payment_transaction_id) REFERENCES public.payment_transactions(id) ON DELETE RESTRICT;


--
-- Name: donations donations_person_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.donations
    ADD CONSTRAINT donations_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(id) ON DELETE SET NULL;


--
-- Name: donations donations_status_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.donations
    ADD CONSTRAINT donations_status_code_fkey FOREIGN KEY (status_code) REFERENCES public.donation_statuses(code);


--
-- Name: evidence_artifacts evidence_artifacts_indicator_observation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_artifacts
    ADD CONSTRAINT evidence_artifacts_indicator_observation_id_fkey FOREIGN KEY (indicator_observation_id) REFERENCES public.indicator_observations(id) ON DELETE CASCADE;


--
-- Name: funds funds_fund_type_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.funds
    ADD CONSTRAINT funds_fund_type_code_fkey FOREIGN KEY (fund_type_code) REFERENCES public.fund_types(code);


--
-- Name: funds funds_initiative_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.funds
    ADD CONSTRAINT funds_initiative_id_fkey FOREIGN KEY (initiative_id) REFERENCES public.initiatives(id) ON DELETE SET NULL;


--
-- Name: funds funds_program_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.funds
    ADD CONSTRAINT funds_program_id_fkey FOREIGN KEY (program_id) REFERENCES public.programs(id) ON DELETE SET NULL;


--
-- Name: governance_appointments governance_appointments_person_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.governance_appointments
    ADD CONSTRAINT governance_appointments_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(id) ON DELETE RESTRICT;


--
-- Name: governance_appointments governance_appointments_role_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.governance_appointments
    ADD CONSTRAINT governance_appointments_role_code_fkey FOREIGN KEY (role_code) REFERENCES public.governance_roles(code);


--
-- Name: indicator_baselines indicator_baselines_measurement_plan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_baselines
    ADD CONSTRAINT indicator_baselines_measurement_plan_id_fkey FOREIGN KEY (measurement_plan_id) REFERENCES public.measurement_plans(id) ON DELETE CASCADE;


--
-- Name: indicator_definitions indicator_definitions_result_level_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_definitions
    ADD CONSTRAINT indicator_definitions_result_level_code_fkey FOREIGN KEY (result_level_code) REFERENCES public.result_levels(code);


--
-- Name: indicator_disaggregations indicator_disaggregations_measurement_plan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_disaggregations
    ADD CONSTRAINT indicator_disaggregations_measurement_plan_id_fkey FOREIGN KEY (measurement_plan_id) REFERENCES public.measurement_plans(id) ON DELETE CASCADE;


--
-- Name: indicator_observations indicator_observations_cohort_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_observations
    ADD CONSTRAINT indicator_observations_cohort_id_fkey FOREIGN KEY (cohort_id) REFERENCES public.cohorts(id) ON DELETE SET NULL;


--
-- Name: indicator_observations indicator_observations_entered_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_observations
    ADD CONSTRAINT indicator_observations_entered_by_fkey FOREIGN KEY (entered_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: indicator_observations indicator_observations_indicator_version_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_observations
    ADD CONSTRAINT indicator_observations_indicator_version_id_fkey FOREIGN KEY (indicator_version_id) REFERENCES public.indicator_versions(id) ON DELETE RESTRICT;


--
-- Name: indicator_observations indicator_observations_measurement_plan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_observations
    ADD CONSTRAINT indicator_observations_measurement_plan_id_fkey FOREIGN KEY (measurement_plan_id) REFERENCES public.measurement_plans(id) ON DELETE CASCADE;


--
-- Name: indicator_observations indicator_observations_reporting_period_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_observations
    ADD CONSTRAINT indicator_observations_reporting_period_id_fkey FOREIGN KEY (reporting_period_id) REFERENCES public.reporting_periods(id) ON DELETE CASCADE;


--
-- Name: indicator_observations indicator_observations_verification_status_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_observations
    ADD CONSTRAINT indicator_observations_verification_status_code_fkey FOREIGN KEY (verification_status_code) REFERENCES public.verification_statuses(code);


--
-- Name: indicator_observations indicator_observations_verified_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_observations
    ADD CONSTRAINT indicator_observations_verified_by_fkey FOREIGN KEY (verified_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: indicator_scopes indicator_scopes_indicator_definition_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_scopes
    ADD CONSTRAINT indicator_scopes_indicator_definition_id_fkey FOREIGN KEY (indicator_definition_id) REFERENCES public.indicator_definitions(id) ON DELETE CASCADE;


--
-- Name: indicator_scopes indicator_scopes_initiative_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_scopes
    ADD CONSTRAINT indicator_scopes_initiative_id_fkey FOREIGN KEY (initiative_id) REFERENCES public.initiatives(id) ON DELETE CASCADE;


--
-- Name: indicator_scopes indicator_scopes_program_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_scopes
    ADD CONSTRAINT indicator_scopes_program_id_fkey FOREIGN KEY (program_id) REFERENCES public.programs(id) ON DELETE CASCADE;


--
-- Name: indicator_scopes indicator_scopes_result_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_scopes
    ADD CONSTRAINT indicator_scopes_result_node_id_fkey FOREIGN KEY (result_node_id) REFERENCES public.result_nodes(id) ON DELETE SET NULL;


--
-- Name: indicator_targets indicator_targets_measurement_plan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_targets
    ADD CONSTRAINT indicator_targets_measurement_plan_id_fkey FOREIGN KEY (measurement_plan_id) REFERENCES public.measurement_plans(id) ON DELETE CASCADE;


--
-- Name: indicator_targets indicator_targets_reporting_period_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_targets
    ADD CONSTRAINT indicator_targets_reporting_period_id_fkey FOREIGN KEY (reporting_period_id) REFERENCES public.reporting_periods(id) ON DELETE CASCADE;


--
-- Name: indicator_translations indicator_translations_indicator_definition_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_translations
    ADD CONSTRAINT indicator_translations_indicator_definition_id_fkey FOREIGN KEY (indicator_definition_id) REFERENCES public.indicator_definitions(id) ON DELETE CASCADE;


--
-- Name: indicator_versions indicator_versions_indicator_definition_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.indicator_versions
    ADD CONSTRAINT indicator_versions_indicator_definition_id_fkey FOREIGN KEY (indicator_definition_id) REFERENCES public.indicator_definitions(id) ON DELETE CASCADE;


--
-- Name: initiative_program_links initiative_program_links_initiative_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.initiative_program_links
    ADD CONSTRAINT initiative_program_links_initiative_id_fkey FOREIGN KEY (initiative_id) REFERENCES public.initiatives(id) ON DELETE CASCADE;


--
-- Name: initiative_program_links initiative_program_links_program_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.initiative_program_links
    ADD CONSTRAINT initiative_program_links_program_id_fkey FOREIGN KEY (program_id) REFERENCES public.programs(id) ON DELETE CASCADE;


--
-- Name: initiative_translations initiative_translations_initiative_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.initiative_translations
    ADD CONSTRAINT initiative_translations_initiative_id_fkey FOREIGN KEY (initiative_id) REFERENCES public.initiatives(id) ON DELETE CASCADE;


--
-- Name: initiatives initiatives_publication_status_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.initiatives
    ADD CONSTRAINT initiatives_publication_status_code_fkey FOREIGN KEY (publication_status_code) REFERENCES public.publication_statuses(code);


--
-- Name: instrument_versions instrument_versions_assessment_instrument_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.instrument_versions
    ADD CONSTRAINT instrument_versions_assessment_instrument_id_fkey FOREIGN KEY (assessment_instrument_id) REFERENCES public.assessment_instruments(id) ON DELETE CASCADE;


--
-- Name: internal_notes internal_notes_author_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.internal_notes
    ADD CONSTRAINT internal_notes_author_id_fkey FOREIGN KEY (author_id) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: learning_actions learning_actions_decided_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.learning_actions
    ADD CONSTRAINT learning_actions_decided_by_fkey FOREIGN KEY (decided_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: learning_actions learning_actions_indicator_observation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.learning_actions
    ADD CONSTRAINT learning_actions_indicator_observation_id_fkey FOREIGN KEY (indicator_observation_id) REFERENCES public.indicator_observations(id) ON DELETE SET NULL;


--
-- Name: learning_actions learning_actions_program_cycle_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.learning_actions
    ADD CONSTRAINT learning_actions_program_cycle_id_fkey FOREIGN KEY (program_cycle_id) REFERENCES public.program_cycles(id) ON DELETE SET NULL;


--
-- Name: measurement_plans measurement_plans_indicator_scope_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.measurement_plans
    ADD CONSTRAINT measurement_plans_indicator_scope_id_fkey FOREIGN KEY (indicator_scope_id) REFERENCES public.indicator_scopes(id) ON DELETE CASCADE;


--
-- Name: measurement_plans measurement_plans_program_cycle_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.measurement_plans
    ADD CONSTRAINT measurement_plans_program_cycle_id_fkey FOREIGN KEY (program_cycle_id) REFERENCES public.program_cycles(id) ON DELETE CASCADE;


--
-- Name: measurement_plans measurement_plans_responsible_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.measurement_plans
    ADD CONSTRAINT measurement_plans_responsible_user_id_fkey FOREIGN KEY (responsible_user_id) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: media_assets media_assets_initiative_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.media_assets
    ADD CONSTRAINT media_assets_initiative_id_fkey FOREIGN KEY (initiative_id) REFERENCES public.initiatives(id) ON DELETE SET NULL;


--
-- Name: media_assets media_assets_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.media_assets
    ADD CONSTRAINT media_assets_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE SET NULL;


--
-- Name: media_assets media_assets_person_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.media_assets
    ADD CONSTRAINT media_assets_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(id) ON DELETE SET NULL;


--
-- Name: media_assets media_assets_program_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.media_assets
    ADD CONSTRAINT media_assets_program_id_fkey FOREIGN KEY (program_id) REFERENCES public.programs(id) ON DELETE SET NULL;


--
-- Name: media_assets media_assets_uploaded_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.media_assets
    ADD CONSTRAINT media_assets_uploaded_by_fkey FOREIGN KEY (uploaded_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: membership_events membership_events_membership_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.membership_events
    ADD CONSTRAINT membership_events_membership_id_fkey FOREIGN KEY (membership_id) REFERENCES public.memberships(id) ON DELETE CASCADE;


--
-- Name: membership_events membership_events_recorded_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.membership_events
    ADD CONSTRAINT membership_events_recorded_by_fkey FOREIGN KEY (recorded_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: memberships memberships_membership_type_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.memberships
    ADD CONSTRAINT memberships_membership_type_code_fkey FOREIGN KEY (membership_type_code) REFERENCES public.membership_types(code);


--
-- Name: memberships memberships_person_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.memberships
    ADD CONSTRAINT memberships_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(id) ON DELETE RESTRICT;


--
-- Name: memberships memberships_status_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.memberships
    ADD CONSTRAINT memberships_status_code_fkey FOREIGN KEY (status_code) REFERENCES public.membership_statuses(code);


--
-- Name: observation_breakdowns observation_breakdowns_indicator_observation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.observation_breakdowns
    ADD CONSTRAINT observation_breakdowns_indicator_observation_id_fkey FOREIGN KEY (indicator_observation_id) REFERENCES public.indicator_observations(id) ON DELETE CASCADE;


--
-- Name: organizations organizations_organization_type_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_organization_type_code_fkey FOREIGN KEY (organization_type_code) REFERENCES public.organization_types(code);


--
-- Name: partner_relationships partner_relationships_initiative_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.partner_relationships
    ADD CONSTRAINT partner_relationships_initiative_id_fkey FOREIGN KEY (initiative_id) REFERENCES public.initiatives(id) ON DELETE SET NULL;


--
-- Name: partner_relationships partner_relationships_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.partner_relationships
    ADD CONSTRAINT partner_relationships_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: partner_relationships partner_relationships_partner_role_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.partner_relationships
    ADD CONSTRAINT partner_relationships_partner_role_code_fkey FOREIGN KEY (partner_role_code) REFERENCES public.partner_roles(code);


--
-- Name: partner_relationships partner_relationships_program_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.partner_relationships
    ADD CONSTRAINT partner_relationships_program_id_fkey FOREIGN KEY (program_id) REFERENCES public.programs(id) ON DELETE SET NULL;


--
-- Name: partnership_inquiries partnership_inquiries_program_of_interest_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.partnership_inquiries
    ADD CONSTRAINT partnership_inquiries_program_of_interest_id_fkey FOREIGN KEY (program_of_interest_id) REFERENCES public.programs(id) ON DELETE SET NULL;


--
-- Name: partnership_inquiries partnership_inquiries_status_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.partnership_inquiries
    ADD CONSTRAINT partnership_inquiries_status_code_fkey FOREIGN KEY (status_code) REFERENCES public.submission_statuses(code);


--
-- Name: payment_customers payment_customers_person_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_customers
    ADD CONSTRAINT payment_customers_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(id) ON DELETE SET NULL;


--
-- Name: payment_customers payment_customers_provider_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_customers
    ADD CONSTRAINT payment_customers_provider_code_fkey FOREIGN KEY (provider_code) REFERENCES public.payment_providers(code);


--
-- Name: payment_events payment_events_payment_transaction_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_events
    ADD CONSTRAINT payment_events_payment_transaction_id_fkey FOREIGN KEY (payment_transaction_id) REFERENCES public.payment_transactions(id) ON DELETE SET NULL;


--
-- Name: payment_events payment_events_provider_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_events
    ADD CONSTRAINT payment_events_provider_code_fkey FOREIGN KEY (provider_code) REFERENCES public.payment_providers(code);


--
-- Name: payment_records payment_records_recorded_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_records
    ADD CONSTRAINT payment_records_recorded_by_fkey FOREIGN KEY (recorded_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: payment_records payment_records_training_registration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_records
    ADD CONSTRAINT payment_records_training_registration_id_fkey FOREIGN KEY (training_registration_id) REFERENCES public.training_registrations(id) ON DELETE CASCADE;


--
-- Name: payment_transactions payment_transactions_currency_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_transactions
    ADD CONSTRAINT payment_transactions_currency_code_fkey FOREIGN KEY (currency_code) REFERENCES public.currencies(code);


--
-- Name: payment_transactions payment_transactions_donation_intent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_transactions
    ADD CONSTRAINT payment_transactions_donation_intent_id_fkey FOREIGN KEY (donation_intent_id) REFERENCES public.donation_intents(id) ON DELETE SET NULL;


--
-- Name: payment_transactions payment_transactions_provider_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_transactions
    ADD CONSTRAINT payment_transactions_provider_code_fkey FOREIGN KEY (provider_code) REFERENCES public.payment_providers(code);


--
-- Name: payment_transactions payment_transactions_recurring_agreement_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_transactions
    ADD CONSTRAINT payment_transactions_recurring_agreement_id_fkey FOREIGN KEY (recurring_agreement_id) REFERENCES public.recurring_agreements(id) ON DELETE SET NULL;


--
-- Name: payment_transactions payment_transactions_status_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_transactions
    ADD CONSTRAINT payment_transactions_status_code_fkey FOREIGN KEY (status_code) REFERENCES public.payment_transaction_statuses(code);


--
-- Name: people_translations people_translations_person_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.people_translations
    ADD CONSTRAINT people_translations_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(id) ON DELETE CASCADE;


--
-- Name: person_accessibility_requests person_accessibility_requests_person_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.person_accessibility_requests
    ADD CONSTRAINT person_accessibility_requests_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(id) ON DELETE CASCADE;


--
-- Name: person_accessibility_requests person_accessibility_requests_reviewed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.person_accessibility_requests
    ADD CONSTRAINT person_accessibility_requests_reviewed_by_fkey FOREIGN KEY (reviewed_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: person_accessibility_requests person_accessibility_requests_training_registration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.person_accessibility_requests
    ADD CONSTRAINT person_accessibility_requests_training_registration_id_fkey FOREIGN KEY (training_registration_id) REFERENCES public.training_registrations(id) ON DELETE CASCADE;


--
-- Name: person_consent_records person_consent_records_granted_by_person_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.person_consent_records
    ADD CONSTRAINT person_consent_records_granted_by_person_id_fkey FOREIGN KEY (granted_by_person_id) REFERENCES public.people(id) ON DELETE SET NULL;


--
-- Name: person_consent_records person_consent_records_person_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.person_consent_records
    ADD CONSTRAINT person_consent_records_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(id) ON DELETE CASCADE;


--
-- Name: person_emergency_contacts person_emergency_contacts_person_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.person_emergency_contacts
    ADD CONSTRAINT person_emergency_contacts_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(id) ON DELETE CASCADE;


--
-- Name: person_guardian_relationships person_guardian_relationships_dependent_person_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.person_guardian_relationships
    ADD CONSTRAINT person_guardian_relationships_dependent_person_id_fkey FOREIGN KEY (dependent_person_id) REFERENCES public.people(id) ON DELETE CASCADE;


--
-- Name: person_guardian_relationships person_guardian_relationships_guardian_person_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.person_guardian_relationships
    ADD CONSTRAINT person_guardian_relationships_guardian_person_id_fkey FOREIGN KEY (guardian_person_id) REFERENCES public.people(id) ON DELETE CASCADE;


--
-- Name: person_guardian_relationships person_guardian_relationships_verified_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.person_guardian_relationships
    ADD CONSTRAINT person_guardian_relationships_verified_by_fkey FOREIGN KEY (verified_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: professional_credentials professional_credentials_reviewed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.professional_credentials
    ADD CONSTRAINT professional_credentials_reviewed_by_fkey FOREIGN KEY (reviewed_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: professional_credentials professional_credentials_trainer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.professional_credentials
    ADD CONSTRAINT professional_credentials_trainer_id_fkey FOREIGN KEY (trainer_id) REFERENCES public.trainers(id) ON DELETE CASCADE;


--
-- Name: profile_documents profile_documents_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.profile_documents
    ADD CONSTRAINT profile_documents_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES public.professional_credentials(id) ON DELETE CASCADE;


--
-- Name: profile_documents profile_documents_trainer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.profile_documents
    ADD CONSTRAINT profile_documents_trainer_id_fkey FOREIGN KEY (trainer_id) REFERENCES public.trainers(id) ON DELETE CASCADE;


--
-- Name: program_activities program_activities_program_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.program_activities
    ADD CONSTRAINT program_activities_program_id_fkey FOREIGN KEY (program_id) REFERENCES public.programs(id) ON DELETE CASCADE;


--
-- Name: program_cycles program_cycles_program_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.program_cycles
    ADD CONSTRAINT program_cycles_program_id_fkey FOREIGN KEY (program_id) REFERENCES public.programs(id) ON DELETE CASCADE;


--
-- Name: program_indicators program_indicators_program_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.program_indicators
    ADD CONSTRAINT program_indicators_program_id_fkey FOREIGN KEY (program_id) REFERENCES public.programs(id) ON DELETE CASCADE;


--
-- Name: program_translations program_translations_program_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.program_translations
    ADD CONSTRAINT program_translations_program_id_fkey FOREIGN KEY (program_id) REFERENCES public.programs(id) ON DELETE CASCADE;


--
-- Name: programs programs_parent_program_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.programs
    ADD CONSTRAINT programs_parent_program_id_fkey FOREIGN KEY (parent_program_id) REFERENCES public.programs(id) ON DELETE SET NULL;


--
-- Name: programs programs_publication_status_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.programs
    ADD CONSTRAINT programs_publication_status_code_fkey FOREIGN KEY (publication_status_code) REFERENCES public.publication_statuses(code);


--
-- Name: programs programs_status_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.programs
    ADD CONSTRAINT programs_status_code_fkey FOREIGN KEY (status_code) REFERENCES public.program_statuses(code);


--
-- Name: publication_approvals publication_approvals_approved_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.publication_approvals
    ADD CONSTRAINT publication_approvals_approved_by_fkey FOREIGN KEY (approved_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: publication_approvals publication_approvals_indicator_observation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.publication_approvals
    ADD CONSTRAINT publication_approvals_indicator_observation_id_fkey FOREIGN KEY (indicator_observation_id) REFERENCES public.indicator_observations(id) ON DELETE CASCADE;


--
-- Name: publication_snapshots publication_snapshots_indicator_observation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.publication_snapshots
    ADD CONSTRAINT publication_snapshots_indicator_observation_id_fkey FOREIGN KEY (indicator_observation_id) REFERENCES public.indicator_observations(id) ON DELETE CASCADE;


--
-- Name: receipt_deliveries receipt_deliveries_receipt_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.receipt_deliveries
    ADD CONSTRAINT receipt_deliveries_receipt_id_fkey FOREIGN KEY (receipt_id) REFERENCES public.receipts(id) ON DELETE CASCADE;


--
-- Name: receipt_deliveries receipt_deliveries_status_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.receipt_deliveries
    ADD CONSTRAINT receipt_deliveries_status_code_fkey FOREIGN KEY (status_code) REFERENCES public.receipt_delivery_statuses(code);


--
-- Name: receipts receipts_donation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.receipts
    ADD CONSTRAINT receipts_donation_id_fkey FOREIGN KEY (donation_id) REFERENCES public.donations(id) ON DELETE RESTRICT;


--
-- Name: receipts receipts_superseded_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.receipts
    ADD CONSTRAINT receipts_superseded_by_fkey FOREIGN KEY (superseded_by) REFERENCES public.receipts(id) ON DELETE SET NULL;


--
-- Name: recurring_agreements recurring_agreements_donation_intent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recurring_agreements
    ADD CONSTRAINT recurring_agreements_donation_intent_id_fkey FOREIGN KEY (donation_intent_id) REFERENCES public.donation_intents(id) ON DELETE SET NULL;


--
-- Name: recurring_agreements recurring_agreements_frequency_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recurring_agreements
    ADD CONSTRAINT recurring_agreements_frequency_code_fkey FOREIGN KEY (frequency_code) REFERENCES public.donation_frequencies(code);


--
-- Name: recurring_agreements recurring_agreements_payment_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recurring_agreements
    ADD CONSTRAINT recurring_agreements_payment_customer_id_fkey FOREIGN KEY (payment_customer_id) REFERENCES public.payment_customers(id) ON DELETE SET NULL;


--
-- Name: recurring_agreements recurring_agreements_provider_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recurring_agreements
    ADD CONSTRAINT recurring_agreements_provider_code_fkey FOREIGN KEY (provider_code) REFERENCES public.payment_providers(code);


--
-- Name: refunds refunds_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refunds
    ADD CONSTRAINT refunds_created_by_fkey FOREIGN KEY (created_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: refunds refunds_donation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refunds
    ADD CONSTRAINT refunds_donation_id_fkey FOREIGN KEY (donation_id) REFERENCES public.donations(id) ON DELETE RESTRICT;


--
-- Name: resource_translations resource_translations_resource_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_translations
    ADD CONSTRAINT resource_translations_resource_id_fkey FOREIGN KEY (resource_id) REFERENCES public.resources(id) ON DELETE CASCADE;


--
-- Name: resources resources_publication_status_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resources
    ADD CONSTRAINT resources_publication_status_code_fkey FOREIGN KEY (publication_status_code) REFERENCES public.publication_statuses(code);


--
-- Name: result_links result_links_from_result_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.result_links
    ADD CONSTRAINT result_links_from_result_node_id_fkey FOREIGN KEY (from_result_node_id) REFERENCES public.result_nodes(id) ON DELETE CASCADE;


--
-- Name: result_links result_links_to_result_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.result_links
    ADD CONSTRAINT result_links_to_result_node_id_fkey FOREIGN KEY (to_result_node_id) REFERENCES public.result_nodes(id) ON DELETE CASCADE;


--
-- Name: result_node_translations result_node_translations_result_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.result_node_translations
    ADD CONSTRAINT result_node_translations_result_node_id_fkey FOREIGN KEY (result_node_id) REFERENCES public.result_nodes(id) ON DELETE CASCADE;


--
-- Name: result_nodes result_nodes_program_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.result_nodes
    ADD CONSTRAINT result_nodes_program_id_fkey FOREIGN KEY (program_id) REFERENCES public.programs(id) ON DELETE CASCADE;


--
-- Name: result_nodes result_nodes_result_level_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.result_nodes
    ADD CONSTRAINT result_nodes_result_level_code_fkey FOREIGN KEY (result_level_code) REFERENCES public.result_levels(code);


--
-- Name: role_permissions role_permissions_permission_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_permission_code_fkey FOREIGN KEY (permission_code) REFERENCES public.permissions(code) ON DELETE CASCADE;


--
-- Name: role_permissions role_permissions_role_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_role_code_fkey FOREIGN KEY (role_code) REFERENCES public.roles(code) ON DELETE CASCADE;


--
-- Name: security_events security_events_actor_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_events
    ADD CONSTRAINT security_events_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: security_events security_events_subject_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_events
    ADD CONSTRAINT security_events_subject_user_id_fkey FOREIGN KEY (subject_user_id) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: submission_status_history submission_status_history_changed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.submission_status_history
    ADD CONSTRAINT submission_status_history_changed_by_fkey FOREIGN KEY (changed_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: submission_status_history submission_status_history_from_status_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.submission_status_history
    ADD CONSTRAINT submission_status_history_from_status_code_fkey FOREIGN KEY (from_status_code) REFERENCES public.submission_statuses(code);


--
-- Name: submission_status_history submission_status_history_to_status_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.submission_status_history
    ADD CONSTRAINT submission_status_history_to_status_code_fkey FOREIGN KEY (to_status_code) REFERENCES public.submission_statuses(code);


--
-- Name: support_item_fulfillments support_item_fulfillments_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.support_item_fulfillments
    ADD CONSTRAINT support_item_fulfillments_created_by_fkey FOREIGN KEY (created_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: support_item_fulfillments support_item_fulfillments_donation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.support_item_fulfillments
    ADD CONSTRAINT support_item_fulfillments_donation_id_fkey FOREIGN KEY (donation_id) REFERENCES public.donations(id) ON DELETE SET NULL;


--
-- Name: support_item_fulfillments support_item_fulfillments_support_item_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.support_item_fulfillments
    ADD CONSTRAINT support_item_fulfillments_support_item_id_fkey FOREIGN KEY (support_item_id) REFERENCES public.support_items(id) ON DELETE CASCADE;


--
-- Name: support_item_translations support_item_translations_support_item_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.support_item_translations
    ADD CONSTRAINT support_item_translations_support_item_id_fkey FOREIGN KEY (support_item_id) REFERENCES public.support_items(id) ON DELETE CASCADE;


--
-- Name: support_items support_items_currency_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.support_items
    ADD CONSTRAINT support_items_currency_code_fkey FOREIGN KEY (currency_code) REFERENCES public.currencies(code);


--
-- Name: support_items support_items_fund_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.support_items
    ADD CONSTRAINT support_items_fund_id_fkey FOREIGN KEY (fund_id) REFERENCES public.funds(id) ON DELETE SET NULL;


--
-- Name: support_items support_items_initiative_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.support_items
    ADD CONSTRAINT support_items_initiative_id_fkey FOREIGN KEY (initiative_id) REFERENCES public.initiatives(id) ON DELETE CASCADE;


--
-- Name: survey_responses survey_responses_measurement_plan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.survey_responses
    ADD CONSTRAINT survey_responses_measurement_plan_id_fkey FOREIGN KEY (measurement_plan_id) REFERENCES public.measurement_plans(id) ON DELETE CASCADE;


--
-- Name: theories_of_change theories_of_change_program_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.theories_of_change
    ADD CONSTRAINT theories_of_change_program_id_fkey FOREIGN KEY (program_id) REFERENCES public.programs(id) ON DELETE CASCADE;


--
-- Name: trainer_application_snapshots trainer_application_snapshots_trainer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trainer_application_snapshots
    ADD CONSTRAINT trainer_application_snapshots_trainer_id_fkey FOREIGN KEY (trainer_id) REFERENCES public.trainers(id) ON DELETE CASCADE;


--
-- Name: trainers trainers_person_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trainers
    ADD CONSTRAINT trainers_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(id) ON DELETE RESTRICT;


--
-- Name: trainers trainers_reviewed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trainers
    ADD CONSTRAINT trainers_reviewed_by_fkey FOREIGN KEY (reviewed_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_academic_plans training_academic_plans_decided_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_academic_plans
    ADD CONSTRAINT training_academic_plans_decided_by_fkey FOREIGN KEY (decided_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_academic_plans training_academic_plans_submitted_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_academic_plans
    ADD CONSTRAINT training_academic_plans_submitted_by_fkey FOREIGN KEY (submitted_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_academic_plans training_academic_plans_training_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_academic_plans
    ADD CONSTRAINT training_academic_plans_training_id_fkey FOREIGN KEY (training_id) REFERENCES public.trainings(id) ON DELETE CASCADE;


--
-- Name: training_assessment_grades training_assessment_grades_assessment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_assessment_grades
    ADD CONSTRAINT training_assessment_grades_assessment_id_fkey FOREIGN KEY (assessment_id) REFERENCES public.training_assessments(id) ON DELETE RESTRICT;


--
-- Name: training_assessment_grades training_assessment_grades_graded_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_assessment_grades
    ADD CONSTRAINT training_assessment_grades_graded_by_fkey FOREIGN KEY (graded_by) REFERENCES auth.users(id) ON DELETE RESTRICT;


--
-- Name: training_assessment_grades training_assessment_grades_training_registration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_assessment_grades
    ADD CONSTRAINT training_assessment_grades_training_registration_id_fkey FOREIGN KEY (training_registration_id) REFERENCES public.training_registrations(id) ON DELETE CASCADE;


--
-- Name: training_assessments training_assessments_academic_plan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_assessments
    ADD CONSTRAINT training_assessments_academic_plan_id_fkey FOREIGN KEY (academic_plan_id) REFERENCES public.training_academic_plans(id) ON DELETE CASCADE;


--
-- Name: training_assignments training_assignments_assessment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_assignments
    ADD CONSTRAINT training_assignments_assessment_id_fkey FOREIGN KEY (assessment_id) REFERENCES public.training_assessments(id);


--
-- Name: training_assignments training_assignments_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_assignments
    ADD CONSTRAINT training_assignments_created_by_fkey FOREIGN KEY (created_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_assignments training_assignments_training_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_assignments
    ADD CONSTRAINT training_assignments_training_id_fkey FOREIGN KEY (training_id) REFERENCES public.trainings(id) ON DELETE CASCADE;


--
-- Name: training_attendance training_attendance_recorded_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_attendance
    ADD CONSTRAINT training_attendance_recorded_by_fkey FOREIGN KEY (recorded_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_attendance training_attendance_training_registration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_attendance
    ADD CONSTRAINT training_attendance_training_registration_id_fkey FOREIGN KEY (training_registration_id) REFERENCES public.training_registrations(id) ON DELETE CASCADE;


--
-- Name: training_attendance training_attendance_training_session_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_attendance
    ADD CONSTRAINT training_attendance_training_session_id_fkey FOREIGN KEY (training_session_id) REFERENCES public.training_sessions(id) ON DELETE CASCADE;


--
-- Name: training_certificate_reissue_authorizations training_certificate_reissue_auth_training_registration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_certificate_reissue_authorizations
    ADD CONSTRAINT training_certificate_reissue_auth_training_registration_id_fkey FOREIGN KEY (training_registration_id) REFERENCES public.training_registrations(id) ON DELETE CASCADE;


--
-- Name: training_certificate_reissue_authorizations training_certificate_reissue_autho_consumed_certificate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_certificate_reissue_authorizations
    ADD CONSTRAINT training_certificate_reissue_autho_consumed_certificate_id_fkey FOREIGN KEY (consumed_certificate_id) REFERENCES public.training_certificates(id) ON DELETE SET NULL;


--
-- Name: training_certificate_reissue_authorizations training_certificate_reissue_author_revoked_certificate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_certificate_reissue_authorizations
    ADD CONSTRAINT training_certificate_reissue_author_revoked_certificate_id_fkey FOREIGN KEY (revoked_certificate_id) REFERENCES public.training_certificates(id) ON DELETE CASCADE;


--
-- Name: training_certificate_reissue_authorizations training_certificate_reissue_authorizations_authorized_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_certificate_reissue_authorizations
    ADD CONSTRAINT training_certificate_reissue_authorizations_authorized_by_fkey FOREIGN KEY (authorized_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_certificates training_certificates_replaces_certificate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_certificates
    ADD CONSTRAINT training_certificates_replaces_certificate_id_fkey FOREIGN KEY (replaces_certificate_id) REFERENCES public.training_certificates(id) ON DELETE SET NULL;


--
-- Name: training_certificates training_certificates_training_registration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_certificates
    ADD CONSTRAINT training_certificates_training_registration_id_fkey FOREIGN KEY (training_registration_id) REFERENCES public.training_registrations(id) ON DELETE CASCADE;


--
-- Name: training_charges training_charges_training_registration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_charges
    ADD CONSTRAINT training_charges_training_registration_id_fkey FOREIGN KEY (training_registration_id) REFERENCES public.training_registrations(id) ON DELETE CASCADE;


--
-- Name: training_completion_rules training_completion_rules_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_completion_rules
    ADD CONSTRAINT training_completion_rules_created_by_fkey FOREIGN KEY (created_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_completion_rules training_completion_rules_training_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_completion_rules
    ADD CONSTRAINT training_completion_rules_training_id_fkey FOREIGN KEY (training_id) REFERENCES public.trainings(id) ON DELETE CASCADE;


--
-- Name: training_fee_access_exceptions training_fee_access_exceptions_decided_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_fee_access_exceptions
    ADD CONSTRAINT training_fee_access_exceptions_decided_by_fkey FOREIGN KEY (decided_by) REFERENCES auth.users(id) ON DELETE RESTRICT;


--
-- Name: training_fee_access_exceptions training_fee_access_exceptions_requested_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_fee_access_exceptions
    ADD CONSTRAINT training_fee_access_exceptions_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES auth.users(id) ON DELETE RESTRICT;


--
-- Name: training_fee_access_exceptions training_fee_access_exceptions_revoked_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_fee_access_exceptions
    ADD CONSTRAINT training_fee_access_exceptions_revoked_by_fkey FOREIGN KEY (revoked_by) REFERENCES auth.users(id) ON DELETE RESTRICT;


--
-- Name: training_fee_access_exceptions training_fee_access_exceptions_training_registration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_fee_access_exceptions
    ADD CONSTRAINT training_fee_access_exceptions_training_registration_id_fkey FOREIGN KEY (training_registration_id) REFERENCES public.training_registrations(id) ON DELETE CASCADE;


--
-- Name: training_fee_proof_submissions training_fee_proof_submissions_resulting_transaction_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_fee_proof_submissions
    ADD CONSTRAINT training_fee_proof_submissions_resulting_transaction_id_fkey FOREIGN KEY (resulting_transaction_id) REFERENCES public.training_fee_transactions(id) ON DELETE SET NULL;


--
-- Name: training_fee_proof_submissions training_fee_proof_submissions_reviewed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_fee_proof_submissions
    ADD CONSTRAINT training_fee_proof_submissions_reviewed_by_fkey FOREIGN KEY (reviewed_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_fee_proof_submissions training_fee_proof_submissions_submitted_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_fee_proof_submissions
    ADD CONSTRAINT training_fee_proof_submissions_submitted_by_fkey FOREIGN KEY (submitted_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_fee_proof_submissions training_fee_proof_submissions_training_charge_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_fee_proof_submissions
    ADD CONSTRAINT training_fee_proof_submissions_training_charge_id_fkey FOREIGN KEY (training_charge_id) REFERENCES public.training_charges(id) ON DELETE CASCADE;


--
-- Name: training_fee_refunds training_fee_refunds_decided_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_fee_refunds
    ADD CONSTRAINT training_fee_refunds_decided_by_fkey FOREIGN KEY (decided_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_fee_refunds training_fee_refunds_recorded_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_fee_refunds
    ADD CONSTRAINT training_fee_refunds_recorded_by_fkey FOREIGN KEY (recorded_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_fee_refunds training_fee_refunds_training_charge_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_fee_refunds
    ADD CONSTRAINT training_fee_refunds_training_charge_id_fkey FOREIGN KEY (training_charge_id) REFERENCES public.training_charges(id) ON DELETE CASCADE;


--
-- Name: training_fee_transactions training_fee_transactions_proof_submission_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_fee_transactions
    ADD CONSTRAINT training_fee_transactions_proof_submission_id_fkey FOREIGN KEY (proof_submission_id) REFERENCES public.training_fee_proof_submissions(id) ON DELETE SET NULL;


--
-- Name: training_fee_transactions training_fee_transactions_recorded_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_fee_transactions
    ADD CONSTRAINT training_fee_transactions_recorded_by_fkey FOREIGN KEY (recorded_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_fee_transactions training_fee_transactions_training_charge_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_fee_transactions
    ADD CONSTRAINT training_fee_transactions_training_charge_id_fkey FOREIGN KEY (training_charge_id) REFERENCES public.training_charges(id) ON DELETE CASCADE;


--
-- Name: training_fee_transactions training_fee_transactions_verified_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_fee_transactions
    ADD CONSTRAINT training_fee_transactions_verified_by_fkey FOREIGN KEY (verified_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_feedback training_feedback_training_registration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_feedback
    ADD CONSTRAINT training_feedback_training_registration_id_fkey FOREIGN KEY (training_registration_id) REFERENCES public.training_registrations(id) ON DELETE CASCADE;


--
-- Name: training_final_grades training_final_grades_academic_plan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_final_grades
    ADD CONSTRAINT training_final_grades_academic_plan_id_fkey FOREIGN KEY (academic_plan_id) REFERENCES public.training_academic_plans(id) ON DELETE RESTRICT;


--
-- Name: training_final_grades training_final_grades_approved_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_final_grades
    ADD CONSTRAINT training_final_grades_approved_by_fkey FOREIGN KEY (approved_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_final_grades training_final_grades_submitted_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_final_grades
    ADD CONSTRAINT training_final_grades_submitted_by_fkey FOREIGN KEY (submitted_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_final_grades training_final_grades_training_registration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_final_grades
    ADD CONSTRAINT training_final_grades_training_registration_id_fkey FOREIGN KEY (training_registration_id) REFERENCES public.training_registrations(id) ON DELETE CASCADE;


--
-- Name: training_materials training_materials_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_materials
    ADD CONSTRAINT training_materials_created_by_fkey FOREIGN KEY (created_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_materials training_materials_training_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_materials
    ADD CONSTRAINT training_materials_training_id_fkey FOREIGN KEY (training_id) REFERENCES public.trainings(id) ON DELETE CASCADE;


--
-- Name: training_prerequisite_decisions training_prerequisite_decisions_prerequisite_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_prerequisite_decisions
    ADD CONSTRAINT training_prerequisite_decisions_prerequisite_id_fkey FOREIGN KEY (prerequisite_id) REFERENCES public.training_prerequisites(id) ON DELETE CASCADE;


--
-- Name: training_prerequisite_decisions training_prerequisite_decisions_requested_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_prerequisite_decisions
    ADD CONSTRAINT training_prerequisite_decisions_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_prerequisite_decisions training_prerequisite_decisions_reviewed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_prerequisite_decisions
    ADD CONSTRAINT training_prerequisite_decisions_reviewed_by_fkey FOREIGN KEY (reviewed_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_prerequisite_decisions training_prerequisite_decisions_training_registration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_prerequisite_decisions
    ADD CONSTRAINT training_prerequisite_decisions_training_registration_id_fkey FOREIGN KEY (training_registration_id) REFERENCES public.training_registrations(id) ON DELETE CASCADE;


--
-- Name: training_prerequisite_evidence training_prerequisite_evidence_prerequisite_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_prerequisite_evidence
    ADD CONSTRAINT training_prerequisite_evidence_prerequisite_id_fkey FOREIGN KEY (prerequisite_id) REFERENCES public.training_prerequisites(id) ON DELETE CASCADE;


--
-- Name: training_prerequisite_evidence training_prerequisite_evidence_reviewed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_prerequisite_evidence
    ADD CONSTRAINT training_prerequisite_evidence_reviewed_by_fkey FOREIGN KEY (reviewed_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_prerequisite_evidence training_prerequisite_evidence_submitted_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_prerequisite_evidence
    ADD CONSTRAINT training_prerequisite_evidence_submitted_by_fkey FOREIGN KEY (submitted_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_prerequisite_evidence training_prerequisite_evidence_training_registration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_prerequisite_evidence
    ADD CONSTRAINT training_prerequisite_evidence_training_registration_id_fkey FOREIGN KEY (training_registration_id) REFERENCES public.training_registrations(id) ON DELETE CASCADE;


--
-- Name: training_prerequisites training_prerequisites_source_training_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_prerequisites
    ADD CONSTRAINT training_prerequisites_source_training_id_fkey FOREIGN KEY (source_training_id) REFERENCES public.trainings(id) ON DELETE CASCADE;


--
-- Name: training_prerequisites training_prerequisites_training_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_prerequisites
    ADD CONSTRAINT training_prerequisites_training_id_fkey FOREIGN KEY (training_id) REFERENCES public.trainings(id) ON DELETE CASCADE;


--
-- Name: training_question_bank_questions training_question_bank_questions_question_bank_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_question_bank_questions
    ADD CONSTRAINT training_question_bank_questions_question_bank_id_fkey FOREIGN KEY (question_bank_id) REFERENCES public.training_question_banks(id) ON DELETE CASCADE;


--
-- Name: training_question_banks training_question_banks_owner_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_question_banks
    ADD CONSTRAINT training_question_banks_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id) ON DELETE RESTRICT;


--
-- Name: training_quiz_accommodations training_quiz_accommodations_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_accommodations
    ADD CONSTRAINT training_quiz_accommodations_created_by_fkey FOREIGN KEY (created_by) REFERENCES auth.users(id) ON DELETE RESTRICT;


--
-- Name: training_quiz_accommodations training_quiz_accommodations_quiz_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_accommodations
    ADD CONSTRAINT training_quiz_accommodations_quiz_id_fkey FOREIGN KEY (quiz_id) REFERENCES public.training_quizzes(id) ON DELETE CASCADE;


--
-- Name: training_quiz_accommodations training_quiz_accommodations_training_registration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_accommodations
    ADD CONSTRAINT training_quiz_accommodations_training_registration_id_fkey FOREIGN KEY (training_registration_id) REFERENCES public.training_registrations(id) ON DELETE CASCADE;


--
-- Name: training_quiz_answers training_quiz_answers_graded_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_answers
    ADD CONSTRAINT training_quiz_answers_graded_by_fkey FOREIGN KEY (graded_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_quiz_answers training_quiz_answers_quiz_attempt_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_answers
    ADD CONSTRAINT training_quiz_answers_quiz_attempt_id_fkey FOREIGN KEY (quiz_attempt_id) REFERENCES public.training_quiz_attempts(id) ON DELETE CASCADE;


--
-- Name: training_quiz_answers training_quiz_answers_quiz_question_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_answers
    ADD CONSTRAINT training_quiz_answers_quiz_question_id_fkey FOREIGN KEY (quiz_question_id) REFERENCES public.training_quiz_questions(id) ON DELETE RESTRICT;


--
-- Name: training_quiz_attempts training_quiz_attempts_quiz_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_attempts
    ADD CONSTRAINT training_quiz_attempts_quiz_id_fkey FOREIGN KEY (quiz_id) REFERENCES public.training_quizzes(id) ON DELETE RESTRICT;


--
-- Name: training_quiz_attempts training_quiz_attempts_training_registration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_attempts
    ADD CONSTRAINT training_quiz_attempts_training_registration_id_fkey FOREIGN KEY (training_registration_id) REFERENCES public.training_registrations(id) ON DELETE RESTRICT;


--
-- Name: training_quiz_grade_overrides training_quiz_grade_overrides_overridden_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_grade_overrides
    ADD CONSTRAINT training_quiz_grade_overrides_overridden_by_fkey FOREIGN KEY (overridden_by) REFERENCES auth.users(id) ON DELETE RESTRICT;


--
-- Name: training_quiz_grade_overrides training_quiz_grade_overrides_quiz_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_grade_overrides
    ADD CONSTRAINT training_quiz_grade_overrides_quiz_id_fkey FOREIGN KEY (quiz_id) REFERENCES public.training_quizzes(id) ON DELETE RESTRICT;


--
-- Name: training_quiz_grade_overrides training_quiz_grade_overrides_training_registration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_grade_overrides
    ADD CONSTRAINT training_quiz_grade_overrides_training_registration_id_fkey FOREIGN KEY (training_registration_id) REFERENCES public.training_registrations(id) ON DELETE RESTRICT;


--
-- Name: training_quiz_question_adjustments training_quiz_question_adjustments_decided_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_question_adjustments
    ADD CONSTRAINT training_quiz_question_adjustments_decided_by_fkey FOREIGN KEY (decided_by) REFERENCES auth.users(id) ON DELETE RESTRICT;


--
-- Name: training_quiz_question_adjustments training_quiz_question_adjustments_quiz_question_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_question_adjustments
    ADD CONSTRAINT training_quiz_question_adjustments_quiz_question_id_fkey FOREIGN KEY (quiz_question_id) REFERENCES public.training_quiz_questions(id) ON DELETE CASCADE;


--
-- Name: training_quiz_questions training_quiz_questions_quiz_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_questions
    ADD CONSTRAINT training_quiz_questions_quiz_id_fkey FOREIGN KEY (quiz_id) REFERENCES public.training_quizzes(id) ON DELETE CASCADE;


--
-- Name: training_quiz_questions training_quiz_questions_source_question_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quiz_questions
    ADD CONSTRAINT training_quiz_questions_source_question_id_fkey FOREIGN KEY (source_question_id) REFERENCES public.training_question_bank_questions(id) ON DELETE SET NULL;


--
-- Name: training_quizzes training_quizzes_assessment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quizzes
    ADD CONSTRAINT training_quizzes_assessment_id_fkey FOREIGN KEY (assessment_id) REFERENCES public.training_assessments(id) ON DELETE RESTRICT;


--
-- Name: training_quizzes training_quizzes_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quizzes
    ADD CONSTRAINT training_quizzes_created_by_fkey FOREIGN KEY (created_by) REFERENCES auth.users(id) ON DELETE RESTRICT;


--
-- Name: training_quizzes training_quizzes_training_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_quizzes
    ADD CONSTRAINT training_quizzes_training_id_fkey FOREIGN KEY (training_id) REFERENCES public.trainings(id) ON DELETE CASCADE;


--
-- Name: training_registration_status_history training_registration_status_hist_training_registration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_registration_status_history
    ADD CONSTRAINT training_registration_status_hist_training_registration_id_fkey FOREIGN KEY (training_registration_id) REFERENCES public.training_registrations(id) ON DELETE CASCADE;


--
-- Name: training_registration_status_history training_registration_status_history_actor_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_registration_status_history
    ADD CONSTRAINT training_registration_status_history_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_registrations training_registrations_person_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_registrations
    ADD CONSTRAINT training_registrations_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(id) ON DELETE SET NULL;


--
-- Name: training_registrations training_registrations_reviewed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_registrations
    ADD CONSTRAINT training_registrations_reviewed_by_fkey FOREIGN KEY (reviewed_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_registrations training_registrations_training_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_registrations
    ADD CONSTRAINT training_registrations_training_id_fkey FOREIGN KEY (training_id) REFERENCES public.trainings(id) ON DELETE CASCADE;


--
-- Name: training_sessions training_sessions_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_sessions
    ADD CONSTRAINT training_sessions_created_by_fkey FOREIGN KEY (created_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_sessions training_sessions_training_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_sessions
    ADD CONSTRAINT training_sessions_training_id_fkey FOREIGN KEY (training_id) REFERENCES public.trainings(id) ON DELETE CASCADE;


--
-- Name: training_submissions training_submissions_graded_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_submissions
    ADD CONSTRAINT training_submissions_graded_by_fkey FOREIGN KEY (graded_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_submissions training_submissions_training_assignment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_submissions
    ADD CONSTRAINT training_submissions_training_assignment_id_fkey FOREIGN KEY (training_assignment_id) REFERENCES public.training_assignments(id) ON DELETE CASCADE;


--
-- Name: training_submissions training_submissions_training_registration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_submissions
    ADD CONSTRAINT training_submissions_training_registration_id_fkey FOREIGN KEY (training_registration_id) REFERENCES public.training_registrations(id) ON DELETE CASCADE;


--
-- Name: training_task_assessment_overrides training_task_assessment_override_training_registration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_task_assessment_overrides
    ADD CONSTRAINT training_task_assessment_override_training_registration_id_fkey FOREIGN KEY (training_registration_id) REFERENCES public.training_registrations(id) ON DELETE CASCADE;


--
-- Name: training_task_assessment_overrides training_task_assessment_overrides_assessment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_task_assessment_overrides
    ADD CONSTRAINT training_task_assessment_overrides_assessment_id_fkey FOREIGN KEY (assessment_id) REFERENCES public.training_assessments(id);


--
-- Name: training_task_assessment_overrides training_task_assessment_overrides_overridden_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_task_assessment_overrides
    ADD CONSTRAINT training_task_assessment_overrides_overridden_by_fkey FOREIGN KEY (overridden_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_task_marks training_task_marks_marked_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_task_marks
    ADD CONSTRAINT training_task_marks_marked_by_fkey FOREIGN KEY (marked_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: training_task_marks training_task_marks_training_assignment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_task_marks
    ADD CONSTRAINT training_task_marks_training_assignment_id_fkey FOREIGN KEY (training_assignment_id) REFERENCES public.training_assignments(id) ON DELETE CASCADE;


--
-- Name: training_task_marks training_task_marks_training_registration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_task_marks
    ADD CONSTRAINT training_task_marks_training_registration_id_fkey FOREIGN KEY (training_registration_id) REFERENCES public.training_registrations(id) ON DELETE CASCADE;


--
-- Name: training_translations training_translations_training_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_translations
    ADD CONSTRAINT training_translations_training_id_fkey FOREIGN KEY (training_id) REFERENCES public.trainings(id) ON DELETE CASCADE;


--
-- Name: training_waitlist_entries training_waitlist_entries_training_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_waitlist_entries
    ADD CONSTRAINT training_waitlist_entries_training_id_fkey FOREIGN KEY (training_id) REFERENCES public.trainings(id) ON DELETE CASCADE;


--
-- Name: training_waitlist_entries training_waitlist_entries_training_registration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.training_waitlist_entries
    ADD CONSTRAINT training_waitlist_entries_training_registration_id_fkey FOREIGN KEY (training_registration_id) REFERENCES public.training_registrations(id) ON DELETE CASCADE;


--
-- Name: trainings trainings_fee_currency_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trainings
    ADD CONSTRAINT trainings_fee_currency_code_fkey FOREIGN KEY (fee_currency_code) REFERENCES public.currencies(code);


--
-- Name: trainings trainings_publication_status_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trainings
    ADD CONSTRAINT trainings_publication_status_code_fkey FOREIGN KEY (publication_status_code) REFERENCES public.publication_statuses(code);


--
-- Name: trainings trainings_trainer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trainings
    ADD CONSTRAINT trainings_trainer_id_fkey FOREIGN KEY (trainer_id) REFERENCES public.trainers(id) ON DELETE RESTRICT;


--
-- Name: user_invitations user_invitations_invited_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_invitations
    ADD CONSTRAINT user_invitations_invited_by_fkey FOREIGN KEY (invited_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: user_invitations user_invitations_person_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_invitations
    ADD CONSTRAINT user_invitations_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(id) ON DELETE SET NULL;


--
-- Name: user_profiles user_profiles_person_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_profiles
    ADD CONSTRAINT user_profiles_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(id) ON DELETE RESTRICT;


--
-- Name: user_profiles user_profiles_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_profiles
    ADD CONSTRAINT user_profiles_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: user_role_assignments user_role_assignments_granted_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_role_assignments
    ADD CONSTRAINT user_role_assignments_granted_by_fkey FOREIGN KEY (granted_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: user_role_assignments user_role_assignments_role_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_role_assignments
    ADD CONSTRAINT user_role_assignments_role_code_fkey FOREIGN KEY (role_code) REFERENCES public.roles(code) ON DELETE RESTRICT;


--
-- Name: user_role_assignments user_role_assignments_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_role_assignments
    ADD CONSTRAINT user_role_assignments_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: verification_reviews verification_reviews_indicator_observation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.verification_reviews
    ADD CONSTRAINT verification_reviews_indicator_observation_id_fkey FOREIGN KEY (indicator_observation_id) REFERENCES public.indicator_observations(id) ON DELETE CASCADE;


--
-- Name: verification_reviews verification_reviews_reviewer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.verification_reviews
    ADD CONSTRAINT verification_reviews_reviewer_id_fkey FOREIGN KEY (reviewer_id) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: volunteer_applications volunteer_applications_person_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.volunteer_applications
    ADD CONSTRAINT volunteer_applications_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(id) ON DELETE SET NULL;


--
-- Name: volunteer_applications volunteer_applications_status_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.volunteer_applications
    ADD CONSTRAINT volunteer_applications_status_code_fkey FOREIGN KEY (status_code) REFERENCES public.submission_statuses(code);


--
-- Name: attendance_records attendance_records_enrollment_id_fkey; Type: FK CONSTRAINT; Schema: restricted; Owner: -
--

ALTER TABLE ONLY restricted.attendance_records
    ADD CONSTRAINT attendance_records_enrollment_id_fkey FOREIGN KEY (enrollment_id) REFERENCES restricted.program_enrollments(id) ON DELETE CASCADE;


--
-- Name: beneficiary_records beneficiary_records_site_id_fkey; Type: FK CONSTRAINT; Schema: restricted; Owner: -
--

ALTER TABLE ONLY restricted.beneficiary_records
    ADD CONSTRAINT beneficiary_records_site_id_fkey FOREIGN KEY (site_id) REFERENCES public.sites(id) ON DELETE SET NULL;


--
-- Name: guardian_relationships guardian_relationships_beneficiary_id_fkey; Type: FK CONSTRAINT; Schema: restricted; Owner: -
--

ALTER TABLE ONLY restricted.guardian_relationships
    ADD CONSTRAINT guardian_relationships_beneficiary_id_fkey FOREIGN KEY (beneficiary_id) REFERENCES restricted.beneficiary_records(id) ON DELETE CASCADE;


--
-- Name: guardian_relationships guardian_relationships_guardian_person_id_fkey; Type: FK CONSTRAINT; Schema: restricted; Owner: -
--

ALTER TABLE ONLY restricted.guardian_relationships
    ADD CONSTRAINT guardian_relationships_guardian_person_id_fkey FOREIGN KEY (guardian_person_id) REFERENCES public.people(id) ON DELETE RESTRICT;


--
-- Name: participation_consents participation_consents_beneficiary_id_fkey; Type: FK CONSTRAINT; Schema: restricted; Owner: -
--

ALTER TABLE ONLY restricted.participation_consents
    ADD CONSTRAINT participation_consents_beneficiary_id_fkey FOREIGN KEY (beneficiary_id) REFERENCES restricted.beneficiary_records(id) ON DELETE CASCADE;


--
-- Name: participation_consents participation_consents_granted_by_person_id_fkey; Type: FK CONSTRAINT; Schema: restricted; Owner: -
--

ALTER TABLE ONLY restricted.participation_consents
    ADD CONSTRAINT participation_consents_granted_by_person_id_fkey FOREIGN KEY (granted_by_person_id) REFERENCES public.people(id) ON DELETE SET NULL;


--
-- Name: program_enrollments program_enrollments_beneficiary_id_fkey; Type: FK CONSTRAINT; Schema: restricted; Owner: -
--

ALTER TABLE ONLY restricted.program_enrollments
    ADD CONSTRAINT program_enrollments_beneficiary_id_fkey FOREIGN KEY (beneficiary_id) REFERENCES restricted.beneficiary_records(id) ON DELETE CASCADE;


--
-- Name: program_enrollments program_enrollments_cohort_id_fkey; Type: FK CONSTRAINT; Schema: restricted; Owner: -
--

ALTER TABLE ONLY restricted.program_enrollments
    ADD CONSTRAINT program_enrollments_cohort_id_fkey FOREIGN KEY (cohort_id) REFERENCES public.cohorts(id) ON DELETE CASCADE;


--
-- Name: referrals referrals_beneficiary_id_fkey; Type: FK CONSTRAINT; Schema: restricted; Owner: -
--

ALTER TABLE ONLY restricted.referrals
    ADD CONSTRAINT referrals_beneficiary_id_fkey FOREIGN KEY (beneficiary_id) REFERENCES restricted.beneficiary_records(id) ON DELETE CASCADE;


--
-- Name: referrals referrals_referred_by_fkey; Type: FK CONSTRAINT; Schema: restricted; Owner: -
--

ALTER TABLE ONLY restricted.referrals
    ADD CONSTRAINT referrals_referred_by_fkey FOREIGN KEY (referred_by) REFERENCES auth.users(id) ON DELETE SET NULL;


--
-- Name: app_modules; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.app_modules ENABLE ROW LEVEL SECURITY;

--
-- Name: app_modules app_modules_super_admin_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY app_modules_super_admin_read ON public.app_modules FOR SELECT USING (public.current_user_has_role('super_admin'::text));


--
-- Name: app_modules app_modules_super_admin_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY app_modules_super_admin_write ON public.app_modules USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: assessment_instruments; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.assessment_instruments ENABLE ROW LEVEL SECURITY;

--
-- Name: assessment_instruments assessment_instruments_impact_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY assessment_instruments_impact_manage ON public.assessment_instruments USING (public.current_user_has_permission('impact.manage'::text)) WITH CHECK (public.current_user_has_permission('impact.manage'::text));


--
-- Name: assessment_instruments assessment_instruments_impact_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY assessment_instruments_impact_read ON public.assessment_instruments FOR SELECT USING (public.current_user_has_any_permission('impact.read'::text));


--
-- Name: assessment_scores; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.assessment_scores ENABLE ROW LEVEL SECURITY;

--
-- Name: assessment_scores assessment_scores_authorized; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY assessment_scores_authorized ON public.assessment_scores USING ((EXISTS ( SELECT 1
   FROM public.assessment_sessions s
  WHERE ((s.id = assessment_scores.assessment_session_id) AND (s.cohort_id IS NOT NULL) AND public.current_user_can_access_cohort(s.cohort_id, 'impact.manage'::text))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM public.assessment_sessions s
  WHERE ((s.id = assessment_scores.assessment_session_id) AND (s.cohort_id IS NOT NULL) AND public.current_user_can_access_cohort(s.cohort_id, 'impact.manage'::text)))));


--
-- Name: assessment_scores assessment_scores_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY assessment_scores_authorized_read ON public.assessment_scores FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.assessment_sessions s
  WHERE ((s.id = assessment_scores.assessment_session_id) AND (((s.cohort_id IS NULL) AND public.current_user_has_permission('impact.read'::text)) OR public.current_user_can_access_cohort(s.cohort_id, 'impact.read'::text))))));


--
-- Name: assessment_sessions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.assessment_sessions ENABLE ROW LEVEL SECURITY;

--
-- Name: assessment_sessions assessment_sessions_authorized; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY assessment_sessions_authorized ON public.assessment_sessions USING ((((cohort_id IS NULL) AND public.current_user_has_permission('impact.manage'::text)) OR public.current_user_can_access_cohort(cohort_id, 'impact.manage'::text))) WITH CHECK ((((cohort_id IS NULL) AND public.current_user_has_permission('impact.manage'::text)) OR public.current_user_can_access_cohort(cohort_id, 'impact.manage'::text)));


--
-- Name: assessment_sessions assessment_sessions_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY assessment_sessions_authorized_read ON public.assessment_sessions FOR SELECT USING ((((cohort_id IS NULL) AND public.current_user_has_permission('impact.read'::text)) OR public.current_user_can_access_cohort(cohort_id, 'impact.read'::text)));


--
-- Name: assignments; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.assignments ENABLE ROW LEVEL SECURITY;

--
-- Name: assignments assignments_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY assignments_auditor_read ON public.assignments FOR SELECT USING (public.current_user_has_permission('intake.read'::text));


--
-- Name: assignments assignments_intake_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY assignments_intake_manage ON public.assignments USING (public.current_user_has_permission('intake.manage'::text)) WITH CHECK (public.current_user_has_permission('intake.manage'::text));


--
-- Name: audit_log; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.audit_log ENABLE ROW LEVEL SECURITY;

--
-- Name: audit_log audit_log_admin_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY audit_log_admin_read ON public.audit_log FOR SELECT USING ((public.current_user_has_role('super_admin'::text) OR public.current_user_has_role('admin'::text) OR public.current_user_has_role('auditor'::text)));


--
-- Name: POLICY audit_log_admin_read ON audit_log; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON POLICY audit_log_admin_read ON public.audit_log IS 'No insert/update/delete policy: audit rows are written only by triggers/server code running as the service role, and can never be edited or removed through the API.';


--
-- Name: audit_log audit_log_credential_self_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY audit_log_credential_self_read ON public.audit_log FOR SELECT USING (((table_name = 'professional_credentials'::text) AND (record_id IN ( SELECT professional_credentials.id
   FROM public.professional_credentials
  WHERE (professional_credentials.trainer_id = public.current_user_trainer_id())))));


--
-- Name: cohorts; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.cohorts ENABLE ROW LEVEL SECURITY;

--
-- Name: cohorts cohorts_authorized_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY cohorts_authorized_manage ON public.cohorts USING (public.current_user_can_access_program_cycle(program_cycle_id, 'impact.manage'::text)) WITH CHECK (public.current_user_can_access_program_cycle(program_cycle_id, 'impact.manage'::text));


--
-- Name: cohorts cohorts_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY cohorts_authorized_read ON public.cohorts FOR SELECT USING (public.current_user_can_access_program_cycle(program_cycle_id, 'impact.read'::text));


--
-- Name: consent_records; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.consent_records ENABLE ROW LEVEL SECURITY;

--
-- Name: consent_records consent_records_admin_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY consent_records_admin_manage ON public.consent_records USING (public.current_user_has_permission('people.manage'::text)) WITH CHECK (public.current_user_has_permission('people.manage'::text));


--
-- Name: consent_records consent_records_self_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY consent_records_self_read ON public.consent_records FOR SELECT USING ((person_id = public.current_person_id()));


--
-- Name: contact_submissions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.contact_submissions ENABLE ROW LEVEL SECURITY;

--
-- Name: contact_submissions contact_submissions_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY contact_submissions_auditor_read ON public.contact_submissions FOR SELECT USING (public.current_user_has_role('auditor'::text));


--
-- Name: contact_submissions contact_submissions_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY contact_submissions_manage ON public.contact_submissions USING (public.current_user_can_manage_intake()) WITH CHECK (public.current_user_can_manage_intake());


--
-- Name: currencies; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.currencies ENABLE ROW LEVEL SECURITY;

--
-- Name: currencies currencies_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY currencies_public_read ON public.currencies FOR SELECT USING (true);


--
-- Name: currencies currencies_super_admin_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY currencies_super_admin_write ON public.currencies USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: data_quality_assessments; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.data_quality_assessments ENABLE ROW LEVEL SECURITY;

--
-- Name: data_quality_assessments data_quality_assessments_authorized; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY data_quality_assessments_authorized ON public.data_quality_assessments USING (public.current_user_can_access_observation(indicator_observation_id, 'impact.manage'::text)) WITH CHECK (public.current_user_can_access_observation(indicator_observation_id, 'impact.manage'::text));


--
-- Name: data_quality_assessments data_quality_assessments_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY data_quality_assessments_authorized_read ON public.data_quality_assessments FOR SELECT USING (public.current_user_can_access_observation(indicator_observation_id, 'impact.read'::text));


--
-- Name: donation_allocations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.donation_allocations ENABLE ROW LEVEL SECURITY;

--
-- Name: donation_allocations donation_allocations_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY donation_allocations_auditor_read ON public.donation_allocations FOR SELECT USING (public.current_user_has_permission('finance.read'::text));


--
-- Name: donation_allocations donation_allocations_finance_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY donation_allocations_finance_manage ON public.donation_allocations USING (public.current_user_has_permission('finance.manage'::text)) WITH CHECK (public.current_user_has_permission('finance.manage'::text));


--
-- Name: donation_allocations donation_allocations_self_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY donation_allocations_self_read ON public.donation_allocations FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.donations d
  WHERE ((d.id = donation_allocations.donation_id) AND (d.person_id = public.current_person_id())))));


--
-- Name: donation_frequencies; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.donation_frequencies ENABLE ROW LEVEL SECURITY;

--
-- Name: donation_frequencies donation_frequencies_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY donation_frequencies_public_read ON public.donation_frequencies FOR SELECT USING (true);


--
-- Name: donation_frequencies donation_frequencies_super_admin_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY donation_frequencies_super_admin_write ON public.donation_frequencies USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: donation_intents; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.donation_intents ENABLE ROW LEVEL SECURITY;

--
-- Name: donation_intents donation_intents_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY donation_intents_auditor_read ON public.donation_intents FOR SELECT USING (public.current_user_has_permission('finance.read'::text));


--
-- Name: donation_intents donation_intents_finance_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY donation_intents_finance_manage ON public.donation_intents USING (public.current_user_has_permission('finance.manage'::text)) WITH CHECK (public.current_user_has_permission('finance.manage'::text));


--
-- Name: donation_intents donation_intents_self_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY donation_intents_self_read ON public.donation_intents FOR SELECT USING ((person_id = public.current_person_id()));


--
-- Name: donation_statuses; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.donation_statuses ENABLE ROW LEVEL SECURITY;

--
-- Name: donation_statuses donation_statuses_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY donation_statuses_public_read ON public.donation_statuses FOR SELECT USING (true);


--
-- Name: donation_statuses donation_statuses_super_admin_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY donation_statuses_super_admin_write ON public.donation_statuses USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: donations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.donations ENABLE ROW LEVEL SECURITY;

--
-- Name: donations donations_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY donations_auditor_read ON public.donations FOR SELECT USING (public.current_user_has_permission('finance.read'::text));


--
-- Name: donations donations_finance_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY donations_finance_manage ON public.donations USING (public.current_user_has_permission('finance.manage'::text)) WITH CHECK (public.current_user_has_permission('finance.manage'::text));


--
-- Name: donations donations_self_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY donations_self_read ON public.donations FOR SELECT USING ((person_id = public.current_person_id()));


--
-- Name: evidence_artifacts; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.evidence_artifacts ENABLE ROW LEVEL SECURITY;

--
-- Name: evidence_artifacts evidence_artifacts_authorized; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY evidence_artifacts_authorized ON public.evidence_artifacts USING ((((indicator_observation_id IS NULL) AND public.current_user_has_permission('impact.manage'::text)) OR public.current_user_can_access_observation(indicator_observation_id, 'impact.manage'::text))) WITH CHECK ((((indicator_observation_id IS NULL) AND public.current_user_has_permission('impact.manage'::text)) OR public.current_user_can_access_observation(indicator_observation_id, 'impact.manage'::text)));


--
-- Name: evidence_artifacts evidence_artifacts_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY evidence_artifacts_authorized_read ON public.evidence_artifacts FOR SELECT USING ((((indicator_observation_id IS NULL) AND public.current_user_has_permission('impact.read'::text)) OR public.current_user_can_access_observation(indicator_observation_id, 'impact.read'::text)));


--
-- Name: fund_types; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.fund_types ENABLE ROW LEVEL SECURITY;

--
-- Name: fund_types fund_types_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY fund_types_public_read ON public.fund_types FOR SELECT USING (true);


--
-- Name: fund_types fund_types_super_admin_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY fund_types_super_admin_write ON public.fund_types USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: funds; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.funds ENABLE ROW LEVEL SECURITY;

--
-- Name: funds funds_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY funds_auditor_read ON public.funds FOR SELECT USING (public.current_user_has_permission('funds.read'::text));


--
-- Name: funds funds_finance_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY funds_finance_manage ON public.funds USING (public.current_user_has_permission('funds.manage'::text)) WITH CHECK (public.current_user_has_permission('funds.manage'::text));


--
-- Name: funds funds_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY funds_public_read ON public.funds FOR SELECT USING ((archived_at IS NULL));


--
-- Name: governance_appointments; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.governance_appointments ENABLE ROW LEVEL SECURITY;

--
-- Name: governance_appointments governance_appointments_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY governance_appointments_auditor_read ON public.governance_appointments FOR SELECT USING (public.current_user_has_permission('team.read'::text));


--
-- Name: governance_appointments governance_appointments_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY governance_appointments_public_read ON public.governance_appointments FOR SELECT USING (true);


--
-- Name: governance_appointments governance_appointments_team_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY governance_appointments_team_manage ON public.governance_appointments USING (public.current_user_has_permission('team.manage'::text)) WITH CHECK (public.current_user_has_permission('team.manage'::text));


--
-- Name: governance_roles; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.governance_roles ENABLE ROW LEVEL SECURITY;

--
-- Name: governance_roles governance_roles_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY governance_roles_public_read ON public.governance_roles FOR SELECT USING (true);


--
-- Name: governance_roles governance_roles_super_admin_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY governance_roles_super_admin_write ON public.governance_roles USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: indicator_baselines; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.indicator_baselines ENABLE ROW LEVEL SECURITY;

--
-- Name: indicator_baselines indicator_baselines_authorized; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY indicator_baselines_authorized ON public.indicator_baselines USING (public.current_user_can_access_measurement_plan(measurement_plan_id, 'impact.manage'::text)) WITH CHECK (public.current_user_can_access_measurement_plan(measurement_plan_id, 'impact.manage'::text));


--
-- Name: indicator_baselines indicator_baselines_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY indicator_baselines_authorized_read ON public.indicator_baselines FOR SELECT USING (public.current_user_can_access_measurement_plan(measurement_plan_id, 'impact.read'::text));


--
-- Name: indicator_definitions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.indicator_definitions ENABLE ROW LEVEL SECURITY;

--
-- Name: indicator_definitions indicator_definitions_global_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY indicator_definitions_global_manage ON public.indicator_definitions USING (public.current_user_has_permission('impact.manage'::text)) WITH CHECK (public.current_user_has_permission('impact.manage'::text));


--
-- Name: indicator_definitions indicator_definitions_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY indicator_definitions_public_read ON public.indicator_definitions FOR SELECT USING (true);


--
-- Name: indicator_disaggregations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.indicator_disaggregations ENABLE ROW LEVEL SECURITY;

--
-- Name: indicator_disaggregations indicator_disaggregations_authorized; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY indicator_disaggregations_authorized ON public.indicator_disaggregations USING (public.current_user_can_access_measurement_plan(measurement_plan_id, 'impact.manage'::text)) WITH CHECK (public.current_user_can_access_measurement_plan(measurement_plan_id, 'impact.manage'::text));


--
-- Name: indicator_disaggregations indicator_disaggregations_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY indicator_disaggregations_authorized_read ON public.indicator_disaggregations FOR SELECT USING (public.current_user_can_access_measurement_plan(measurement_plan_id, 'impact.read'::text));


--
-- Name: indicator_observations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.indicator_observations ENABLE ROW LEVEL SECURITY;

--
-- Name: indicator_observations indicator_observations_authorized_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY indicator_observations_authorized_insert ON public.indicator_observations FOR INSERT WITH CHECK (public.current_user_can_access_measurement_plan(measurement_plan_id, 'impact.manage'::text));


--
-- Name: indicator_observations indicator_observations_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY indicator_observations_authorized_read ON public.indicator_observations FOR SELECT USING (public.current_user_can_access_measurement_plan(measurement_plan_id, 'impact.read'::text));


--
-- Name: indicator_observations indicator_observations_authorized_update; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY indicator_observations_authorized_update ON public.indicator_observations FOR UPDATE USING (public.current_user_can_access_measurement_plan(measurement_plan_id, 'impact.manage'::text)) WITH CHECK (public.current_user_can_access_measurement_plan(measurement_plan_id, 'impact.manage'::text));


--
-- Name: indicator_observations indicator_observations_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY indicator_observations_public_read ON public.indicator_observations FOR SELECT USING (((verification_status_code = 'published'::text) AND (is_suppressed = false)));


--
-- Name: indicator_scopes; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.indicator_scopes ENABLE ROW LEVEL SECURITY;

--
-- Name: indicator_scopes indicator_scopes_authorized_delete; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY indicator_scopes_authorized_delete ON public.indicator_scopes FOR DELETE USING (public.current_user_can_access_indicator_scope(id, 'impact.manage'::text));


--
-- Name: indicator_scopes indicator_scopes_authorized_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY indicator_scopes_authorized_insert ON public.indicator_scopes FOR INSERT WITH CHECK ((((program_id IS NOT NULL) AND public.current_user_can_access_program(program_id, 'impact.manage'::text)) OR ((initiative_id IS NOT NULL) AND public.current_user_can_access_initiative(initiative_id, 'impact.manage'::text))));


--
-- Name: indicator_scopes indicator_scopes_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY indicator_scopes_authorized_read ON public.indicator_scopes FOR SELECT USING ((((program_id IS NOT NULL) AND public.current_user_can_access_program(program_id, 'impact.read'::text)) OR ((initiative_id IS NOT NULL) AND public.current_user_can_access_initiative(initiative_id, 'impact.read'::text))));


--
-- Name: indicator_scopes indicator_scopes_authorized_update; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY indicator_scopes_authorized_update ON public.indicator_scopes FOR UPDATE USING (public.current_user_can_access_indicator_scope(id, 'impact.manage'::text)) WITH CHECK ((((program_id IS NOT NULL) AND public.current_user_can_access_program(program_id, 'impact.manage'::text)) OR ((initiative_id IS NOT NULL) AND public.current_user_can_access_initiative(initiative_id, 'impact.manage'::text))));


--
-- Name: indicator_targets; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.indicator_targets ENABLE ROW LEVEL SECURITY;

--
-- Name: indicator_targets indicator_targets_authorized; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY indicator_targets_authorized ON public.indicator_targets USING (public.current_user_can_access_measurement_plan(measurement_plan_id, 'impact.manage'::text)) WITH CHECK (public.current_user_can_access_measurement_plan(measurement_plan_id, 'impact.manage'::text));


--
-- Name: indicator_targets indicator_targets_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY indicator_targets_authorized_read ON public.indicator_targets FOR SELECT USING (public.current_user_can_access_measurement_plan(measurement_plan_id, 'impact.read'::text));


--
-- Name: indicator_translations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.indicator_translations ENABLE ROW LEVEL SECURITY;

--
-- Name: indicator_translations indicator_translations_global_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY indicator_translations_global_manage ON public.indicator_translations USING (public.current_user_has_permission('impact.manage'::text)) WITH CHECK (public.current_user_has_permission('impact.manage'::text));


--
-- Name: indicator_translations indicator_translations_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY indicator_translations_public_read ON public.indicator_translations FOR SELECT USING (true);


--
-- Name: indicator_versions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.indicator_versions ENABLE ROW LEVEL SECURITY;

--
-- Name: indicator_versions indicator_versions_global_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY indicator_versions_global_manage ON public.indicator_versions USING (public.current_user_has_permission('impact.manage'::text)) WITH CHECK (public.current_user_has_permission('impact.manage'::text));


--
-- Name: indicator_versions indicator_versions_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY indicator_versions_public_read ON public.indicator_versions FOR SELECT USING (true);


--
-- Name: initiative_program_links; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.initiative_program_links ENABLE ROW LEVEL SECURITY;

--
-- Name: initiative_program_links initiative_program_links_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY initiative_program_links_authorized_read ON public.initiative_program_links FOR SELECT USING ((public.current_user_can_access_initiative(initiative_id, 'initiatives.read'::text) OR public.current_user_can_access_program(program_id, 'programs.read'::text)));


--
-- Name: initiative_program_links initiative_program_links_authorized_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY initiative_program_links_authorized_write ON public.initiative_program_links USING ((public.current_user_can_access_initiative(initiative_id, 'initiatives.manage'::text) AND public.current_user_can_access_program(program_id, 'programs.manage'::text))) WITH CHECK ((public.current_user_can_access_initiative(initiative_id, 'initiatives.manage'::text) AND public.current_user_can_access_program(program_id, 'programs.manage'::text)));


--
-- Name: initiative_program_links initiative_program_links_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY initiative_program_links_public_read ON public.initiative_program_links FOR SELECT USING (((EXISTS ( SELECT 1
   FROM public.initiatives i
  WHERE ((i.id = initiative_program_links.initiative_id) AND (i.publication_status_code = 'published'::text)))) AND (EXISTS ( SELECT 1
   FROM public.programs p
  WHERE ((p.id = initiative_program_links.program_id) AND (p.publication_status_code = 'published'::text))))));


--
-- Name: initiative_translations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.initiative_translations ENABLE ROW LEVEL SECURITY;

--
-- Name: initiative_translations initiative_translations_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY initiative_translations_authorized_read ON public.initiative_translations FOR SELECT USING (public.current_user_can_access_initiative(initiative_id, 'initiatives.read'::text));


--
-- Name: initiative_translations initiative_translations_authorized_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY initiative_translations_authorized_write ON public.initiative_translations USING (public.current_user_can_access_initiative(initiative_id, 'initiatives.manage'::text)) WITH CHECK (public.current_user_can_access_initiative(initiative_id, 'initiatives.manage'::text));


--
-- Name: initiative_translations initiative_translations_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY initiative_translations_public_read ON public.initiative_translations FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.initiatives i
  WHERE ((i.id = initiative_translations.initiative_id) AND (i.publication_status_code = 'published'::text)))));


--
-- Name: initiatives; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.initiatives ENABLE ROW LEVEL SECURITY;

--
-- Name: initiatives initiatives_authorized_delete; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY initiatives_authorized_delete ON public.initiatives FOR DELETE USING (public.current_user_can_access_initiative(id, 'initiatives.manage'::text));


--
-- Name: initiatives initiatives_authorized_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY initiatives_authorized_insert ON public.initiatives FOR INSERT WITH CHECK (public.current_user_has_permission('initiatives.manage'::text));


--
-- Name: initiatives initiatives_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY initiatives_authorized_read ON public.initiatives FOR SELECT USING (public.current_user_can_access_initiative(id, 'initiatives.read'::text));


--
-- Name: initiatives initiatives_authorized_update; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY initiatives_authorized_update ON public.initiatives FOR UPDATE USING (public.current_user_can_access_initiative(id, 'initiatives.manage'::text)) WITH CHECK (public.current_user_can_access_initiative(id, 'initiatives.manage'::text));


--
-- Name: initiatives initiatives_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY initiatives_public_read ON public.initiatives FOR SELECT USING ((publication_status_code = 'published'::text));


--
-- Name: instrument_versions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.instrument_versions ENABLE ROW LEVEL SECURITY;

--
-- Name: instrument_versions instrument_versions_impact_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY instrument_versions_impact_manage ON public.instrument_versions USING (public.current_user_has_permission('impact.manage'::text)) WITH CHECK (public.current_user_has_permission('impact.manage'::text));


--
-- Name: instrument_versions instrument_versions_impact_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY instrument_versions_impact_read ON public.instrument_versions FOR SELECT USING (public.current_user_has_any_permission('impact.read'::text));


--
-- Name: internal_notes; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.internal_notes ENABLE ROW LEVEL SECURITY;

--
-- Name: internal_notes internal_notes_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY internal_notes_auditor_read ON public.internal_notes FOR SELECT USING (public.current_user_has_permission('intake.read'::text));


--
-- Name: internal_notes internal_notes_intake_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY internal_notes_intake_manage ON public.internal_notes USING (public.current_user_has_permission('intake.manage'::text)) WITH CHECK (public.current_user_has_permission('intake.manage'::text));


--
-- Name: learning_actions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.learning_actions ENABLE ROW LEVEL SECURITY;

--
-- Name: learning_actions learning_actions_authorized_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY learning_actions_authorized_manage ON public.learning_actions USING ((((program_cycle_id IS NULL) AND (indicator_observation_id IS NULL) AND public.current_user_has_permission('impact.manage'::text)) OR ((program_cycle_id IS NOT NULL) AND public.current_user_can_access_program_cycle(program_cycle_id, 'impact.manage'::text)) OR ((indicator_observation_id IS NOT NULL) AND public.current_user_can_access_observation(indicator_observation_id, 'impact.manage'::text)))) WITH CHECK ((((program_cycle_id IS NULL) AND (indicator_observation_id IS NULL) AND public.current_user_has_permission('impact.manage'::text)) OR ((program_cycle_id IS NOT NULL) AND public.current_user_can_access_program_cycle(program_cycle_id, 'impact.manage'::text)) OR ((indicator_observation_id IS NOT NULL) AND public.current_user_can_access_observation(indicator_observation_id, 'impact.manage'::text))));


--
-- Name: learning_actions learning_actions_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY learning_actions_public_read ON public.learning_actions FOR SELECT USING (true);


--
-- Name: measurement_plans; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.measurement_plans ENABLE ROW LEVEL SECURITY;

--
-- Name: measurement_plans measurement_plans_authorized_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY measurement_plans_authorized_manage ON public.measurement_plans USING (public.current_user_can_access_indicator_scope(indicator_scope_id, 'impact.manage'::text)) WITH CHECK (public.current_user_can_access_indicator_scope(indicator_scope_id, 'impact.manage'::text));


--
-- Name: measurement_plans measurement_plans_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY measurement_plans_authorized_read ON public.measurement_plans FOR SELECT USING (public.current_user_can_access_indicator_scope(indicator_scope_id, 'impact.read'::text));


--
-- Name: media_assets; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.media_assets ENABLE ROW LEVEL SECURITY;

--
-- Name: media_assets media_assets_authorized_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY media_assets_authorized_manage ON public.media_assets USING ((public.current_user_has_permission('team.manage'::text) OR public.current_user_has_permission('resources.manage'::text) OR public.current_user_has_permission('training.manage'::text) OR ((program_id IS NOT NULL) AND public.current_user_can_access_program(program_id, 'programs.manage'::text)) OR ((initiative_id IS NOT NULL) AND public.current_user_can_access_initiative(initiative_id, 'initiatives.manage'::text)))) WITH CHECK ((public.current_user_has_permission('team.manage'::text) OR public.current_user_has_permission('resources.manage'::text) OR public.current_user_has_permission('training.manage'::text) OR ((program_id IS NOT NULL) AND public.current_user_can_access_program(program_id, 'programs.manage'::text)) OR ((initiative_id IS NOT NULL) AND public.current_user_can_access_initiative(initiative_id, 'initiatives.manage'::text))));


--
-- Name: media_assets media_assets_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY media_assets_public_read ON public.media_assets FOR SELECT USING (true);


--
-- Name: media_assets media_assets_self_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY media_assets_self_manage ON public.media_assets USING (((person_id = public.current_person_id()) AND (program_id IS NULL) AND (initiative_id IS NULL) AND (organization_id IS NULL))) WITH CHECK (((person_id = public.current_person_id()) AND (program_id IS NULL) AND (initiative_id IS NULL) AND (organization_id IS NULL)));


--
-- Name: POLICY media_assets_self_manage ON media_assets; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON POLICY media_assets_self_manage ON public.media_assets IS 'Anyone signed in can manage their own person-linked media rows - explicitly excluded from ever touching a program/initiative/organization-linked asset (those stay staff-only via media_assets_staff_all) by requiring all three of those foreign keys to be null, not just checking person_id.';


--
-- Name: membership_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.membership_events ENABLE ROW LEVEL SECURITY;

--
-- Name: membership_events membership_events_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY membership_events_auditor_read ON public.membership_events FOR SELECT USING (public.current_user_has_permission('memberships.read'::text));


--
-- Name: membership_events membership_events_authorized_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY membership_events_authorized_manage ON public.membership_events USING (public.current_user_can_manage_memberships()) WITH CHECK (public.current_user_can_manage_memberships());


--
-- Name: membership_events membership_events_self_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY membership_events_self_read ON public.membership_events FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.memberships m
  WHERE ((m.id = membership_events.membership_id) AND (m.person_id = public.current_person_id())))));


--
-- Name: membership_statuses; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.membership_statuses ENABLE ROW LEVEL SECURITY;

--
-- Name: membership_statuses membership_statuses_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY membership_statuses_public_read ON public.membership_statuses FOR SELECT USING (true);


--
-- Name: membership_statuses membership_statuses_super_admin_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY membership_statuses_super_admin_write ON public.membership_statuses USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: membership_types; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.membership_types ENABLE ROW LEVEL SECURITY;

--
-- Name: membership_types membership_types_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY membership_types_public_read ON public.membership_types FOR SELECT USING (true);


--
-- Name: membership_types membership_types_super_admin_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY membership_types_super_admin_write ON public.membership_types USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: memberships; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.memberships ENABLE ROW LEVEL SECURITY;

--
-- Name: memberships memberships_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY memberships_auditor_read ON public.memberships FOR SELECT USING (public.current_user_has_permission('memberships.read'::text));


--
-- Name: memberships memberships_authorized_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY memberships_authorized_manage ON public.memberships USING (public.current_user_can_manage_memberships()) WITH CHECK (public.current_user_can_manage_memberships());


--
-- Name: memberships memberships_self_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY memberships_self_read ON public.memberships FOR SELECT USING ((person_id = public.current_person_id()));


--
-- Name: observation_breakdowns; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.observation_breakdowns ENABLE ROW LEVEL SECURITY;

--
-- Name: observation_breakdowns observation_breakdowns_authorized; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY observation_breakdowns_authorized ON public.observation_breakdowns USING (public.current_user_can_access_observation(indicator_observation_id, 'impact.manage'::text)) WITH CHECK (public.current_user_can_access_observation(indicator_observation_id, 'impact.manage'::text));


--
-- Name: observation_breakdowns observation_breakdowns_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY observation_breakdowns_authorized_read ON public.observation_breakdowns FOR SELECT USING (public.current_user_can_access_observation(indicator_observation_id, 'impact.read'::text));


--
-- Name: observation_breakdowns observation_breakdowns_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY observation_breakdowns_public_read ON public.observation_breakdowns FOR SELECT USING (((is_suppressed = false) AND (EXISTS ( SELECT 1
   FROM public.indicator_observations io
  WHERE ((io.id = observation_breakdowns.indicator_observation_id) AND (io.verification_status_code = 'published'::text) AND (io.is_suppressed = false))))));


--
-- Name: observation_rubrics; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.observation_rubrics ENABLE ROW LEVEL SECURITY;

--
-- Name: observation_rubrics observation_rubrics_impact_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY observation_rubrics_impact_manage ON public.observation_rubrics USING (public.current_user_has_permission('impact.manage'::text)) WITH CHECK (public.current_user_has_permission('impact.manage'::text));


--
-- Name: observation_rubrics observation_rubrics_impact_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY observation_rubrics_impact_read ON public.observation_rubrics FOR SELECT USING (public.current_user_has_any_permission('impact.read'::text));


--
-- Name: organization_types; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.organization_types ENABLE ROW LEVEL SECURITY;

--
-- Name: organization_types organization_types_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY organization_types_public_read ON public.organization_types FOR SELECT USING (true);


--
-- Name: organization_types organization_types_super_admin_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY organization_types_super_admin_write ON public.organization_types USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: organizations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;

--
-- Name: organizations organizations_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY organizations_auditor_read ON public.organizations FOR SELECT USING (public.current_user_has_permission('intake.read'::text));


--
-- Name: organizations organizations_intake_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY organizations_intake_manage ON public.organizations USING (public.current_user_has_permission('intake.manage'::text)) WITH CHECK (public.current_user_has_permission('intake.manage'::text));


--
-- Name: organizations organizations_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY organizations_public_read ON public.organizations FOR SELECT USING ((logo_publication_permitted = true));


--
-- Name: partner_relationships; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.partner_relationships ENABLE ROW LEVEL SECURITY;

--
-- Name: partner_relationships partner_relationships_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY partner_relationships_auditor_read ON public.partner_relationships FOR SELECT USING (public.current_user_has_permission('intake.read'::text));


--
-- Name: partner_relationships partner_relationships_intake_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY partner_relationships_intake_manage ON public.partner_relationships USING (public.current_user_has_permission('intake.manage'::text)) WITH CHECK (public.current_user_has_permission('intake.manage'::text));


--
-- Name: partner_relationships partner_relationships_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY partner_relationships_public_read ON public.partner_relationships FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.organizations o
  WHERE ((o.id = partner_relationships.organization_id) AND (o.logo_publication_permitted = true)))));


--
-- Name: partner_roles; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.partner_roles ENABLE ROW LEVEL SECURITY;

--
-- Name: partner_roles partner_roles_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY partner_roles_public_read ON public.partner_roles FOR SELECT USING (true);


--
-- Name: partner_roles partner_roles_super_admin_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY partner_roles_super_admin_write ON public.partner_roles USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: partnership_inquiries; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.partnership_inquiries ENABLE ROW LEVEL SECURITY;

--
-- Name: partnership_inquiries partnership_inquiries_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY partnership_inquiries_auditor_read ON public.partnership_inquiries FOR SELECT USING (public.current_user_has_role('auditor'::text));


--
-- Name: partnership_inquiries partnership_inquiries_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY partnership_inquiries_manage ON public.partnership_inquiries USING (public.current_user_can_manage_intake()) WITH CHECK (public.current_user_can_manage_intake());


--
-- Name: payment_customers; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.payment_customers ENABLE ROW LEVEL SECURITY;

--
-- Name: payment_customers payment_customers_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY payment_customers_auditor_read ON public.payment_customers FOR SELECT USING (public.current_user_has_permission('finance.read'::text));


--
-- Name: payment_customers payment_customers_finance_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY payment_customers_finance_manage ON public.payment_customers USING (public.current_user_has_permission('finance.manage'::text)) WITH CHECK (public.current_user_has_permission('finance.manage'::text));


--
-- Name: payment_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.payment_events ENABLE ROW LEVEL SECURITY;

--
-- Name: payment_events payment_events_finance_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY payment_events_finance_read ON public.payment_events FOR SELECT USING (public.current_user_has_permission('finance.read'::text));


--
-- Name: payment_providers; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.payment_providers ENABLE ROW LEVEL SECURITY;

--
-- Name: payment_providers payment_providers_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY payment_providers_public_read ON public.payment_providers FOR SELECT USING (true);


--
-- Name: payment_providers payment_providers_super_admin_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY payment_providers_super_admin_write ON public.payment_providers USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: payment_records; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.payment_records ENABLE ROW LEVEL SECURITY;

--
-- Name: payment_records payment_records_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY payment_records_insert ON public.payment_records FOR INSERT WITH CHECK (public.current_user_has_permission('finance.manage'::text));


--
-- Name: POLICY payment_records_insert ON payment_records; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON POLICY payment_records_insert ON public.payment_records IS 'finance.manage can add a new ledger entry - insert only. No UPDATE or DELETE policy exists for any role: a mistaken entry is corrected with a new, offsetting entry, never by editing or removing history. training.manage was already removed from this permission by 20260910000003_narrow_finance_permission.sql.';


--
-- Name: payment_records payment_records_self_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY payment_records_self_read ON public.payment_records FOR SELECT USING (public.current_user_owns_training_registration(training_registration_id));


--
-- Name: POLICY payment_records_self_read ON payment_records; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON POLICY payment_records_self_read ON public.payment_records IS 'A trainee can read their own payment history (amount, method, date - not staff notes intended to stay internal, though note has no separate visibility split yet). No portal UI surfaces this yet; the policy exists so that UI can be added without a further migration.';


--
-- Name: payment_records payment_records_staff_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY payment_records_staff_read ON public.payment_records FOR SELECT USING ((public.current_user_has_permission('finance.read'::text) OR public.current_user_has_permission('training.read'::text)));


--
-- Name: payment_transaction_statuses; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.payment_transaction_statuses ENABLE ROW LEVEL SECURITY;

--
-- Name: payment_transaction_statuses payment_transaction_statuses_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY payment_transaction_statuses_public_read ON public.payment_transaction_statuses FOR SELECT USING (true);


--
-- Name: payment_transaction_statuses payment_transaction_statuses_super_admin_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY payment_transaction_statuses_super_admin_write ON public.payment_transaction_statuses USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: payment_transactions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.payment_transactions ENABLE ROW LEVEL SECURITY;

--
-- Name: payment_transactions payment_transactions_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY payment_transactions_auditor_read ON public.payment_transactions FOR SELECT USING (public.current_user_has_permission('finance.read'::text));


--
-- Name: payment_transactions payment_transactions_finance_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY payment_transactions_finance_manage ON public.payment_transactions USING (public.current_user_has_permission('finance.manage'::text)) WITH CHECK (public.current_user_has_permission('finance.manage'::text));


--
-- Name: people; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.people ENABLE ROW LEVEL SECURITY;

--
-- Name: people people_authorized_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY people_authorized_manage ON public.people USING (public.current_user_has_permission('people.manage'::text)) WITH CHECK (public.current_user_has_permission('people.manage'::text));


--
-- Name: people people_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY people_authorized_read ON public.people FOR SELECT USING (public.current_user_has_permission('people.read'::text));


--
-- Name: people people_self_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY people_self_read ON public.people FOR SELECT USING ((id = public.current_person_id()));


--
-- Name: people people_self_update; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY people_self_update ON public.people FOR UPDATE USING ((id = public.current_person_id())) WITH CHECK ((id = public.current_person_id()));


--
-- Name: POLICY people_self_update ON people; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON POLICY people_self_update ON public.people IS 'A signed-in person can update their own row - enforce_people_self_service_columns restricts this to preferred_name/phone/preferred_locale/region/timezone/education_employment_context/learning_interests/learning_goals regardless of RLS, so this row-level grant alone cannot be used to change legal name, verified email, country or staff notes.';


--
-- Name: people_translations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.people_translations ENABLE ROW LEVEL SECURITY;

--
-- Name: people_translations people_translations_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY people_translations_auditor_read ON public.people_translations FOR SELECT USING (public.current_user_has_permission('people.read'::text));


--
-- Name: people_translations people_translations_authorized_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY people_translations_authorized_manage ON public.people_translations USING (public.current_user_has_permission('people.manage'::text)) WITH CHECK (public.current_user_has_permission('people.manage'::text));


--
-- Name: people_translations people_translations_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY people_translations_public_read ON public.people_translations FOR SELECT USING (((EXISTS ( SELECT 1
   FROM (public.people p
     JOIN public.governance_appointments ga ON (((ga.person_id = p.id) AND (ga.is_current = true))))
  WHERE ((p.id = people_translations.person_id) AND (p.public_slug IS NOT NULL)))) OR (EXISTS ( SELECT 1
   FROM public.public_trainers_directory ptd
  WHERE (ptd.person_id = people_translations.person_id)))));


--
-- Name: people_translations people_translations_self_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY people_translations_self_manage ON public.people_translations USING ((person_id = public.current_person_id())) WITH CHECK ((person_id = public.current_person_id()));


--
-- Name: POLICY people_translations_self_manage ON people_translations; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON POLICY people_translations_self_manage ON public.people_translations IS 'Anyone signed in can manage their own biography row(s) - harmless for a role with no public profile surface (it simply never gets read anywhere), and exactly what an approved trainer needs to write the bio people_translations_public_read already lets the public read.';


--
-- Name: permissions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.permissions ENABLE ROW LEVEL SECURITY;

--
-- Name: permissions permissions_super_admin_all; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY permissions_super_admin_all ON public.permissions USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: person_accessibility_requests; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.person_accessibility_requests ENABLE ROW LEVEL SECURITY;

--
-- Name: person_accessibility_requests person_accessibility_requests_safeguarding_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY person_accessibility_requests_safeguarding_manage ON public.person_accessibility_requests USING (public.current_user_has_permission('safeguarding.manage'::text)) WITH CHECK (public.current_user_has_permission('safeguarding.manage'::text));


--
-- Name: person_accessibility_requests person_accessibility_requests_safeguarding_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY person_accessibility_requests_safeguarding_read ON public.person_accessibility_requests FOR SELECT USING (public.current_user_has_permission('safeguarding.read'::text));


--
-- Name: person_accessibility_requests person_accessibility_requests_self_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY person_accessibility_requests_self_insert ON public.person_accessibility_requests FOR INSERT WITH CHECK (((person_id = public.current_person_id()) AND (status_code = 'submitted'::text) AND (reviewed_by IS NULL) AND (reviewed_at IS NULL) AND (staff_notes IS NULL)));


--
-- Name: POLICY person_accessibility_requests_self_insert ON person_accessibility_requests; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON POLICY person_accessibility_requests_self_insert ON public.person_accessibility_requests IS 'A person can submit a request about themselves, always starting at submitted with no review fields set - there is no self-update policy at all, so once submitted only safeguarding.manage can change its status or add notes.';


--
-- Name: person_accessibility_requests person_accessibility_requests_self_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY person_accessibility_requests_self_select ON public.person_accessibility_requests FOR SELECT USING ((person_id = public.current_person_id()));


--
-- Name: person_consent_records; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.person_consent_records ENABLE ROW LEVEL SECURITY;

--
-- Name: person_consent_records person_consent_records_safeguarding_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY person_consent_records_safeguarding_manage ON public.person_consent_records USING (public.current_user_has_permission('safeguarding.manage'::text)) WITH CHECK (public.current_user_has_permission('safeguarding.manage'::text));


--
-- Name: person_consent_records person_consent_records_safeguarding_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY person_consent_records_safeguarding_read ON public.person_consent_records FOR SELECT USING (public.current_user_has_permission('safeguarding.read'::text));


--
-- Name: person_consent_records person_consent_records_self_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY person_consent_records_self_insert ON public.person_consent_records FOR INSERT WITH CHECK (((person_id = public.current_person_id()) AND (granted_by_person_id = public.current_person_id()) AND (method = 'self_service'::text)));


--
-- Name: person_consent_records person_consent_records_self_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY person_consent_records_self_select ON public.person_consent_records FOR SELECT USING ((person_id = public.current_person_id()));


--
-- Name: person_emergency_contacts; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.person_emergency_contacts ENABLE ROW LEVEL SECURITY;

--
-- Name: person_emergency_contacts person_emergency_contacts_safeguarding_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY person_emergency_contacts_safeguarding_manage ON public.person_emergency_contacts USING (public.current_user_has_permission('safeguarding.manage'::text)) WITH CHECK (public.current_user_has_permission('safeguarding.manage'::text));


--
-- Name: person_emergency_contacts person_emergency_contacts_safeguarding_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY person_emergency_contacts_safeguarding_read ON public.person_emergency_contacts FOR SELECT USING (public.current_user_has_permission('safeguarding.read'::text));


--
-- Name: person_emergency_contacts person_emergency_contacts_self_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY person_emergency_contacts_self_manage ON public.person_emergency_contacts USING ((person_id = public.current_person_id())) WITH CHECK ((person_id = public.current_person_id()));


--
-- Name: person_guardian_relationships; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.person_guardian_relationships ENABLE ROW LEVEL SECURITY;

--
-- Name: person_guardian_relationships person_guardian_relationships_safeguarding_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY person_guardian_relationships_safeguarding_manage ON public.person_guardian_relationships USING (public.current_user_has_permission('safeguarding.manage'::text)) WITH CHECK (public.current_user_has_permission('safeguarding.manage'::text));


--
-- Name: person_guardian_relationships person_guardian_relationships_safeguarding_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY person_guardian_relationships_safeguarding_read ON public.person_guardian_relationships FOR SELECT USING (public.current_user_has_permission('safeguarding.read'::text));


--
-- Name: person_guardian_relationships person_guardian_relationships_self_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY person_guardian_relationships_self_insert ON public.person_guardian_relationships FOR INSERT WITH CHECK (((guardian_person_id = public.current_person_id()) AND (verified = false) AND (verified_by IS NULL) AND (verified_at IS NULL)));


--
-- Name: POLICY person_guardian_relationships_self_insert ON person_guardian_relationships; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON POLICY person_guardian_relationships_self_insert ON public.person_guardian_relationships IS 'Self-service only ever creates an unverified claim about oneself as the guardian of another existing person - never self-verified (no self-update policy exists at all), and both sides of the claimed relationship can see it, not just the one who filed it.';


--
-- Name: person_guardian_relationships person_guardian_relationships_self_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY person_guardian_relationships_self_select ON public.person_guardian_relationships FOR SELECT USING (((guardian_person_id = public.current_person_id()) OR (dependent_person_id = public.current_person_id())));


--
-- Name: professional_credentials; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.professional_credentials ENABLE ROW LEVEL SECURITY;

--
-- Name: professional_credentials professional_credentials_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY professional_credentials_auditor_read ON public.professional_credentials FOR SELECT USING (public.current_user_has_permission('training.read'::text));


--
-- Name: professional_credentials professional_credentials_self_delete; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY professional_credentials_self_delete ON public.professional_credentials FOR DELETE USING (((trainer_id = public.current_user_trainer_id()) AND (verification_status_code = ANY (ARRAY['draft'::text, 'rejected'::text]))));


--
-- Name: professional_credentials professional_credentials_self_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY professional_credentials_self_insert ON public.professional_credentials FOR INSERT WITH CHECK (((trainer_id = public.current_user_trainer_id()) AND (verification_status_code = ANY (ARRAY['draft'::text, 'submitted'::text])) AND (reviewed_by IS NULL) AND (reviewed_at IS NULL) AND (review_notes IS NULL)));


--
-- Name: professional_credentials professional_credentials_self_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY professional_credentials_self_select ON public.professional_credentials FOR SELECT USING ((trainer_id = public.current_user_trainer_id()));


--
-- Name: professional_credentials professional_credentials_self_update; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY professional_credentials_self_update ON public.professional_credentials FOR UPDATE USING ((trainer_id = public.current_user_trainer_id())) WITH CHECK ((trainer_id = public.current_user_trainer_id()));


--
-- Name: professional_credentials professional_credentials_staff_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY professional_credentials_staff_manage ON public.professional_credentials USING (public.current_user_can_manage_trainings()) WITH CHECK (public.current_user_can_manage_trainings());


--
-- Name: profile_documents; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.profile_documents ENABLE ROW LEVEL SECURITY;

--
-- Name: profile_documents profile_documents_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY profile_documents_auditor_read ON public.profile_documents FOR SELECT USING (public.current_user_has_permission('training.read'::text));


--
-- Name: profile_documents profile_documents_self_delete; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY profile_documents_self_delete ON public.profile_documents FOR DELETE USING ((trainer_id = public.current_user_trainer_id()));


--
-- Name: profile_documents profile_documents_self_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY profile_documents_self_insert ON public.profile_documents FOR INSERT WITH CHECK ((trainer_id = public.current_user_trainer_id()));


--
-- Name: profile_documents profile_documents_self_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY profile_documents_self_select ON public.profile_documents FOR SELECT USING ((trainer_id = public.current_user_trainer_id()));


--
-- Name: profile_documents profile_documents_staff_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY profile_documents_staff_manage ON public.profile_documents USING (public.current_user_can_manage_trainings()) WITH CHECK (public.current_user_can_manage_trainings());


--
-- Name: program_activities; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.program_activities ENABLE ROW LEVEL SECURITY;

--
-- Name: program_activities program_activities_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY program_activities_authorized_read ON public.program_activities FOR SELECT USING (public.current_user_can_access_program(program_id, 'programs.read'::text));


--
-- Name: program_activities program_activities_authorized_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY program_activities_authorized_write ON public.program_activities USING (public.current_user_can_access_program(program_id, 'programs.manage'::text)) WITH CHECK (public.current_user_can_access_program(program_id, 'programs.manage'::text));


--
-- Name: program_activities program_activities_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY program_activities_public_read ON public.program_activities FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.programs p
  WHERE ((p.id = program_activities.program_id) AND (p.publication_status_code = 'published'::text)))));


--
-- Name: program_cycles; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.program_cycles ENABLE ROW LEVEL SECURITY;

--
-- Name: program_cycles program_cycles_authorized_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY program_cycles_authorized_manage ON public.program_cycles USING (public.current_user_can_access_program(program_id, 'impact.manage'::text)) WITH CHECK (public.current_user_can_access_program(program_id, 'impact.manage'::text));


--
-- Name: program_cycles program_cycles_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY program_cycles_authorized_read ON public.program_cycles FOR SELECT USING (public.current_user_can_access_program(program_id, 'impact.read'::text));


--
-- Name: program_indicators; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.program_indicators ENABLE ROW LEVEL SECURITY;

--
-- Name: program_indicators program_indicators_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY program_indicators_authorized_read ON public.program_indicators FOR SELECT USING (public.current_user_can_access_program(program_id, 'programs.read'::text));


--
-- Name: program_indicators program_indicators_authorized_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY program_indicators_authorized_write ON public.program_indicators USING (public.current_user_can_access_program(program_id, 'programs.manage'::text)) WITH CHECK (public.current_user_can_access_program(program_id, 'programs.manage'::text));


--
-- Name: program_indicators program_indicators_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY program_indicators_public_read ON public.program_indicators FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.programs p
  WHERE ((p.id = program_indicators.program_id) AND (p.publication_status_code = 'published'::text)))));


--
-- Name: program_statuses; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.program_statuses ENABLE ROW LEVEL SECURITY;

--
-- Name: program_statuses program_statuses_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY program_statuses_public_read ON public.program_statuses FOR SELECT USING (true);


--
-- Name: program_statuses program_statuses_super_admin_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY program_statuses_super_admin_write ON public.program_statuses USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: program_translations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.program_translations ENABLE ROW LEVEL SECURITY;

--
-- Name: program_translations program_translations_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY program_translations_authorized_read ON public.program_translations FOR SELECT USING (public.current_user_can_access_program(program_id, 'programs.read'::text));


--
-- Name: program_translations program_translations_authorized_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY program_translations_authorized_write ON public.program_translations USING (public.current_user_can_access_program(program_id, 'programs.manage'::text)) WITH CHECK (public.current_user_can_access_program(program_id, 'programs.manage'::text));


--
-- Name: program_translations program_translations_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY program_translations_public_read ON public.program_translations FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.programs p
  WHERE ((p.id = program_translations.program_id) AND (p.publication_status_code = 'published'::text)))));


--
-- Name: programs; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.programs ENABLE ROW LEVEL SECURITY;

--
-- Name: programs programs_authorized_delete; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY programs_authorized_delete ON public.programs FOR DELETE USING (public.current_user_can_access_program(id, 'programs.manage'::text));


--
-- Name: programs programs_authorized_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY programs_authorized_insert ON public.programs FOR INSERT WITH CHECK ((public.current_user_has_permission('programs.manage'::text) OR ((parent_program_id IS NOT NULL) AND public.current_user_can_access_program(parent_program_id, 'programs.manage'::text))));


--
-- Name: programs programs_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY programs_authorized_read ON public.programs FOR SELECT USING (public.current_user_can_access_program(id, 'programs.read'::text));


--
-- Name: programs programs_authorized_update; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY programs_authorized_update ON public.programs FOR UPDATE USING (public.current_user_can_access_program(id, 'programs.manage'::text)) WITH CHECK (public.current_user_can_access_program(id, 'programs.manage'::text));


--
-- Name: programs programs_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY programs_public_read ON public.programs FOR SELECT USING ((publication_status_code = 'published'::text));


--
-- Name: publication_approvals; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.publication_approvals ENABLE ROW LEVEL SECURITY;

--
-- Name: publication_approvals publication_approvals_authorized; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY publication_approvals_authorized ON public.publication_approvals USING (public.current_user_can_access_observation(indicator_observation_id, 'impact.manage'::text)) WITH CHECK (public.current_user_can_access_observation(indicator_observation_id, 'impact.manage'::text));


--
-- Name: publication_approvals publication_approvals_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY publication_approvals_authorized_read ON public.publication_approvals FOR SELECT USING (public.current_user_can_access_observation(indicator_observation_id, 'impact.read'::text));


--
-- Name: publication_snapshots; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.publication_snapshots ENABLE ROW LEVEL SECURITY;

--
-- Name: publication_snapshots publication_snapshots_authorized_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY publication_snapshots_authorized_manage ON public.publication_snapshots USING (public.current_user_can_access_observation(indicator_observation_id, 'impact.manage'::text)) WITH CHECK (public.current_user_can_access_observation(indicator_observation_id, 'impact.manage'::text));


--
-- Name: publication_snapshots publication_snapshots_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY publication_snapshots_public_read ON public.publication_snapshots FOR SELECT USING (true);


--
-- Name: publication_statuses; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.publication_statuses ENABLE ROW LEVEL SECURITY;

--
-- Name: publication_statuses publication_statuses_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY publication_statuses_public_read ON public.publication_statuses FOR SELECT USING (true);


--
-- Name: publication_statuses publication_statuses_super_admin_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY publication_statuses_super_admin_write ON public.publication_statuses USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: receipt_deliveries; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.receipt_deliveries ENABLE ROW LEVEL SECURITY;

--
-- Name: receipt_deliveries receipt_deliveries_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY receipt_deliveries_auditor_read ON public.receipt_deliveries FOR SELECT USING (public.current_user_has_permission('finance.read'::text));


--
-- Name: receipt_deliveries receipt_deliveries_finance_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY receipt_deliveries_finance_manage ON public.receipt_deliveries USING (public.current_user_has_permission('finance.manage'::text)) WITH CHECK (public.current_user_has_permission('finance.manage'::text));


--
-- Name: receipt_delivery_statuses; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.receipt_delivery_statuses ENABLE ROW LEVEL SECURITY;

--
-- Name: receipt_delivery_statuses receipt_delivery_statuses_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY receipt_delivery_statuses_public_read ON public.receipt_delivery_statuses FOR SELECT USING (true);


--
-- Name: receipt_delivery_statuses receipt_delivery_statuses_super_admin_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY receipt_delivery_statuses_super_admin_write ON public.receipt_delivery_statuses USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: receipts; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.receipts ENABLE ROW LEVEL SECURITY;

--
-- Name: receipts receipts_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY receipts_auditor_read ON public.receipts FOR SELECT USING (public.current_user_has_permission('finance.read'::text));


--
-- Name: receipts receipts_finance_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY receipts_finance_manage ON public.receipts USING (public.current_user_has_permission('finance.manage'::text)) WITH CHECK (public.current_user_has_permission('finance.manage'::text));


--
-- Name: receipts receipts_self_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY receipts_self_read ON public.receipts FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.donations d
  WHERE ((d.id = receipts.donation_id) AND (d.person_id = public.current_person_id())))));


--
-- Name: recurring_agreements; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.recurring_agreements ENABLE ROW LEVEL SECURITY;

--
-- Name: recurring_agreements recurring_agreements_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY recurring_agreements_auditor_read ON public.recurring_agreements FOR SELECT USING (public.current_user_has_permission('finance.read'::text));


--
-- Name: recurring_agreements recurring_agreements_finance_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY recurring_agreements_finance_manage ON public.recurring_agreements USING (public.current_user_has_permission('finance.manage'::text)) WITH CHECK (public.current_user_has_permission('finance.manage'::text));


--
-- Name: refunds; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.refunds ENABLE ROW LEVEL SECURITY;

--
-- Name: refunds refunds_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY refunds_auditor_read ON public.refunds FOR SELECT USING (public.current_user_has_permission('finance.read'::text));


--
-- Name: refunds refunds_finance_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY refunds_finance_manage ON public.refunds USING (public.current_user_has_permission('finance.manage'::text)) WITH CHECK (public.current_user_has_permission('finance.manage'::text));


--
-- Name: reporting_periods; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.reporting_periods ENABLE ROW LEVEL SECURITY;

--
-- Name: reporting_periods reporting_periods_global_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY reporting_periods_global_manage ON public.reporting_periods USING (public.current_user_has_permission('impact.manage'::text)) WITH CHECK (public.current_user_has_permission('impact.manage'::text));


--
-- Name: reporting_periods reporting_periods_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY reporting_periods_public_read ON public.reporting_periods FOR SELECT USING (true);


--
-- Name: resource_translations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.resource_translations ENABLE ROW LEVEL SECURITY;

--
-- Name: resource_translations resource_translations_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY resource_translations_auditor_read ON public.resource_translations FOR SELECT USING (public.current_user_has_role('auditor'::text));


--
-- Name: resource_translations resource_translations_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY resource_translations_manage ON public.resource_translations USING (public.current_user_can_manage_content()) WITH CHECK (public.current_user_can_manage_content());


--
-- Name: resource_translations resource_translations_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY resource_translations_public_read ON public.resource_translations FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.resources r
  WHERE ((r.id = resource_translations.resource_id) AND (r.publication_status_code = 'published'::text)))));


--
-- Name: resources; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.resources ENABLE ROW LEVEL SECURITY;

--
-- Name: resources resources_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY resources_auditor_read ON public.resources FOR SELECT USING (public.current_user_has_role('auditor'::text));


--
-- Name: resources resources_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY resources_manage ON public.resources USING (public.current_user_can_manage_content()) WITH CHECK (public.current_user_can_manage_content());


--
-- Name: resources resources_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY resources_public_read ON public.resources FOR SELECT USING ((publication_status_code = 'published'::text));


--
-- Name: result_levels; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.result_levels ENABLE ROW LEVEL SECURITY;

--
-- Name: result_levels result_levels_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY result_levels_public_read ON public.result_levels FOR SELECT USING (true);


--
-- Name: result_levels result_levels_super_admin_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY result_levels_super_admin_write ON public.result_levels USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: result_links; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.result_links ENABLE ROW LEVEL SECURITY;

--
-- Name: result_links result_links_authorized_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY result_links_authorized_manage ON public.result_links USING (((EXISTS ( SELECT 1
   FROM public.result_nodes rn
  WHERE ((rn.id = result_links.from_result_node_id) AND public.current_user_can_access_program(rn.program_id, 'impact.manage'::text)))) AND (EXISTS ( SELECT 1
   FROM public.result_nodes rn
  WHERE ((rn.id = result_links.to_result_node_id) AND public.current_user_can_access_program(rn.program_id, 'impact.manage'::text)))))) WITH CHECK (((EXISTS ( SELECT 1
   FROM public.result_nodes rn
  WHERE ((rn.id = result_links.from_result_node_id) AND public.current_user_can_access_program(rn.program_id, 'impact.manage'::text)))) AND (EXISTS ( SELECT 1
   FROM public.result_nodes rn
  WHERE ((rn.id = result_links.to_result_node_id) AND public.current_user_can_access_program(rn.program_id, 'impact.manage'::text))))));


--
-- Name: result_links result_links_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY result_links_public_read ON public.result_links FOR SELECT USING (true);


--
-- Name: result_node_translations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.result_node_translations ENABLE ROW LEVEL SECURITY;

--
-- Name: result_node_translations result_node_translations_authorized_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY result_node_translations_authorized_manage ON public.result_node_translations USING ((EXISTS ( SELECT 1
   FROM public.result_nodes rn
  WHERE ((rn.id = result_node_translations.result_node_id) AND public.current_user_can_access_program(rn.program_id, 'impact.manage'::text))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM public.result_nodes rn
  WHERE ((rn.id = result_node_translations.result_node_id) AND public.current_user_can_access_program(rn.program_id, 'impact.manage'::text)))));


--
-- Name: result_node_translations result_node_translations_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY result_node_translations_public_read ON public.result_node_translations FOR SELECT USING (true);


--
-- Name: result_nodes; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.result_nodes ENABLE ROW LEVEL SECURITY;

--
-- Name: result_nodes result_nodes_authorized_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY result_nodes_authorized_manage ON public.result_nodes USING (public.current_user_can_access_program(program_id, 'impact.manage'::text)) WITH CHECK (public.current_user_can_access_program(program_id, 'impact.manage'::text));


--
-- Name: result_nodes result_nodes_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY result_nodes_public_read ON public.result_nodes FOR SELECT USING (true);


--
-- Name: role_permissions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.role_permissions ENABLE ROW LEVEL SECURITY;

--
-- Name: role_permissions role_permissions_super_admin_all; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY role_permissions_super_admin_all ON public.role_permissions USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: roles; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.roles ENABLE ROW LEVEL SECURITY;

--
-- Name: roles roles_super_admin_all; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY roles_super_admin_all ON public.roles USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: security_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.security_events ENABLE ROW LEVEL SECURITY;

--
-- Name: security_events security_events_super_admin_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY security_events_super_admin_read ON public.security_events FOR SELECT USING (public.current_user_has_role('super_admin'::text));


--
-- Name: sites; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.sites ENABLE ROW LEVEL SECURITY;

--
-- Name: sites sites_impact_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sites_impact_manage ON public.sites USING (public.current_user_has_any_permission('impact.manage'::text)) WITH CHECK (public.current_user_has_any_permission('impact.manage'::text));


--
-- Name: sites sites_impact_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sites_impact_read ON public.sites FOR SELECT USING (public.current_user_has_any_permission('impact.read'::text));


--
-- Name: submission_status_history; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.submission_status_history ENABLE ROW LEVEL SECURITY;

--
-- Name: submission_status_history submission_status_history_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY submission_status_history_auditor_read ON public.submission_status_history FOR SELECT USING (public.current_user_has_permission('intake.read'::text));


--
-- Name: submission_status_history submission_status_history_intake_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY submission_status_history_intake_manage ON public.submission_status_history USING (public.current_user_has_permission('intake.manage'::text)) WITH CHECK (public.current_user_has_permission('intake.manage'::text));


--
-- Name: submission_statuses; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.submission_statuses ENABLE ROW LEVEL SECURITY;

--
-- Name: submission_statuses submission_statuses_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY submission_statuses_public_read ON public.submission_statuses FOR SELECT USING (true);


--
-- Name: submission_statuses submission_statuses_super_admin_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY submission_statuses_super_admin_write ON public.submission_statuses USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: support_item_fulfillments; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.support_item_fulfillments ENABLE ROW LEVEL SECURITY;

--
-- Name: support_item_fulfillments support_item_fulfillments_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY support_item_fulfillments_auditor_read ON public.support_item_fulfillments FOR SELECT USING (public.current_user_has_permission('support.read'::text));


--
-- Name: support_item_fulfillments support_item_fulfillments_finance_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY support_item_fulfillments_finance_manage ON public.support_item_fulfillments USING (public.current_user_has_permission('support.manage'::text)) WITH CHECK (public.current_user_has_permission('support.manage'::text));


--
-- Name: support_item_translations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.support_item_translations ENABLE ROW LEVEL SECURITY;

--
-- Name: support_item_translations support_item_translations_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY support_item_translations_auditor_read ON public.support_item_translations FOR SELECT USING (public.current_user_has_permission('support.read'::text));


--
-- Name: support_item_translations support_item_translations_finance_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY support_item_translations_finance_manage ON public.support_item_translations USING (public.current_user_has_permission('support.manage'::text)) WITH CHECK (public.current_user_has_permission('support.manage'::text));


--
-- Name: support_item_translations support_item_translations_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY support_item_translations_public_read ON public.support_item_translations FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.support_items si
  WHERE ((si.id = support_item_translations.support_item_id) AND (si.status = ANY (ARRAY['active'::text, 'complete'::text]))))));


--
-- Name: support_items; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.support_items ENABLE ROW LEVEL SECURITY;

--
-- Name: support_items support_items_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY support_items_auditor_read ON public.support_items FOR SELECT USING (public.current_user_has_permission('support.read'::text));


--
-- Name: support_items support_items_finance_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY support_items_finance_manage ON public.support_items USING (public.current_user_has_permission('support.manage'::text)) WITH CHECK (public.current_user_has_permission('support.manage'::text));


--
-- Name: support_items support_items_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY support_items_public_read ON public.support_items FOR SELECT USING ((status = ANY (ARRAY['active'::text, 'complete'::text])));


--
-- Name: survey_responses; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.survey_responses ENABLE ROW LEVEL SECURITY;

--
-- Name: survey_responses survey_responses_authorized; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY survey_responses_authorized ON public.survey_responses USING (public.current_user_can_access_measurement_plan(measurement_plan_id, 'impact.manage'::text)) WITH CHECK (public.current_user_can_access_measurement_plan(measurement_plan_id, 'impact.manage'::text));


--
-- Name: survey_responses survey_responses_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY survey_responses_authorized_read ON public.survey_responses FOR SELECT USING (public.current_user_can_access_measurement_plan(measurement_plan_id, 'impact.read'::text));


--
-- Name: theories_of_change; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.theories_of_change ENABLE ROW LEVEL SECURITY;

--
-- Name: theories_of_change theories_of_change_authorized_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY theories_of_change_authorized_manage ON public.theories_of_change USING (public.current_user_can_access_program(program_id, 'impact.manage'::text)) WITH CHECK (public.current_user_can_access_program(program_id, 'impact.manage'::text));


--
-- Name: theories_of_change theories_of_change_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY theories_of_change_authorized_read ON public.theories_of_change FOR SELECT USING (public.current_user_can_access_program(program_id, 'impact.read'::text));


--
-- Name: trainer_application_snapshots; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.trainer_application_snapshots ENABLE ROW LEVEL SECURITY;

--
-- Name: trainer_application_snapshots trainer_application_snapshots_self_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY trainer_application_snapshots_self_read ON public.trainer_application_snapshots FOR SELECT USING ((trainer_id = public.current_user_trainer_id()));


--
-- Name: POLICY trainer_application_snapshots_self_read ON trainer_application_snapshots; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON POLICY trainer_application_snapshots_self_read ON public.trainer_application_snapshots IS 'A trainer can read their own original application snapshot - this table has no insert/update/delete policy for anyone at all (staff included), only the service role can ever write it.';


--
-- Name: trainer_application_snapshots trainer_application_snapshots_staff_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY trainer_application_snapshots_staff_read ON public.trainer_application_snapshots FOR SELECT USING (public.current_user_has_permission('training.read'::text));


--
-- Name: trainers; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.trainers ENABLE ROW LEVEL SECURITY;

--
-- Name: trainers trainers_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY trainers_auditor_read ON public.trainers FOR SELECT USING (public.current_user_has_role('auditor'::text));


--
-- Name: trainers trainers_manage_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY trainers_manage_insert ON public.trainers FOR INSERT WITH CHECK (public.current_user_can_manage_trainings());


--
-- Name: trainers trainers_manage_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY trainers_manage_select ON public.trainers FOR SELECT USING (public.current_user_can_manage_trainings());


--
-- Name: trainers trainers_manager_delete; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY trainers_manager_delete ON public.trainers FOR DELETE USING ((public.current_user_has_role('training_manager'::text) OR public.current_user_has_role('admin'::text) OR public.current_user_has_role('super_admin'::text)));


--
-- Name: trainers trainers_manager_update; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY trainers_manager_update ON public.trainers FOR UPDATE USING ((public.current_user_has_role('training_manager'::text) OR public.current_user_has_role('admin'::text) OR public.current_user_has_role('super_admin'::text))) WITH CHECK ((public.current_user_has_role('training_manager'::text) OR public.current_user_has_role('admin'::text) OR public.current_user_has_role('super_admin'::text)));


--
-- Name: POLICY trainers_manager_update ON trainers; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON POLICY trainers_manager_update ON public.trainers IS 'Only a training manager (or admin/super_admin) can approve/reject a trainer candidate - any staff can propose one (insert) but cannot unilaterally approve their own or anyone else''s.';


--
-- Name: trainers trainers_self_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY trainers_self_select ON public.trainers FOR SELECT USING ((id = public.current_user_trainer_id()));


--
-- Name: POLICY trainers_self_select ON trainers; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON POLICY trainers_self_select ON public.trainers IS 'trainers_staff_select requires current_user_is_staff(), which a plain trainer never holds - without this, a trainer could update their own row via trainers_self_update below but never read it back to populate an edit form in the first place.';


--
-- Name: trainers trainers_self_update; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY trainers_self_update ON public.trainers FOR UPDATE USING ((id = public.current_user_trainer_id())) WITH CHECK ((id = public.current_user_trainer_id()));


--
-- Name: POLICY trainers_self_update ON trainers; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON POLICY trainers_self_update ON public.trainers IS 'An approved trainer can update their own row - enforce_trainer_profile_columns restricts this to specialty/experience/location/education/languages/availability regardless of RLS, so this row-level grant alone cannot be used to self-approve or change document paths.';


--
-- Name: training_academic_plans; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_academic_plans ENABLE ROW LEVEL SECURITY;

--
-- Name: training_academic_plans training_academic_plans_manager_all; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_academic_plans_manager_all ON public.training_academic_plans USING (public.current_user_can_manage_trainings()) WITH CHECK (public.current_user_can_manage_trainings());


--
-- Name: training_academic_plans training_academic_plans_trainer_draft; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_academic_plans_trainer_draft ON public.training_academic_plans FOR INSERT WITH CHECK (((status_code = 'draft'::text) AND (EXISTS ( SELECT 1
   FROM public.trainings t
  WHERE ((t.id = training_academic_plans.training_id) AND public.current_user_is_trainer_for(t.id))))));


--
-- Name: training_academic_plans training_academic_plans_trainer_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_academic_plans_trainer_read ON public.training_academic_plans FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.trainings t
  WHERE ((t.id = training_academic_plans.training_id) AND public.current_user_is_trainer_for(t.id)))));


--
-- Name: training_academic_plans training_academic_plans_trainer_update_draft; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_academic_plans_trainer_update_draft ON public.training_academic_plans FOR UPDATE USING (((status_code = 'draft'::text) AND (EXISTS ( SELECT 1
   FROM public.trainings t
  WHERE ((t.id = training_academic_plans.training_id) AND public.current_user_is_trainer_for(t.id)))))) WITH CHECK (((status_code = ANY (ARRAY['draft'::text, 'pending_approval'::text])) AND (EXISTS ( SELECT 1
   FROM public.trainings t
  WHERE ((t.id = training_academic_plans.training_id) AND public.current_user_is_trainer_for(t.id))))));


--
-- Name: training_assessment_grade_history; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_assessment_grade_history ENABLE ROW LEVEL SECURITY;

--
-- Name: training_assessment_grade_history training_assessment_grade_history_staff_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_assessment_grade_history_staff_read ON public.training_assessment_grade_history FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.training_registrations r
  WHERE ((r.id = training_assessment_grade_history.training_registration_id) AND (public.current_user_is_trainer_for(r.training_id) OR public.current_user_can_manage_trainings())))));


--
-- Name: training_assessment_grades; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_assessment_grades ENABLE ROW LEVEL SECURITY;

--
-- Name: training_assessment_grades training_assessment_grades_delivery; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_assessment_grades_delivery ON public.training_assessment_grades USING ((EXISTS ( SELECT 1
   FROM public.training_registrations r
  WHERE ((r.id = training_assessment_grades.training_registration_id) AND (public.current_user_is_trainer_for(r.training_id) OR public.current_user_can_manage_trainings()))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM public.training_registrations r
  WHERE ((r.id = training_assessment_grades.training_registration_id) AND (public.current_user_is_trainer_for(r.training_id) OR public.current_user_can_manage_trainings())))));


--
-- Name: training_assessment_grades training_assessment_grades_trainee_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_assessment_grades_trainee_read ON public.training_assessment_grades FOR SELECT USING (public.current_user_owns_training_registration(training_registration_id));


--
-- Name: training_assessments; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_assessments ENABLE ROW LEVEL SECURITY;

--
-- Name: training_assessments training_assessments_manager_all; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_assessments_manager_all ON public.training_assessments USING (public.current_user_can_manage_trainings()) WITH CHECK (public.current_user_can_manage_trainings());


--
-- Name: training_assessments training_assessments_trainer_draft_all; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_assessments_trainer_draft_all ON public.training_assessments USING ((EXISTS ( SELECT 1
   FROM public.training_academic_plans p
  WHERE ((p.id = training_assessments.academic_plan_id) AND (p.status_code = 'draft'::text) AND public.current_user_is_trainer_for(p.training_id))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM public.training_academic_plans p
  WHERE ((p.id = training_assessments.academic_plan_id) AND (p.status_code = 'draft'::text) AND public.current_user_is_trainer_for(p.training_id)))));


--
-- Name: training_assessments training_assessments_trainer_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_assessments_trainer_read ON public.training_assessments FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.training_academic_plans p
  WHERE ((p.id = training_assessments.academic_plan_id) AND public.current_user_is_trainer_for(p.training_id)))));


--
-- Name: training_assignments; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_assignments ENABLE ROW LEVEL SECURITY;

--
-- Name: training_assignments training_assignments_delivery_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_assignments_delivery_manage ON public.training_assignments USING ((public.current_user_is_trainer_for(training_id) OR public.current_user_has_permission('training.manage'::text))) WITH CHECK ((public.current_user_is_trainer_for(training_id) OR public.current_user_has_permission('training.manage'::text)));


--
-- Name: training_assignments training_assignments_staff_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_assignments_staff_read ON public.training_assignments FOR SELECT USING (public.current_user_has_permission('training.read'::text));


--
-- Name: training_assignments training_assignments_trainee_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_assignments_trainee_read ON public.training_assignments FOR SELECT USING ((is_published AND public.current_user_is_trainee_for(training_id)));


--
-- Name: training_attendance; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_attendance ENABLE ROW LEVEL SECURITY;

--
-- Name: training_attendance training_attendance_delivery_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_attendance_delivery_manage ON public.training_attendance TO authenticated USING (public.current_user_can_manage_attendance(training_session_id)) WITH CHECK (public.current_user_can_manage_attendance(training_session_id));


--
-- Name: training_attendance training_attendance_staff_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_attendance_staff_read ON public.training_attendance FOR SELECT TO authenticated USING (public.current_user_has_permission('training.read'::text));


--
-- Name: training_attendance training_attendance_trainee_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_attendance_trainee_read ON public.training_attendance FOR SELECT TO authenticated USING (public.current_user_owns_training_registration(training_registration_id));


--
-- Name: training_certificate_reissue_authorizations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_certificate_reissue_authorizations ENABLE ROW LEVEL SECURITY;

--
-- Name: training_certificate_reissue_authorizations training_certificate_reissue_authorizations_staff_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_certificate_reissue_authorizations_staff_read ON public.training_certificate_reissue_authorizations FOR SELECT USING (public.current_user_can_manage_trainings());


--
-- Name: training_certificates; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_certificates ENABLE ROW LEVEL SECURITY;

--
-- Name: training_certificates training_certificates_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_certificates_manage ON public.training_certificates USING (public.current_user_has_permission('training.manage'::text)) WITH CHECK (public.current_user_has_permission('training.manage'::text));


--
-- Name: training_certificates training_certificates_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_certificates_read ON public.training_certificates FOR SELECT USING (public.current_user_has_permission('training.read'::text));


--
-- Name: training_charges; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_charges ENABLE ROW LEVEL SECURITY;

--
-- Name: training_charges training_charges_finance_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_charges_finance_read ON public.training_charges FOR SELECT USING ((public.current_user_has_permission('finance.read'::text) OR public.current_user_has_permission('finance.manage'::text)));


--
-- Name: training_charges training_charges_self_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_charges_self_read ON public.training_charges FOR SELECT USING (public.current_user_owns_training_registration(training_registration_id));


--
-- Name: POLICY training_charges_self_read ON training_charges; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON POLICY training_charges_self_read ON public.training_charges IS 'A trainee can read their own charge (amount, currency, receipt once issued). No trainee-facing payment centre UI exists yet - this policy exists so one can be added without a further migration, same reasoning as payment_records_self_read.';


--
-- Name: training_completion_rules; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_completion_rules ENABLE ROW LEVEL SECURITY;

--
-- Name: training_completion_rules training_completion_rules_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_completion_rules_manage ON public.training_completion_rules USING (public.current_user_can_manage_trainings()) WITH CHECK (public.current_user_can_manage_trainings());


--
-- Name: training_completion_rules training_completion_rules_staff_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_completion_rules_staff_read ON public.training_completion_rules FOR SELECT USING (public.current_user_has_permission('training.read'::text));


--
-- Name: training_completion_rules training_completion_rules_trainee_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_completion_rules_trainee_read ON public.training_completion_rules FOR SELECT USING ((public.current_user_is_trainee_for(training_id) OR (EXISTS ( SELECT 1
   FROM public.training_registrations tr
  WHERE ((tr.training_id = training_completion_rules.training_id) AND public.current_user_owns_training_registration(tr.id))))));


--
-- Name: training_completion_rules training_completion_rules_trainer_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_completion_rules_trainer_read ON public.training_completion_rules FOR SELECT USING (public.current_user_is_trainer_for(training_id));


--
-- Name: training_fee_access_exceptions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_fee_access_exceptions ENABLE ROW LEVEL SECURITY;

--
-- Name: training_fee_access_exceptions training_fee_access_exceptions_staff_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_fee_access_exceptions_staff_read ON public.training_fee_access_exceptions FOR SELECT USING ((public.current_user_has_permission('finance.read'::text) OR public.current_user_has_permission('finance.manage'::text) OR public.current_user_has_permission('training.manage'::text)));


--
-- Name: training_fee_proof_submissions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_fee_proof_submissions ENABLE ROW LEVEL SECURITY;

--
-- Name: training_fee_proof_submissions training_fee_proof_submissions_finance_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_fee_proof_submissions_finance_read ON public.training_fee_proof_submissions FOR SELECT USING ((public.current_user_has_permission('finance.read'::text) OR public.current_user_has_permission('finance.manage'::text)));


--
-- Name: training_fee_proof_submissions training_fee_proof_submissions_self_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_fee_proof_submissions_self_insert ON public.training_fee_proof_submissions FOR INSERT WITH CHECK (((EXISTS ( SELECT 1
   FROM public.training_charges tc
  WHERE ((tc.id = training_fee_proof_submissions.training_charge_id) AND public.current_user_owns_training_registration(tc.training_registration_id)))) AND (NOT public.training_charge_has_pending_or_accepted_proof_submission(training_charge_id))));


--
-- Name: training_fee_proof_submissions training_fee_proof_submissions_self_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_fee_proof_submissions_self_read ON public.training_fee_proof_submissions FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.training_charges tc
  WHERE ((tc.id = training_fee_proof_submissions.training_charge_id) AND public.current_user_owns_training_registration(tc.training_registration_id)))));


--
-- Name: training_fee_refunds; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_fee_refunds ENABLE ROW LEVEL SECURITY;

--
-- Name: training_fee_refunds training_fee_refunds_finance_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_fee_refunds_finance_insert ON public.training_fee_refunds FOR INSERT WITH CHECK ((public.current_user_has_permission('finance.manage'::text) AND (EXISTS ( SELECT 1
   FROM public.training_charges tc
  WHERE (tc.id = training_fee_refunds.training_charge_id)))));


--
-- Name: training_fee_refunds training_fee_refunds_finance_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_fee_refunds_finance_read ON public.training_fee_refunds FOR SELECT USING ((public.current_user_has_permission('finance.read'::text) OR public.current_user_has_permission('finance.manage'::text)));


--
-- Name: training_fee_refunds training_fee_refunds_self_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_fee_refunds_self_read ON public.training_fee_refunds FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.training_charges tc
  WHERE ((tc.id = training_fee_refunds.training_charge_id) AND public.current_user_owns_training_registration(tc.training_registration_id)))));


--
-- Name: training_fee_transactions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_fee_transactions ENABLE ROW LEVEL SECURITY;

--
-- Name: training_fee_transactions training_fee_transactions_finance_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_fee_transactions_finance_insert ON public.training_fee_transactions FOR INSERT WITH CHECK ((public.current_user_has_permission('finance.manage'::text) AND (EXISTS ( SELECT 1
   FROM public.training_charges tc
  WHERE (tc.id = training_fee_transactions.training_charge_id)))));


--
-- Name: training_fee_transactions training_fee_transactions_finance_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_fee_transactions_finance_read ON public.training_fee_transactions FOR SELECT USING ((public.current_user_has_permission('finance.read'::text) OR public.current_user_has_permission('finance.manage'::text)));


--
-- Name: training_fee_transactions training_fee_transactions_self_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_fee_transactions_self_read ON public.training_fee_transactions FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.training_charges tc
  WHERE ((tc.id = training_fee_transactions.training_charge_id) AND public.current_user_owns_training_registration(tc.training_registration_id)))));


--
-- Name: training_feedback; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_feedback ENABLE ROW LEVEL SECURITY;

--
-- Name: training_feedback training_feedback_delivery_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_feedback_delivery_read ON public.training_feedback FOR SELECT TO authenticated USING (((EXISTS ( SELECT 1
   FROM public.training_registrations registration
  WHERE ((registration.id = training_feedback.training_registration_id) AND public.current_user_is_trainer_for(registration.training_id)))) OR public.current_user_has_permission('training.read'::text)));


--
-- Name: training_feedback training_feedback_trainee_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_feedback_trainee_insert ON public.training_feedback FOR INSERT TO authenticated WITH CHECK (public.current_user_can_submit_training_feedback(training_registration_id));


--
-- Name: training_feedback training_feedback_trainee_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_feedback_trainee_select ON public.training_feedback FOR SELECT TO authenticated USING (public.current_user_owns_training_registration(training_registration_id));


--
-- Name: training_feedback training_feedback_trainee_update; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_feedback_trainee_update ON public.training_feedback FOR UPDATE TO authenticated USING (public.current_user_can_submit_training_feedback(training_registration_id)) WITH CHECK (public.current_user_can_submit_training_feedback(training_registration_id));


--
-- Name: training_final_grades; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_final_grades ENABLE ROW LEVEL SECURITY;

--
-- Name: training_final_grades training_final_grades_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_final_grades_read ON public.training_final_grades FOR SELECT USING ((((status_code = 'approved'::text) AND public.current_user_owns_training_registration(training_registration_id)) OR (EXISTS ( SELECT 1
   FROM public.training_registrations r
  WHERE ((r.id = training_final_grades.training_registration_id) AND (public.current_user_is_trainer_for(r.training_id) OR public.current_user_can_manage_trainings()))))));


--
-- Name: training_materials; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_materials ENABLE ROW LEVEL SECURITY;

--
-- Name: training_materials training_materials_delivery_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_materials_delivery_manage ON public.training_materials TO authenticated USING ((public.current_user_is_trainer_for(training_id) OR public.current_user_has_permission('training.manage'::text))) WITH CHECK ((public.current_user_is_trainer_for(training_id) OR public.current_user_has_permission('training.manage'::text)));


--
-- Name: training_materials training_materials_staff_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_materials_staff_read ON public.training_materials FOR SELECT TO authenticated USING (public.current_user_has_permission('training.read'::text));


--
-- Name: training_materials training_materials_trainee_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_materials_trainee_read ON public.training_materials FOR SELECT TO authenticated USING ((is_published AND public.current_user_is_trainee_for(training_id)));


--
-- Name: training_prerequisite_decisions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_prerequisite_decisions ENABLE ROW LEVEL SECURITY;

--
-- Name: training_prerequisite_decisions training_prerequisite_decisions_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_prerequisite_decisions_select ON public.training_prerequisite_decisions FOR SELECT USING (public.current_user_can_view_registration(training_registration_id));


--
-- Name: training_prerequisite_evidence; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_prerequisite_evidence ENABLE ROW LEVEL SECURITY;

--
-- Name: training_prerequisite_evidence training_prerequisite_evidence_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_prerequisite_evidence_select ON public.training_prerequisite_evidence FOR SELECT USING (public.current_user_can_view_registration(training_registration_id));


--
-- Name: POLICY training_prerequisite_evidence_select ON training_prerequisite_evidence; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON POLICY training_prerequisite_evidence_select ON public.training_prerequisite_evidence IS 'The trainee who owns the registration, the assigned trainer, or a training manager/admin/super_admin may read it. No insert/update policy - submit_prerequisite_evidence()/review_prerequisite_evidence() (security definer) are the only ways to write.';


--
-- Name: training_prerequisites; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_prerequisites ENABLE ROW LEVEL SECURITY;

--
-- Name: training_prerequisites training_prerequisites_manage_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_prerequisites_manage_insert ON public.training_prerequisites FOR INSERT WITH CHECK (public.current_user_can_manage_trainings());


--
-- Name: POLICY training_prerequisites_manage_insert ON training_prerequisites; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON POLICY training_prerequisites_manage_insert ON public.training_prerequisites IS 'A training manager/admin/super_admin may define a prerequisite for any training - matches every other write in TrainingManagementPanel.tsx.';


--
-- Name: training_prerequisites training_prerequisites_manage_update; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_prerequisites_manage_update ON public.training_prerequisites FOR UPDATE USING (public.current_user_can_manage_trainings()) WITH CHECK (public.current_user_can_manage_trainings());


--
-- Name: POLICY training_prerequisites_manage_update ON training_prerequisites; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON POLICY training_prerequisites_manage_update ON public.training_prerequisites IS 'Same permission as insert. Used to edit a definition or deactivate one (active = false) - there is no delete policy, so retiring a prerequisite never destroys the evidence/decision history already recorded against it.';


--
-- Name: training_prerequisites training_prerequisites_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_prerequisites_select ON public.training_prerequisites FOR SELECT USING (true);


--
-- Name: POLICY training_prerequisites_select ON training_prerequisites; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON POLICY training_prerequisites_select ON public.training_prerequisites IS 'Prerequisite definitions are non-sensitive training metadata - any signed-in user may read them (needed for the trainee evidence form and trainer recommendation screen). No insert/update/delete policy exists - these rows remain database-managed only.';


--
-- Name: training_question_bank_questions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_question_bank_questions ENABLE ROW LEVEL SECURITY;

--
-- Name: training_question_bank_questions training_question_bank_questions_owner; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_question_bank_questions_owner ON public.training_question_bank_questions USING ((EXISTS ( SELECT 1
   FROM public.training_question_banks b
  WHERE ((b.id = training_question_bank_questions.question_bank_id) AND ((b.owner_id = auth.uid()) OR public.current_user_can_manage_trainings()))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM public.training_question_banks b
  WHERE ((b.id = training_question_bank_questions.question_bank_id) AND ((b.owner_id = auth.uid()) OR public.current_user_can_manage_trainings())))));


--
-- Name: training_question_banks; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_question_banks ENABLE ROW LEVEL SECURITY;

--
-- Name: training_question_banks training_question_banks_owner; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_question_banks_owner ON public.training_question_banks USING (((owner_id = auth.uid()) OR public.current_user_can_manage_trainings())) WITH CHECK (((owner_id = auth.uid()) OR public.current_user_can_manage_trainings()));


--
-- Name: training_quiz_accommodations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_quiz_accommodations ENABLE ROW LEVEL SECURITY;

--
-- Name: training_quiz_accommodations training_quiz_accommodations_staff; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_quiz_accommodations_staff ON public.training_quiz_accommodations USING ((EXISTS ( SELECT 1
   FROM (public.training_quizzes q
     JOIN public.training_registrations r ON ((r.id = training_quiz_accommodations.training_registration_id)))
  WHERE ((q.id = training_quiz_accommodations.quiz_id) AND (r.training_id = q.training_id) AND (public.current_user_is_trainer_for(q.training_id) OR public.current_user_can_manage_trainings()))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM (public.training_quizzes q
     JOIN public.training_registrations r ON ((r.id = training_quiz_accommodations.training_registration_id)))
  WHERE ((q.id = training_quiz_accommodations.quiz_id) AND (r.training_id = q.training_id) AND (public.current_user_is_trainer_for(q.training_id) OR public.current_user_can_manage_trainings())))));


--
-- Name: training_quiz_answers; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_quiz_answers ENABLE ROW LEVEL SECURITY;

--
-- Name: training_quiz_answers training_quiz_answers_staff_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_quiz_answers_staff_read ON public.training_quiz_answers FOR SELECT USING ((EXISTS ( SELECT 1
   FROM (public.training_quiz_attempts a
     JOIN public.training_quizzes q ON ((q.id = a.quiz_id)))
  WHERE ((a.id = training_quiz_answers.quiz_attempt_id) AND (public.current_user_is_trainer_for(q.training_id) OR public.current_user_can_manage_trainings())))));


--
-- Name: training_quiz_attempts; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_quiz_attempts ENABLE ROW LEVEL SECURITY;

--
-- Name: training_quiz_attempts training_quiz_attempts_staff_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_quiz_attempts_staff_read ON public.training_quiz_attempts FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.training_quizzes q
  WHERE ((q.id = training_quiz_attempts.quiz_id) AND (public.current_user_is_trainer_for(q.training_id) OR public.current_user_can_manage_trainings())))));


--
-- Name: training_quiz_grade_overrides; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_quiz_grade_overrides ENABLE ROW LEVEL SECURITY;

--
-- Name: training_quiz_grade_overrides training_quiz_grade_overrides_staff; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_quiz_grade_overrides_staff ON public.training_quiz_grade_overrides USING ((EXISTS ( SELECT 1
   FROM public.training_quizzes q
  WHERE ((q.id = training_quiz_grade_overrides.quiz_id) AND (public.current_user_is_trainer_for(q.training_id) OR public.current_user_can_manage_trainings()))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM (public.training_quizzes q
     JOIN public.training_registrations r ON ((r.id = training_quiz_grade_overrides.training_registration_id)))
  WHERE ((q.id = training_quiz_grade_overrides.quiz_id) AND (r.training_id = q.training_id) AND (public.current_user_is_trainer_for(q.training_id) OR public.current_user_can_manage_trainings())))));


--
-- Name: training_quiz_question_adjustments; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_quiz_question_adjustments ENABLE ROW LEVEL SECURITY;

--
-- Name: training_quiz_question_adjustments training_quiz_question_adjustments_staff; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_quiz_question_adjustments_staff ON public.training_quiz_question_adjustments USING ((EXISTS ( SELECT 1
   FROM (public.training_quiz_questions question
     JOIN public.training_quizzes q ON ((q.id = question.quiz_id)))
  WHERE ((question.id = training_quiz_question_adjustments.quiz_question_id) AND (public.current_user_is_trainer_for(q.training_id) OR public.current_user_can_manage_trainings()))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM (public.training_quiz_questions question
     JOIN public.training_quizzes q ON ((q.id = question.quiz_id)))
  WHERE ((question.id = training_quiz_question_adjustments.quiz_question_id) AND (public.current_user_is_trainer_for(q.training_id) OR public.current_user_can_manage_trainings())))));


--
-- Name: training_quiz_questions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_quiz_questions ENABLE ROW LEVEL SECURITY;

--
-- Name: training_quiz_questions training_quiz_questions_staff; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_quiz_questions_staff ON public.training_quiz_questions USING ((EXISTS ( SELECT 1
   FROM public.training_quizzes q
  WHERE ((q.id = training_quiz_questions.quiz_id) AND (public.current_user_is_trainer_for(q.training_id) OR public.current_user_can_manage_trainings()))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM public.training_quizzes q
  WHERE ((q.id = training_quiz_questions.quiz_id) AND (public.current_user_is_trainer_for(q.training_id) OR public.current_user_can_manage_trainings())))));


--
-- Name: training_quizzes; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_quizzes ENABLE ROW LEVEL SECURITY;

--
-- Name: training_quizzes training_quizzes_staff; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_quizzes_staff ON public.training_quizzes USING ((public.current_user_is_trainer_for(training_id) OR public.current_user_can_manage_trainings())) WITH CHECK ((public.current_user_is_trainer_for(training_id) OR public.current_user_can_manage_trainings()));


--
-- Name: training_registration_status_history; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_registration_status_history ENABLE ROW LEVEL SECURITY;

--
-- Name: training_registration_status_history training_registration_status_history_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_registration_status_history_select ON public.training_registration_status_history FOR SELECT USING (public.current_user_can_view_registration(training_registration_id));


--
-- Name: training_registrations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_registrations ENABLE ROW LEVEL SECURITY;

--
-- Name: training_registrations training_registrations_approval_update; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_registrations_approval_update ON public.training_registrations FOR UPDATE USING ((public.current_user_is_trainer_for(training_id) OR public.current_user_has_role('training_manager'::text) OR public.current_user_has_role('admin'::text) OR public.current_user_has_role('super_admin'::text))) WITH CHECK ((public.current_user_is_trainer_for(training_id) OR public.current_user_has_role('training_manager'::text) OR public.current_user_has_role('admin'::text) OR public.current_user_has_role('super_admin'::text)));


--
-- Name: POLICY training_registrations_approval_update ON training_registrations; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON POLICY training_registrations_approval_update ON public.training_registrations IS 'A trainer can approve/reject/mark-paid registrations for their own training only (current_user_is_trainer_for); training_manager/admin/super_admin can do so for any training.';


--
-- Name: training_registrations training_registrations_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_registrations_auditor_read ON public.training_registrations FOR SELECT USING (public.current_user_has_role('auditor'::text));


--
-- Name: training_registrations training_registrations_manage_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_registrations_manage_select ON public.training_registrations FOR SELECT USING (public.current_user_can_manage_trainings());


--
-- Name: training_registrations training_registrations_self_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_registrations_self_select ON public.training_registrations FOR SELECT USING ((person_id = public.current_person_id()));


--
-- Name: POLICY training_registrations_self_select ON training_registrations; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON POLICY training_registrations_self_select ON public.training_registrations IS 'A trainee can see their own registration rows (and, through the trainings/training_translations public-read policies, the training details) once approve-registration.ts has linked person_id to their people row.';


--
-- Name: training_registrations training_registrations_trainer_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_registrations_trainer_select ON public.training_registrations FOR SELECT USING (public.current_user_is_trainer_for(training_id));


--
-- Name: POLICY training_registrations_trainer_select ON training_registrations; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON POLICY training_registrations_trainer_select ON public.training_registrations IS 'Lets the training''s own assigned trainer see registrations for it - the SELECT half of the same permission training_registrations_approval_update already grants for UPDATE. Without this, that UPDATE policy was unusable in practice (a client can''t discover row IDs it was never allowed to list).';


--
-- Name: training_sessions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_sessions ENABLE ROW LEVEL SECURITY;

--
-- Name: training_sessions training_sessions_delivery_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_sessions_delivery_manage ON public.training_sessions TO authenticated USING ((public.current_user_is_trainer_for(training_id) OR public.current_user_has_permission('training.manage'::text))) WITH CHECK ((public.current_user_is_trainer_for(training_id) OR public.current_user_has_permission('training.manage'::text)));


--
-- Name: training_sessions training_sessions_staff_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_sessions_staff_read ON public.training_sessions FOR SELECT TO authenticated USING (public.current_user_has_permission('training.read'::text));


--
-- Name: training_sessions training_sessions_trainee_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_sessions_trainee_read ON public.training_sessions FOR SELECT TO authenticated USING (public.current_user_is_trainee_for(training_id));


--
-- Name: training_submissions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_submissions ENABLE ROW LEVEL SECURITY;

--
-- Name: training_submissions training_submissions_delivery_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_submissions_delivery_manage ON public.training_submissions USING ((public.current_user_has_permission('training.manage'::text) OR (EXISTS ( SELECT 1
   FROM public.training_assignments ta
  WHERE ((ta.id = training_submissions.training_assignment_id) AND public.current_user_is_trainer_for(ta.training_id)))))) WITH CHECK ((public.current_user_has_permission('training.manage'::text) OR (EXISTS ( SELECT 1
   FROM public.training_assignments ta
  WHERE ((ta.id = training_submissions.training_assignment_id) AND public.current_user_is_trainer_for(ta.training_id))))));


--
-- Name: training_submissions training_submissions_self_delete; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_submissions_self_delete ON public.training_submissions FOR DELETE USING ((public.current_user_owns_training_registration(training_registration_id) AND (EXISTS ( SELECT 1
   FROM (public.training_assignments assignment
     JOIN public.training_registrations registration ON ((registration.id = training_submissions.training_registration_id)))
  WHERE ((assignment.id = training_submissions.training_assignment_id) AND (assignment.training_id = registration.training_id) AND public.current_user_is_trainee_for(assignment.training_id))))));


--
-- Name: training_submissions training_submissions_self_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_submissions_self_insert ON public.training_submissions FOR INSERT WITH CHECK ((public.current_user_owns_training_registration(training_registration_id) AND (EXISTS ( SELECT 1
   FROM (public.training_assignments assignment
     JOIN public.training_registrations registration ON ((registration.id = training_submissions.training_registration_id)))
  WHERE ((assignment.id = training_submissions.training_assignment_id) AND (assignment.training_id = registration.training_id) AND public.current_user_is_trainee_for(assignment.training_id))))));


--
-- Name: training_submissions training_submissions_self_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_submissions_self_read ON public.training_submissions FOR SELECT USING (public.current_user_owns_training_registration(training_registration_id));


--
-- Name: training_submissions training_submissions_self_update; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_submissions_self_update ON public.training_submissions FOR UPDATE USING (public.current_user_owns_training_registration(training_registration_id)) WITH CHECK ((public.current_user_owns_training_registration(training_registration_id) AND (EXISTS ( SELECT 1
   FROM (public.training_assignments assignment
     JOIN public.training_registrations registration ON ((registration.id = training_submissions.training_registration_id)))
  WHERE ((assignment.id = training_submissions.training_assignment_id) AND (assignment.training_id = registration.training_id) AND public.current_user_is_trainee_for(assignment.training_id))))));


--
-- Name: training_submissions training_submissions_staff_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_submissions_staff_read ON public.training_submissions FOR SELECT USING (public.current_user_has_permission('training.read'::text));


--
-- Name: training_task_assessment_overrides; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_task_assessment_overrides ENABLE ROW LEVEL SECURITY;

--
-- Name: training_task_assessment_overrides training_task_assessment_overrides_staff_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_task_assessment_overrides_staff_read ON public.training_task_assessment_overrides FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.training_registrations r
  WHERE ((r.id = training_task_assessment_overrides.training_registration_id) AND (public.current_user_is_trainer_for(r.training_id) OR public.current_user_can_manage_trainings())))));


--
-- Name: training_task_mark_history; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_task_mark_history ENABLE ROW LEVEL SECURITY;

--
-- Name: training_task_mark_history training_task_mark_history_staff_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_task_mark_history_staff_read ON public.training_task_mark_history FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.training_registrations r
  WHERE ((r.id = training_task_mark_history.training_registration_id) AND (public.current_user_is_trainer_for(r.training_id) OR public.current_user_can_manage_trainings())))));


--
-- Name: training_task_marks; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_task_marks ENABLE ROW LEVEL SECURITY;

--
-- Name: training_task_marks training_task_marks_staff_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_task_marks_staff_read ON public.training_task_marks FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.training_registrations r
  WHERE ((r.id = training_task_marks.training_registration_id) AND (public.current_user_is_trainer_for(r.training_id) OR public.current_user_can_manage_trainings() OR public.current_user_has_permission('training.read'::text))))));


--
-- Name: training_task_marks training_task_marks_trainee_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_task_marks_trainee_read ON public.training_task_marks FOR SELECT USING ((public.current_user_owns_training_registration(training_registration_id) AND public.training_task_is_published(training_assignment_id)));


--
-- Name: training_translations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_translations ENABLE ROW LEVEL SECURITY;

--
-- Name: training_translations training_translations_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_translations_auditor_read ON public.training_translations FOR SELECT USING (public.current_user_has_role('auditor'::text));


--
-- Name: training_translations training_translations_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_translations_manage ON public.training_translations USING (public.current_user_can_manage_trainings()) WITH CHECK (public.current_user_can_manage_trainings());


--
-- Name: training_translations training_translations_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_translations_public_read ON public.training_translations FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.trainings tr
  WHERE ((tr.id = training_translations.training_id) AND (tr.publication_status_code = ANY (ARRAY['published'::text, 'publish_pending'::text]))))));


--
-- Name: training_translations training_translations_registrant_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_translations_registrant_read ON public.training_translations FOR SELECT TO authenticated USING (public.current_user_registered_for(training_id));


--
-- Name: training_translations training_translations_trainer_own; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_translations_trainer_own ON public.training_translations USING ((EXISTS ( SELECT 1
   FROM public.trainings t
  WHERE ((t.id = training_translations.training_id) AND (t.trainer_id = public.current_user_trainer_id()))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM public.trainings t
  WHERE ((t.id = training_translations.training_id) AND (t.trainer_id = public.current_user_trainer_id())))));


--
-- Name: training_waitlist_entries; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.training_waitlist_entries ENABLE ROW LEVEL SECURITY;

--
-- Name: training_waitlist_entries training_waitlist_entries_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY training_waitlist_entries_select ON public.training_waitlist_entries FOR SELECT USING (public.current_user_can_view_registration(training_registration_id));


--
-- Name: trainings; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.trainings ENABLE ROW LEVEL SECURITY;

--
-- Name: trainings trainings_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY trainings_auditor_read ON public.trainings FOR SELECT USING (public.current_user_has_role('auditor'::text));


--
-- Name: trainings trainings_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY trainings_manage ON public.trainings USING (public.current_user_can_manage_trainings()) WITH CHECK (public.current_user_can_manage_trainings());


--
-- Name: trainings trainings_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY trainings_public_read ON public.trainings FOR SELECT USING ((publication_status_code = ANY (ARRAY['published'::text, 'publish_pending'::text])));


--
-- Name: trainings trainings_registrant_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY trainings_registrant_read ON public.trainings FOR SELECT TO authenticated USING (public.current_user_registered_for(id));


--
-- Name: trainings trainings_trainer_propose; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY trainings_trainer_propose ON public.trainings FOR INSERT WITH CHECK ((trainer_id = public.current_user_trainer_id()));


--
-- Name: POLICY trainings_trainer_propose ON trainings; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON POLICY trainings_trainer_propose ON public.trainings IS 'A trainer can only ever insert/select/update a row where trainer_id is their own - never another trainer''s. Publishing it is still blocked by enforce_training_publish_approval regardless of these policies.';


--
-- Name: trainings trainings_trainer_select_own; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY trainings_trainer_select_own ON public.trainings FOR SELECT USING ((trainer_id = public.current_user_trainer_id()));


--
-- Name: trainings trainings_trainer_update_own; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY trainings_trainer_update_own ON public.trainings FOR UPDATE USING ((trainer_id = public.current_user_trainer_id())) WITH CHECK ((trainer_id = public.current_user_trainer_id()));


--
-- Name: user_invitations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.user_invitations ENABLE ROW LEVEL SECURITY;

--
-- Name: user_invitations user_invitations_super_admin_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY user_invitations_super_admin_manage ON public.user_invitations USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: user_profiles; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.user_profiles ENABLE ROW LEVEL SECURITY;

--
-- Name: user_profiles user_profiles_self_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY user_profiles_self_read ON public.user_profiles FOR SELECT USING ((user_id = auth.uid()));


--
-- Name: user_profiles user_profiles_super_admin_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY user_profiles_super_admin_manage ON public.user_profiles USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: user_role_assignments; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.user_role_assignments ENABLE ROW LEVEL SECURITY;

--
-- Name: user_role_assignments user_role_assignments_self_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY user_role_assignments_self_read ON public.user_role_assignments FOR SELECT USING ((user_id = auth.uid()));


--
-- Name: user_role_assignments user_role_assignments_super_admin_all; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY user_role_assignments_super_admin_all ON public.user_role_assignments USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: verification_reviews; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.verification_reviews ENABLE ROW LEVEL SECURITY;

--
-- Name: verification_reviews verification_reviews_authorized; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY verification_reviews_authorized ON public.verification_reviews USING (public.current_user_can_access_observation(indicator_observation_id, 'impact.manage'::text)) WITH CHECK (public.current_user_can_access_observation(indicator_observation_id, 'impact.manage'::text));


--
-- Name: verification_reviews verification_reviews_authorized_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY verification_reviews_authorized_read ON public.verification_reviews FOR SELECT USING (public.current_user_can_access_observation(indicator_observation_id, 'impact.read'::text));


--
-- Name: verification_statuses; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.verification_statuses ENABLE ROW LEVEL SECURITY;

--
-- Name: verification_statuses verification_statuses_public_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY verification_statuses_public_read ON public.verification_statuses FOR SELECT USING (true);


--
-- Name: verification_statuses verification_statuses_super_admin_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY verification_statuses_super_admin_write ON public.verification_statuses USING (public.current_user_has_role('super_admin'::text)) WITH CHECK (public.current_user_has_role('super_admin'::text));


--
-- Name: volunteer_applications; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.volunteer_applications ENABLE ROW LEVEL SECURITY;

--
-- Name: volunteer_applications volunteer_applications_auditor_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY volunteer_applications_auditor_read ON public.volunteer_applications FOR SELECT USING (public.current_user_has_role('auditor'::text));


--
-- Name: volunteer_applications volunteer_applications_manage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY volunteer_applications_manage ON public.volunteer_applications USING (public.current_user_can_manage_intake()) WITH CHECK (public.current_user_can_manage_intake());


--
-- Name: attendance_records; Type: ROW SECURITY; Schema: restricted; Owner: -
--

ALTER TABLE restricted.attendance_records ENABLE ROW LEVEL SECURITY;

--
-- Name: attendance_records attendance_records_program_staff; Type: POLICY; Schema: restricted; Owner: -
--

CREATE POLICY attendance_records_program_staff ON restricted.attendance_records USING ((EXISTS ( SELECT 1
   FROM restricted.program_enrollments pe
  WHERE ((pe.id = attendance_records.enrollment_id) AND public.current_user_can_access_cohort(pe.cohort_id, 'participants.manage'::text))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM restricted.program_enrollments pe
  WHERE ((pe.id = attendance_records.enrollment_id) AND public.current_user_can_access_cohort(pe.cohort_id, 'participants.manage'::text)))));


--
-- Name: attendance_records attendance_records_program_staff_read; Type: POLICY; Schema: restricted; Owner: -
--

CREATE POLICY attendance_records_program_staff_read ON restricted.attendance_records FOR SELECT USING ((EXISTS ( SELECT 1
   FROM restricted.program_enrollments pe
  WHERE ((pe.id = attendance_records.enrollment_id) AND public.current_user_can_access_cohort(pe.cohort_id, 'participants.read'::text)))));


--
-- Name: beneficiary_records; Type: ROW SECURITY; Schema: restricted; Owner: -
--

ALTER TABLE restricted.beneficiary_records ENABLE ROW LEVEL SECURITY;

--
-- Name: beneficiary_records beneficiary_records_authorized_read; Type: POLICY; Schema: restricted; Owner: -
--

CREATE POLICY beneficiary_records_authorized_read ON restricted.beneficiary_records FOR SELECT USING ((public.current_user_can_access_beneficiary(id, 'participants.read'::text) OR public.current_user_can_access_beneficiary(id, 'safeguarding.read'::text)));


--
-- Name: beneficiary_records beneficiary_records_authorized_update; Type: POLICY; Schema: restricted; Owner: -
--

CREATE POLICY beneficiary_records_authorized_update ON restricted.beneficiary_records FOR UPDATE USING ((public.current_user_can_access_beneficiary(id, 'participants.manage'::text) OR public.current_user_can_access_beneficiary(id, 'safeguarding.manage'::text))) WITH CHECK ((public.current_user_can_access_beneficiary(id, 'participants.manage'::text) OR public.current_user_can_access_beneficiary(id, 'safeguarding.manage'::text)));


--
-- Name: beneficiary_records beneficiary_records_global_insert; Type: POLICY; Schema: restricted; Owner: -
--

CREATE POLICY beneficiary_records_global_insert ON restricted.beneficiary_records FOR INSERT WITH CHECK ((public.current_user_has_permission('participants.manage'::text) OR public.current_user_has_permission('safeguarding.manage'::text)));


--
-- Name: guardian_relationships; Type: ROW SECURITY; Schema: restricted; Owner: -
--

ALTER TABLE restricted.guardian_relationships ENABLE ROW LEVEL SECURITY;

--
-- Name: guardian_relationships guardian_relationships_safeguarding; Type: POLICY; Schema: restricted; Owner: -
--

CREATE POLICY guardian_relationships_safeguarding ON restricted.guardian_relationships USING (public.current_user_can_access_beneficiary(beneficiary_id, 'safeguarding.manage'::text)) WITH CHECK (public.current_user_can_access_beneficiary(beneficiary_id, 'safeguarding.manage'::text));


--
-- Name: guardian_relationships guardian_relationships_safeguarding_read; Type: POLICY; Schema: restricted; Owner: -
--

CREATE POLICY guardian_relationships_safeguarding_read ON restricted.guardian_relationships FOR SELECT USING (public.current_user_can_access_beneficiary(beneficiary_id, 'safeguarding.read'::text));


--
-- Name: participation_consents; Type: ROW SECURITY; Schema: restricted; Owner: -
--

ALTER TABLE restricted.participation_consents ENABLE ROW LEVEL SECURITY;

--
-- Name: participation_consents participation_consents_safeguarding; Type: POLICY; Schema: restricted; Owner: -
--

CREATE POLICY participation_consents_safeguarding ON restricted.participation_consents USING (public.current_user_can_access_beneficiary(beneficiary_id, 'safeguarding.manage'::text)) WITH CHECK (public.current_user_can_access_beneficiary(beneficiary_id, 'safeguarding.manage'::text));


--
-- Name: participation_consents participation_consents_safeguarding_read; Type: POLICY; Schema: restricted; Owner: -
--

CREATE POLICY participation_consents_safeguarding_read ON restricted.participation_consents FOR SELECT USING (public.current_user_can_access_beneficiary(beneficiary_id, 'safeguarding.read'::text));


--
-- Name: program_enrollments; Type: ROW SECURITY; Schema: restricted; Owner: -
--

ALTER TABLE restricted.program_enrollments ENABLE ROW LEVEL SECURITY;

--
-- Name: program_enrollments program_enrollments_program_staff; Type: POLICY; Schema: restricted; Owner: -
--

CREATE POLICY program_enrollments_program_staff ON restricted.program_enrollments USING (public.current_user_can_access_cohort(cohort_id, 'participants.manage'::text)) WITH CHECK (public.current_user_can_access_cohort(cohort_id, 'participants.manage'::text));


--
-- Name: program_enrollments program_enrollments_program_staff_read; Type: POLICY; Schema: restricted; Owner: -
--

CREATE POLICY program_enrollments_program_staff_read ON restricted.program_enrollments FOR SELECT USING (public.current_user_can_access_cohort(cohort_id, 'participants.read'::text));


--
-- Name: referrals; Type: ROW SECURITY; Schema: restricted; Owner: -
--

ALTER TABLE restricted.referrals ENABLE ROW LEVEL SECURITY;

--
-- Name: referrals referrals_safeguarding; Type: POLICY; Schema: restricted; Owner: -
--

CREATE POLICY referrals_safeguarding ON restricted.referrals USING (public.current_user_can_access_beneficiary(beneficiary_id, 'safeguarding.manage'::text)) WITH CHECK (public.current_user_can_access_beneficiary(beneficiary_id, 'safeguarding.manage'::text));


--
-- Name: referrals referrals_safeguarding_read; Type: POLICY; Schema: restricted; Owner: -
--

CREATE POLICY referrals_safeguarding_read ON restricted.referrals FOR SELECT USING (public.current_user_can_access_beneficiary(beneficiary_id, 'safeguarding.read'::text));


--
-- Name: FUNCTION accept_waitlist_offer(p_registration_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.accept_waitlist_offer(p_registration_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.accept_waitlist_offer(p_registration_id uuid) TO authenticated;


--
-- Name: FUNCTION admin_can_manage_staff_user(p_user_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.admin_can_manage_staff_user(p_user_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.admin_can_manage_staff_user(p_user_id uuid) TO authenticated;


--
-- Name: FUNCTION admin_complete_mfa_recovery(p_user_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.admin_complete_mfa_recovery(p_user_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.admin_complete_mfa_recovery(p_user_id uuid) TO authenticated;


--
-- Name: FUNCTION admin_fail_mfa_recovery(p_user_id uuid, p_reason text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.admin_fail_mfa_recovery(p_user_id uuid, p_reason text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.admin_fail_mfa_recovery(p_user_id uuid, p_reason text) TO authenticated;


--
-- Name: FUNCTION admin_grant_role(target_email text, new_role_code text, p_scope_type text, p_scope_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.admin_grant_role(target_email text, new_role_code text, p_scope_type text, p_scope_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.admin_grant_role(target_email text, new_role_code text, p_scope_type text, p_scope_id uuid) TO authenticated;


--
-- Name: FUNCTION admin_list_role_assignments(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.admin_list_role_assignments() FROM PUBLIC;
GRANT ALL ON FUNCTION public.admin_list_role_assignments() TO authenticated;


--
-- Name: FUNCTION admin_list_roles(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.admin_list_roles() FROM PUBLIC;
GRANT ALL ON FUNCTION public.admin_list_roles() TO authenticated;


--
-- Name: FUNCTION admin_register_trainee(p_training_id uuid, p_full_name text, p_email text, p_phone text, p_reason text, p_override boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.admin_register_trainee(p_training_id uuid, p_full_name text, p_email text, p_phone text, p_reason text, p_override boolean) FROM PUBLIC;
GRANT ALL ON FUNCTION public.admin_register_trainee(p_training_id uuid, p_full_name text, p_email text, p_phone text, p_reason text, p_override boolean) TO authenticated;


--
-- Name: FUNCTION admin_release_recovery_hold(p_user_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.admin_release_recovery_hold(p_user_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.admin_release_recovery_hold(p_user_id uuid) TO authenticated;


--
-- Name: FUNCTION admin_revoke_role(assignment_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.admin_revoke_role(assignment_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.admin_revoke_role(assignment_id uuid) TO authenticated;


--
-- Name: FUNCTION admin_revoke_user_sessions(p_user_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.admin_revoke_user_sessions(p_user_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.admin_revoke_user_sessions(p_user_id uuid) TO authenticated;


--
-- Name: FUNCTION admin_role_access_matrix(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.admin_role_access_matrix() FROM PUBLIC;
GRANT ALL ON FUNCTION public.admin_role_access_matrix() TO authenticated;


--
-- Name: FUNCTION admin_start_mfa_recovery(p_user_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.admin_start_mfa_recovery(p_user_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.admin_start_mfa_recovery(p_user_id uuid) TO authenticated;


--
-- Name: FUNCTION assign_training_system_identity(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.assign_training_system_identity() FROM PUBLIC;


--
-- Name: FUNCTION authorize_certificate_reissue(p_registration_id uuid, p_reason text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.authorize_certificate_reissue(p_registration_id uuid, p_reason text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.authorize_certificate_reissue(p_registration_id uuid, p_reason text) TO authenticated;


--
-- Name: FUNCTION available_trainings_for_registration(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.available_trainings_for_registration() FROM PUBLIC;
GRANT ALL ON FUNCTION public.available_trainings_for_registration() TO authenticated;


--
-- Name: FUNCTION cancel_training_quiz_question(p_question_id uuid, p_reason text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.cancel_training_quiz_question(p_question_id uuid, p_reason text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.cancel_training_quiz_question(p_question_id uuid, p_reason text) TO authenticated;


--
-- Name: FUNCTION cancel_training_registration(p_registration_id uuid, p_reason text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.cancel_training_registration(p_registration_id uuid, p_reason text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.cancel_training_registration(p_registration_id uuid, p_reason text) TO authenticated;


--
-- Name: FUNCTION current_person_id(); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.current_person_id() TO authenticated;


--
-- Name: FUNCTION current_user_aal2(); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.current_user_aal2() TO authenticated;


--
-- Name: FUNCTION current_user_can_access_beneficiary(p_beneficiary_id uuid, p_permission text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.current_user_can_access_beneficiary(p_beneficiary_id uuid, p_permission text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.current_user_can_access_beneficiary(p_beneficiary_id uuid, p_permission text) TO authenticated;


--
-- Name: FUNCTION current_user_can_access_cohort(p_cohort_id uuid, p_permission text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.current_user_can_access_cohort(p_cohort_id uuid, p_permission text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.current_user_can_access_cohort(p_cohort_id uuid, p_permission text) TO authenticated;
GRANT ALL ON FUNCTION public.current_user_can_access_cohort(p_cohort_id uuid, p_permission text) TO anon;


--
-- Name: FUNCTION current_user_can_access_indicator_scope(p_scope_id uuid, p_permission text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.current_user_can_access_indicator_scope(p_scope_id uuid, p_permission text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.current_user_can_access_indicator_scope(p_scope_id uuid, p_permission text) TO authenticated;
GRANT ALL ON FUNCTION public.current_user_can_access_indicator_scope(p_scope_id uuid, p_permission text) TO anon;


--
-- Name: FUNCTION current_user_can_access_initiative(p_initiative_id uuid, p_permission text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.current_user_can_access_initiative(p_initiative_id uuid, p_permission text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.current_user_can_access_initiative(p_initiative_id uuid, p_permission text) TO authenticated;
GRANT ALL ON FUNCTION public.current_user_can_access_initiative(p_initiative_id uuid, p_permission text) TO anon;


--
-- Name: FUNCTION current_user_can_access_measurement_plan(p_plan_id uuid, p_permission text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.current_user_can_access_measurement_plan(p_plan_id uuid, p_permission text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.current_user_can_access_measurement_plan(p_plan_id uuid, p_permission text) TO authenticated;
GRANT ALL ON FUNCTION public.current_user_can_access_measurement_plan(p_plan_id uuid, p_permission text) TO anon;


--
-- Name: FUNCTION current_user_can_access_observation(p_observation_id uuid, p_permission text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.current_user_can_access_observation(p_observation_id uuid, p_permission text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.current_user_can_access_observation(p_observation_id uuid, p_permission text) TO authenticated;
GRANT ALL ON FUNCTION public.current_user_can_access_observation(p_observation_id uuid, p_permission text) TO anon;


--
-- Name: FUNCTION current_user_can_access_program(p_program_id uuid, p_permission text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.current_user_can_access_program(p_program_id uuid, p_permission text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.current_user_can_access_program(p_program_id uuid, p_permission text) TO authenticated;
GRANT ALL ON FUNCTION public.current_user_can_access_program(p_program_id uuid, p_permission text) TO anon;


--
-- Name: FUNCTION current_user_can_access_program_cycle(p_cycle_id uuid, p_permission text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.current_user_can_access_program_cycle(p_cycle_id uuid, p_permission text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.current_user_can_access_program_cycle(p_cycle_id uuid, p_permission text) TO authenticated;
GRANT ALL ON FUNCTION public.current_user_can_access_program_cycle(p_cycle_id uuid, p_permission text) TO anon;


--
-- Name: FUNCTION current_user_can_view_registration(p_training_registration_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.current_user_can_view_registration(p_training_registration_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.current_user_can_view_registration(p_training_registration_id uuid) TO authenticated;


--
-- Name: FUNCTION current_user_has_any_permission(check_permission text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.current_user_has_any_permission(check_permission text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.current_user_has_any_permission(check_permission text) TO authenticated;
GRANT ALL ON FUNCTION public.current_user_has_any_permission(check_permission text) TO anon;


--
-- Name: FUNCTION current_user_has_permission(check_permission text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.current_user_has_permission(check_permission text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.current_user_has_permission(check_permission text) TO authenticated;
GRANT ALL ON FUNCTION public.current_user_has_permission(check_permission text) TO anon;


--
-- Name: FUNCTION current_user_has_role(check_role text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.current_user_has_role(check_role text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.current_user_has_role(check_role text) TO authenticated;
GRANT ALL ON FUNCTION public.current_user_has_role(check_role text) TO anon;


--
-- Name: FUNCTION current_user_in_recovery_hold(); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.current_user_in_recovery_hold() TO authenticated;


--
-- Name: FUNCTION current_user_is_staff(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.current_user_is_staff() FROM PUBLIC;
GRANT ALL ON FUNCTION public.current_user_is_staff() TO authenticated;
GRANT ALL ON FUNCTION public.current_user_is_staff() TO anon;


--
-- Name: FUNCTION current_user_module_access(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.current_user_module_access() FROM PUBLIC;
GRANT ALL ON FUNCTION public.current_user_module_access() TO authenticated;
GRANT ALL ON FUNCTION public.current_user_module_access() TO anon;


--
-- Name: FUNCTION current_user_registered_for(p_training_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.current_user_registered_for(p_training_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.current_user_registered_for(p_training_id uuid) TO authenticated;


--
-- Name: FUNCTION current_user_role_codes(); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.current_user_role_codes() TO authenticated;


--
-- Name: FUNCTION decide_fee_refund(p_refund_id uuid, p_decision text, p_rejection_reason text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.decide_fee_refund(p_refund_id uuid, p_decision text, p_rejection_reason text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.decide_fee_refund(p_refund_id uuid, p_decision text, p_rejection_reason text) TO authenticated;


--
-- Name: FUNCTION decide_payment_transaction(p_transaction_id uuid, p_decision text, p_rejection_reason text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.decide_payment_transaction(p_transaction_id uuid, p_decision text, p_rejection_reason text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.decide_payment_transaction(p_transaction_id uuid, p_decision text, p_rejection_reason text) TO authenticated;


--
-- Name: FUNCTION decide_training_academic_plan(p_plan_id uuid, p_decision text, p_note text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.decide_training_academic_plan(p_plan_id uuid, p_decision text, p_note text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.decide_training_academic_plan(p_plan_id uuid, p_decision text, p_note text) TO authenticated;


--
-- Name: FUNCTION decide_training_completion(p_registration_id uuid, p_decision text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.decide_training_completion(p_registration_id uuid, p_decision text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.decide_training_completion(p_registration_id uuid, p_decision text) TO authenticated;


--
-- Name: FUNCTION decide_training_final_grade(p_registration_id uuid, p_decision text, p_note text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.decide_training_final_grade(p_registration_id uuid, p_decision text, p_note text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.decide_training_final_grade(p_registration_id uuid, p_decision text, p_note text) TO authenticated;


--
-- Name: FUNCTION decide_training_registration(p_registration_id uuid, p_reason text, p_override boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.decide_training_registration(p_registration_id uuid, p_reason text, p_override boolean) FROM PUBLIC;
GRANT ALL ON FUNCTION public.decide_training_registration(p_registration_id uuid, p_reason text, p_override boolean) TO authenticated;


--
-- Name: FUNCTION enforce_grade_only_submission(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.enforce_grade_only_submission() FROM PUBLIC;


--
-- Name: FUNCTION enforce_training_assessment_grade(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.enforce_training_assessment_grade() FROM PUBLIC;


--
-- Name: FUNCTION enforce_training_system_identity(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.enforce_training_system_identity() FROM PUBLIC;


--
-- Name: FUNCTION enforce_training_task_link(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.enforce_training_task_link() FROM PUBLIC;


--
-- Name: FUNCTION expire_due_training_quiz_attempts(p_limit integer); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.expire_due_training_quiz_attempts(p_limit integer) FROM PUBLIC;
GRANT ALL ON FUNCTION public.expire_due_training_quiz_attempts(p_limit integer) TO service_role;


--
-- Name: FUNCTION expire_waitlist_offers(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.expire_waitlist_offers() FROM PUBLIC;
GRANT ALL ON FUNCTION public.expire_waitlist_offers() TO service_role;


--
-- Name: FUNCTION finance_request_training_access_exception(p_training_registration_id uuid, p_reason text, p_expires_on date); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.finance_request_training_access_exception(p_training_registration_id uuid, p_reason text, p_expires_on date) FROM PUBLIC;
GRANT ALL ON FUNCTION public.finance_request_training_access_exception(p_training_registration_id uuid, p_reason text, p_expires_on date) TO authenticated;


--
-- Name: FUNCTION log_own_mfa_event(p_event_type text); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.log_own_mfa_event(p_event_type text) TO authenticated;


--
-- Name: FUNCTION log_training_assessment_grade(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.log_training_assessment_grade() FROM PUBLIC;


--
-- Name: FUNCTION log_training_task_mark(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.log_training_task_mark() FROM PUBLIC;


--
-- Name: FUNCTION mark_training_quiz_answer(p_attempt_id uuid, p_question_id uuid, p_points numeric, p_feedback text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.mark_training_quiz_answer(p_attempt_id uuid, p_question_id uuid, p_points numeric, p_feedback text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.mark_training_quiz_answer(p_attempt_id uuid, p_question_id uuid, p_points numeric, p_feedback text) TO authenticated;


--
-- Name: FUNCTION my_waitlist_position(p_registration_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.my_waitlist_position(p_registration_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.my_waitlist_position(p_registration_id uuid) TO authenticated;


--
-- Name: FUNCTION override_training_quiz_grade(p_quiz_id uuid, p_registration_id uuid, p_score_percent numeric, p_reason text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.override_training_quiz_grade(p_quiz_id uuid, p_registration_id uuid, p_score_percent numeric, p_reason text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.override_training_quiz_grade(p_quiz_id uuid, p_registration_id uuid, p_score_percent numeric, p_reason text) TO authenticated;


--
-- Name: FUNCTION override_training_task_assessment_grade(p_assessment_id uuid, p_registration_id uuid, p_score_percent numeric, p_reason text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.override_training_task_assessment_grade(p_assessment_id uuid, p_registration_id uuid, p_score_percent numeric, p_reason text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.override_training_task_assessment_grade(p_assessment_id uuid, p_registration_id uuid, p_score_percent numeric, p_reason text) TO authenticated;


--
-- Name: FUNCTION prevent_history_change(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.prevent_history_change() FROM PUBLIC;


--
-- Name: FUNCTION prevent_linked_training_grade_delete(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.prevent_linked_training_grade_delete() FROM PUBLIC;


--
-- Name: FUNCTION prevent_marked_task_delete(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.prevent_marked_task_delete() FROM PUBLIC;


--
-- Name: FUNCTION promote_next_waitlist_entry(p_training_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.promote_next_waitlist_entry(p_training_id uuid) FROM PUBLIC;


--
-- Name: FUNCTION record_prerequisite_decision(p_training_registration_id uuid, p_prerequisite_id uuid, p_decision_code text, p_recommendation_text text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.record_prerequisite_decision(p_training_registration_id uuid, p_prerequisite_id uuid, p_decision_code text, p_recommendation_text text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.record_prerequisite_decision(p_training_registration_id uuid, p_prerequisite_id uuid, p_decision_code text, p_recommendation_text text) TO authenticated;


--
-- Name: FUNCTION record_training_task_mark(p_assignment_id uuid, p_registration_id uuid, p_status text, p_marks numeric, p_reason text, p_feedback text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.record_training_task_mark(p_assignment_id uuid, p_registration_id uuid, p_status text, p_marks numeric, p_reason text, p_feedback text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.record_training_task_mark(p_assignment_id uuid, p_registration_id uuid, p_status text, p_marks numeric, p_reason text, p_feedback text) TO authenticated;


--
-- Name: FUNCTION refresh_training_slug_from_english_title(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.refresh_training_slug_from_english_title() FROM PUBLIC;


--
-- Name: FUNCTION registration_ineligibility_reason(p_training_id uuid, p_email text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.registration_ineligibility_reason(p_training_id uuid, p_email text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.registration_ineligibility_reason(p_training_id uuid, p_email text) TO authenticated;


--
-- Name: FUNCTION reject_training_registration(p_registration_id uuid, p_reason text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.reject_training_registration(p_registration_id uuid, p_reason text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.reject_training_registration(p_registration_id uuid, p_reason text) TO authenticated;


--
-- Name: FUNCTION request_training_publication(p_training_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.request_training_publication(p_training_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.request_training_publication(p_training_id uuid) TO authenticated;


--
-- Name: FUNCTION review_fee_proof_submission(p_submission_id uuid, p_decision text, p_note text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.review_fee_proof_submission(p_submission_id uuid, p_decision text, p_note text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.review_fee_proof_submission(p_submission_id uuid, p_decision text, p_note text) TO authenticated;


--
-- Name: FUNCTION review_prerequisite_evidence(p_evidence_id uuid, p_status_code text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.review_prerequisite_evidence(p_evidence_id uuid, p_status_code text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.review_prerequisite_evidence(p_evidence_id uuid, p_status_code text) TO authenticated;


--
-- Name: FUNCTION revoke_certificate(p_certificate_id uuid, p_reason text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.revoke_certificate(p_certificate_id uuid, p_reason text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.revoke_certificate(p_certificate_id uuid, p_reason text) TO authenticated;


--
-- Name: FUNCTION revoke_training_access_exception(p_exception_id uuid, p_reason text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.revoke_training_access_exception(p_exception_id uuid, p_reason text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.revoke_training_access_exception(p_exception_id uuid, p_reason text) TO authenticated;


--
-- Name: FUNCTION save_training_quiz_answer(p_attempt_id uuid, p_question_id uuid, p_response jsonb); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.save_training_quiz_answer(p_attempt_id uuid, p_question_id uuid, p_response jsonb) FROM PUBLIC;
GRANT ALL ON FUNCTION public.save_training_quiz_answer(p_attempt_id uuid, p_question_id uuid, p_response jsonb) TO authenticated;


--
-- Name: FUNCTION start_training_quiz_attempt(p_quiz_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.start_training_quiz_attempt(p_quiz_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.start_training_quiz_attempt(p_quiz_id uuid) TO authenticated;


--
-- Name: FUNCTION submit_prerequisite_evidence(p_training_registration_id uuid, p_prerequisite_id uuid, p_evidence_type text, p_evidence_url text, p_evidence_note text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.submit_prerequisite_evidence(p_training_registration_id uuid, p_prerequisite_id uuid, p_evidence_type text, p_evidence_url text, p_evidence_note text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.submit_prerequisite_evidence(p_training_registration_id uuid, p_prerequisite_id uuid, p_evidence_type text, p_evidence_url text, p_evidence_note text) TO authenticated;


--
-- Name: FUNCTION submit_training_final_grade(p_registration_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.submit_training_final_grade(p_registration_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.submit_training_final_grade(p_registration_id uuid) TO authenticated;


--
-- Name: FUNCTION submit_training_quiz_attempt(p_attempt_id uuid, p_auto_submit boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.submit_training_quiz_attempt(p_attempt_id uuid, p_auto_submit boolean) FROM PUBLIC;
GRANT ALL ON FUNCTION public.submit_training_quiz_attempt(p_attempt_id uuid, p_auto_submit boolean) TO authenticated;


--
-- Name: FUNCTION submit_training_registration(p_training_id uuid, p_full_name text, p_email text, p_phone text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.submit_training_registration(p_training_id uuid, p_full_name text, p_email text, p_phone text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.submit_training_registration(p_training_id uuid, p_full_name text, p_email text, p_phone text) TO authenticated;
GRANT ALL ON FUNCTION public.submit_training_registration(p_training_id uuid, p_full_name text, p_email text, p_phone text) TO service_role;


--
-- Name: FUNCTION support_item_progress(p_support_item_id uuid); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.support_item_progress(p_support_item_id uuid) TO anon;
GRANT ALL ON FUNCTION public.support_item_progress(p_support_item_id uuid) TO authenticated;


--
-- Name: FUNCTION trainee_quiz_attempts(p_quiz_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.trainee_quiz_attempts(p_quiz_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.trainee_quiz_attempts(p_quiz_id uuid) TO authenticated;


--
-- Name: FUNCTION trainee_training_academic_plans(p_training_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.trainee_training_academic_plans(p_training_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.trainee_training_academic_plans(p_training_id uuid) TO authenticated;


--
-- Name: FUNCTION trainee_training_quizzes(p_training_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.trainee_training_quizzes(p_training_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.trainee_training_quizzes(p_training_id uuid) TO authenticated;


--
-- Name: FUNCTION trainer_get_trainee_profile(p_registration_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.trainer_get_trainee_profile(p_registration_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.trainer_get_trainee_profile(p_registration_id uuid) TO authenticated;


--
-- Name: FUNCTION training_assessment_is_task_linked(p_assessment_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.training_assessment_is_task_linked(p_assessment_id uuid) FROM PUBLIC;


--
-- Name: FUNCTION training_capacity_summary(p_training_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.training_capacity_summary(p_training_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.training_capacity_summary(p_training_id uuid) TO authenticated;


--
-- Name: FUNCTION training_certificate_final_grade_eligible(p_registration_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.training_certificate_final_grade_eligible(p_registration_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.training_certificate_final_grade_eligible(p_registration_id uuid) TO authenticated;


--
-- Name: FUNCTION training_completion_eligibility(p_registration_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.training_completion_eligibility(p_registration_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.training_completion_eligibility(p_registration_id uuid) TO authenticated;


--
-- Name: FUNCTION training_decide_access_exception(p_exception_id uuid, p_decision text, p_note text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.training_decide_access_exception(p_exception_id uuid, p_decision text, p_note text) FROM PUBLIC;
GRANT ALL ON FUNCTION public.training_decide_access_exception(p_exception_id uuid, p_decision text, p_note text) TO authenticated;


--
-- Name: FUNCTION training_final_grade_after_return(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.training_final_grade_after_return() FROM PUBLIC;


--
-- Name: FUNCTION training_pending_access_exceptions(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.training_pending_access_exceptions() FROM PUBLIC;
GRANT ALL ON FUNCTION public.training_pending_access_exceptions() TO authenticated;


--
-- Name: FUNCTION training_quiz_attempt_questions(p_attempt_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.training_quiz_attempt_questions(p_attempt_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.training_quiz_attempt_questions(p_attempt_id uuid) TO authenticated;


--
-- Name: FUNCTION training_quiz_attempt_score(p_attempt_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.training_quiz_attempt_score(p_attempt_id uuid) FROM PUBLIC;


--
-- Name: FUNCTION training_quiz_export_best(p_quiz_id uuid, p_registration_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.training_quiz_export_best(p_quiz_id uuid, p_registration_id uuid) FROM PUBLIC;


--
-- Name: FUNCTION training_quiz_finish_attempt(p_attempt_id uuid, p_expired boolean); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.training_quiz_finish_attempt(p_attempt_id uuid, p_expired boolean) FROM PUBLIC;


--
-- Name: FUNCTION training_quiz_rescore_attempt(p_attempt_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.training_quiz_rescore_attempt(p_attempt_id uuid) FROM PUBLIC;


--
-- Name: FUNCTION training_quiz_results_released(p_quiz_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.training_quiz_results_released(p_quiz_id uuid) FROM PUBLIC;


--
-- Name: FUNCTION training_quiz_staff_check(p_quiz_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.training_quiz_staff_check(p_quiz_id uuid) FROM PUBLIC;


--
-- Name: FUNCTION training_registration_prerequisites_met(p_training_registration_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.training_registration_prerequisites_met(p_training_registration_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.training_registration_prerequisites_met(p_training_registration_id uuid) TO authenticated;


--
-- Name: FUNCTION training_task_after_change(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.training_task_after_change() FROM PUBLIC;


--
-- Name: FUNCTION training_task_export_all(p_assessment_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.training_task_export_all(p_assessment_id uuid) FROM PUBLIC;


--
-- Name: FUNCTION training_task_export_assessment(p_assessment_id uuid, p_registration_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.training_task_export_assessment(p_assessment_id uuid, p_registration_id uuid) FROM PUBLIC;


--
-- Name: FUNCTION training_task_export_registration(p_registration_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.training_task_export_registration(p_registration_id uuid) FROM PUBLIC;


--
-- Name: FUNCTION user_in_recovery_hold(p_user_id uuid); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.user_in_recovery_hold(p_user_id uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION public.user_in_recovery_hold(p_user_id uuid) TO authenticated;


--
-- Name: FUNCTION verify_certificate(p_verification_token uuid); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.verify_certificate(p_verification_token uuid) TO anon;
GRANT ALL ON FUNCTION public.verify_certificate(p_verification_token uuid) TO authenticated;


--
-- Name: TABLE finance_payment_queue; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.finance_payment_queue TO authenticated;


--
-- Name: TABLE public_founders_directory; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.public_founders_directory TO anon;
GRANT SELECT ON TABLE public.public_founders_directory TO authenticated;


--
-- Name: TABLE public_trainers_directory; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.public_trainers_directory TO anon;
GRANT SELECT ON TABLE public.public_trainers_directory TO authenticated;


--
-- Name: TABLE public_volunteers_directory; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.public_volunteers_directory TO anon;
GRANT SELECT ON TABLE public.public_volunteers_directory TO authenticated;


--
-- Name: TABLE training_attendance; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.training_attendance TO authenticated;


--
-- Name: TABLE training_feedback; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,UPDATE ON TABLE public.training_feedback TO authenticated;


--
-- Name: TABLE training_materials; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.training_materials TO authenticated;


--
-- Name: TABLE training_prerequisite_decisions; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.training_prerequisite_decisions TO authenticated;


--
-- Name: TABLE training_prerequisite_evidence; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.training_prerequisite_evidence TO authenticated;


--
-- Name: TABLE training_prerequisites; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,UPDATE ON TABLE public.training_prerequisites TO authenticated;


--
-- Name: TABLE training_registration_clearance; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.training_registration_clearance TO authenticated;


--
-- Name: TABLE training_registration_status_history; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.training_registration_status_history TO authenticated;


--
-- Name: TABLE training_sessions; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.training_sessions TO authenticated;


--
-- Name: TABLE training_waitlist_entries; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.training_waitlist_entries TO authenticated;


--
-- PostgreSQL database dump complete
--



grant usage on schema public to anon,authenticated,service_role;
grant select on table public.app_modules to anon;
grant select,insert,update,delete on table public.app_modules to authenticated;
grant select on table public.assessment_instruments to anon;
grant select,insert,update,delete on table public.assessment_instruments to authenticated;
grant select on table public.assessment_scores to anon;
grant select,insert,update,delete on table public.assessment_scores to authenticated;
grant select on table public.assessment_sessions to anon;
grant select,insert,update,delete on table public.assessment_sessions to authenticated;
grant select on table public.assignments to anon;
grant select,insert,update,delete on table public.assignments to authenticated;
grant select on table public.audit_log to anon;
grant select,insert,update,delete on table public.audit_log to authenticated;
grant select on table public.cohorts to anon;
grant select,insert,update,delete on table public.cohorts to authenticated;
grant select on table public.consent_records to anon;
grant select,insert,update,delete on table public.consent_records to authenticated;
grant select on table public.contact_submissions to anon;
grant select,insert,update,delete on table public.contact_submissions to authenticated;
grant select on table public.currencies to anon;
grant select,insert,update,delete on table public.currencies to authenticated;
grant select on table public.data_quality_assessments to anon;
grant select,insert,update,delete on table public.data_quality_assessments to authenticated;
grant select on table public.donation_allocations to anon;
grant select,insert,update,delete on table public.donation_allocations to authenticated;
grant select on table public.donation_frequencies to anon;
grant select,insert,update,delete on table public.donation_frequencies to authenticated;
grant select on table public.donation_intents to anon;
grant select,insert,update,delete on table public.donation_intents to authenticated;
grant select on table public.donation_statuses to anon;
grant select,insert,update,delete on table public.donation_statuses to authenticated;
grant select on table public.donations to anon;
grant select,insert,update,delete on table public.donations to authenticated;
grant select on table public.evidence_artifacts to anon;
grant select,insert,update,delete on table public.evidence_artifacts to authenticated;
grant select on table public.fund_types to anon;
grant select,insert,update,delete on table public.fund_types to authenticated;
grant select on table public.funds to anon;
grant select,insert,update,delete on table public.funds to authenticated;
grant select on table public.governance_appointments to anon;
grant select,insert,update,delete on table public.governance_appointments to authenticated;
grant select on table public.governance_roles to anon;
grant select,insert,update,delete on table public.governance_roles to authenticated;
grant select on table public.indicator_baselines to anon;
grant select,insert,update,delete on table public.indicator_baselines to authenticated;
grant select on table public.indicator_definitions to anon;
grant select,insert,update,delete on table public.indicator_definitions to authenticated;
grant select on table public.indicator_disaggregations to anon;
grant select,insert,update,delete on table public.indicator_disaggregations to authenticated;
grant select on table public.indicator_observations to anon;
grant select,insert,update,delete on table public.indicator_observations to authenticated;
grant select on table public.indicator_scopes to anon;
grant select,insert,update,delete on table public.indicator_scopes to authenticated;
grant select on table public.indicator_targets to anon;
grant select,insert,update,delete on table public.indicator_targets to authenticated;
grant select on table public.indicator_translations to anon;
grant select,insert,update,delete on table public.indicator_translations to authenticated;
grant select on table public.indicator_versions to anon;
grant select,insert,update,delete on table public.indicator_versions to authenticated;
grant select on table public.initiative_program_links to anon;
grant select,insert,update,delete on table public.initiative_program_links to authenticated;
grant select on table public.initiative_translations to anon;
grant select,insert,update,delete on table public.initiative_translations to authenticated;
grant select on table public.initiatives to anon;
grant select,insert,update,delete on table public.initiatives to authenticated;
grant select on table public.instrument_versions to anon;
grant select,insert,update,delete on table public.instrument_versions to authenticated;
grant select on table public.internal_notes to anon;
grant select,insert,update,delete on table public.internal_notes to authenticated;
grant select on table public.learning_actions to anon;
grant select,insert,update,delete on table public.learning_actions to authenticated;
grant select on table public.measurement_plans to anon;
grant select,insert,update,delete on table public.measurement_plans to authenticated;
grant select on table public.media_assets to anon;
grant select,insert,update,delete on table public.media_assets to authenticated;
grant select on table public.membership_events to anon;
grant select,insert,update,delete on table public.membership_events to authenticated;
grant select on table public.membership_statuses to anon;
grant select,insert,update,delete on table public.membership_statuses to authenticated;
grant select on table public.membership_types to anon;
grant select,insert,update,delete on table public.membership_types to authenticated;
grant select on table public.memberships to anon;
grant select,insert,update,delete on table public.memberships to authenticated;
grant select on table public.observation_breakdowns to anon;
grant select,insert,update,delete on table public.observation_breakdowns to authenticated;
grant select on table public.observation_rubrics to anon;
grant select,insert,update,delete on table public.observation_rubrics to authenticated;
grant select on table public.organization_types to anon;
grant select,insert,update,delete on table public.organization_types to authenticated;
grant select on table public.organizations to anon;
grant select,insert,update,delete on table public.organizations to authenticated;
grant select on table public.partner_relationships to anon;
grant select,insert,update,delete on table public.partner_relationships to authenticated;
grant select on table public.partner_roles to anon;
grant select,insert,update,delete on table public.partner_roles to authenticated;
grant select on table public.partnership_inquiries to anon;
grant select,insert,update,delete on table public.partnership_inquiries to authenticated;
grant select on table public.payment_customers to anon;
grant select,insert,update,delete on table public.payment_customers to authenticated;
grant select on table public.payment_events to anon;
grant select,insert,update,delete on table public.payment_events to authenticated;
grant select on table public.payment_providers to anon;
grant select,insert,update,delete on table public.payment_providers to authenticated;
grant select on table public.payment_records to anon;
grant select,insert,update,delete on table public.payment_records to authenticated;
grant select on table public.payment_transaction_statuses to anon;
grant select,insert,update,delete on table public.payment_transaction_statuses to authenticated;
grant select on table public.payment_transactions to anon;
grant select,insert,update,delete on table public.payment_transactions to authenticated;
grant select on table public.people to anon;
grant select,insert,update,delete on table public.people to authenticated;
grant select on table public.people_translations to anon;
grant select,insert,update,delete on table public.people_translations to authenticated;
grant select on table public.permissions to anon;
grant select,insert,update,delete on table public.permissions to authenticated;
grant select on table public.person_accessibility_requests to anon;
grant select,insert,update,delete on table public.person_accessibility_requests to authenticated;
grant select on table public.person_consent_records to anon;
grant select,insert,update,delete on table public.person_consent_records to authenticated;
grant select on table public.person_emergency_contacts to anon;
grant select,insert,update,delete on table public.person_emergency_contacts to authenticated;
grant select on table public.person_guardian_relationships to anon;
grant select,insert,update,delete on table public.person_guardian_relationships to authenticated;
grant select on table public.professional_credentials to anon;
grant select,insert,update,delete on table public.professional_credentials to authenticated;
grant select on table public.profile_documents to anon;
grant select,insert,update,delete on table public.profile_documents to authenticated;
grant select on table public.program_activities to anon;
grant select,insert,update,delete on table public.program_activities to authenticated;
grant select on table public.program_cycles to anon;
grant select,insert,update,delete on table public.program_cycles to authenticated;
grant select on table public.program_indicators to anon;
grant select,insert,update,delete on table public.program_indicators to authenticated;
grant select on table public.program_statuses to anon;
grant select,insert,update,delete on table public.program_statuses to authenticated;
grant select on table public.program_translations to anon;
grant select,insert,update,delete on table public.program_translations to authenticated;
grant select on table public.programs to anon;
grant select,insert,update,delete on table public.programs to authenticated;
grant select on table public.publication_approvals to anon;
grant select,insert,update,delete on table public.publication_approvals to authenticated;
grant select on table public.publication_snapshots to anon;
grant select,insert,update,delete on table public.publication_snapshots to authenticated;
grant select on table public.publication_statuses to anon;
grant select,insert,update,delete on table public.publication_statuses to authenticated;
grant select on table public.receipt_deliveries to anon;
grant select,insert,update,delete on table public.receipt_deliveries to authenticated;
grant select on table public.receipt_delivery_statuses to anon;
grant select,insert,update,delete on table public.receipt_delivery_statuses to authenticated;
grant select on table public.receipts to anon;
grant select,insert,update,delete on table public.receipts to authenticated;
grant select on table public.recurring_agreements to anon;
grant select,insert,update,delete on table public.recurring_agreements to authenticated;
grant select on table public.refunds to anon;
grant select,insert,update,delete on table public.refunds to authenticated;
grant select on table public.reporting_periods to anon;
grant select,insert,update,delete on table public.reporting_periods to authenticated;
grant select on table public.resource_translations to anon;
grant select,insert,update,delete on table public.resource_translations to authenticated;
grant select on table public.resources to anon;
grant select,insert,update,delete on table public.resources to authenticated;
grant select on table public.result_levels to anon;
grant select,insert,update,delete on table public.result_levels to authenticated;
grant select on table public.result_links to anon;
grant select,insert,update,delete on table public.result_links to authenticated;
grant select on table public.result_node_translations to anon;
grant select,insert,update,delete on table public.result_node_translations to authenticated;
grant select on table public.result_nodes to anon;
grant select,insert,update,delete on table public.result_nodes to authenticated;
grant select on table public.role_permissions to anon;
grant select,insert,update,delete on table public.role_permissions to authenticated;
grant select on table public.roles to anon;
grant select,insert,update,delete on table public.roles to authenticated;
grant select on table public.security_events to anon;
grant select,insert,update,delete on table public.security_events to authenticated;
grant select on table public.sites to anon;
grant select,insert,update,delete on table public.sites to authenticated;
grant select on table public.submission_status_history to anon;
grant select,insert,update,delete on table public.submission_status_history to authenticated;
grant select on table public.submission_statuses to anon;
grant select,insert,update,delete on table public.submission_statuses to authenticated;
grant select on table public.support_item_fulfillments to anon;
grant select,insert,update,delete on table public.support_item_fulfillments to authenticated;
grant select on table public.support_item_translations to anon;
grant select,insert,update,delete on table public.support_item_translations to authenticated;
grant select on table public.support_items to anon;
grant select,insert,update,delete on table public.support_items to authenticated;
grant select on table public.survey_responses to anon;
grant select,insert,update,delete on table public.survey_responses to authenticated;
grant select on table public.theories_of_change to anon;
grant select,insert,update,delete on table public.theories_of_change to authenticated;
grant select on table public.trainer_application_snapshots to anon;
grant select,insert,update,delete on table public.trainer_application_snapshots to authenticated;
grant select on table public.trainers to anon;
grant select,insert,update,delete on table public.trainers to authenticated;
grant select on table public.training_academic_plans to anon;
grant select,insert,update,delete on table public.training_academic_plans to authenticated;
grant select on table public.training_assessment_grade_history to anon;
grant select,insert,update,delete on table public.training_assessment_grade_history to authenticated;
grant select on table public.training_assessment_grades to anon;
grant select,insert,update,delete on table public.training_assessment_grades to authenticated;
grant select on table public.training_assessments to anon;
grant select,insert,update,delete on table public.training_assessments to authenticated;
grant select on table public.training_assignments to anon;
grant select,insert,update,delete on table public.training_assignments to authenticated;
grant select on table public.training_attendance to anon;
grant select,insert,update,delete on table public.training_attendance to authenticated;
grant select on table public.training_certificate_reissue_authorizations to anon;
grant select,insert,update,delete on table public.training_certificate_reissue_authorizations to authenticated;
grant select on table public.training_certificates to anon;
grant select,insert,update,delete on table public.training_certificates to authenticated;
grant select on table public.training_charges to anon;
grant select,insert,update,delete on table public.training_charges to authenticated;
grant select on table public.training_completion_rules to anon;
grant select,insert,update,delete on table public.training_completion_rules to authenticated;
grant select on table public.training_fee_access_exceptions to anon;
grant select,insert,update,delete on table public.training_fee_access_exceptions to authenticated;
grant select on table public.training_fee_proof_submissions to anon;
grant select,insert,update,delete on table public.training_fee_proof_submissions to authenticated;
grant select on table public.training_fee_refunds to anon;
grant select,insert,update,delete on table public.training_fee_refunds to authenticated;
grant select on table public.training_fee_transactions to anon;
grant select,insert,update,delete on table public.training_fee_transactions to authenticated;
grant select on table public.training_feedback to anon;
grant select,insert,update,delete on table public.training_feedback to authenticated;
grant select on table public.training_final_grades to anon;
grant select,insert,update,delete on table public.training_final_grades to authenticated;
grant select on table public.training_materials to anon;
grant select,insert,update,delete on table public.training_materials to authenticated;
grant select on table public.training_prerequisite_decisions to anon;
grant select,insert,update,delete on table public.training_prerequisite_decisions to authenticated;
grant select on table public.training_prerequisite_evidence to anon;
grant select,insert,update,delete on table public.training_prerequisite_evidence to authenticated;
grant select on table public.training_prerequisites to anon;
grant select,insert,update,delete on table public.training_prerequisites to authenticated;
grant select on table public.training_question_bank_questions to anon;
grant select,insert,update,delete on table public.training_question_bank_questions to authenticated;
grant select on table public.training_question_banks to anon;
grant select,insert,update,delete on table public.training_question_banks to authenticated;
grant select on table public.training_quiz_accommodations to anon;
grant select,insert,update,delete on table public.training_quiz_accommodations to authenticated;
grant select on table public.training_quiz_answers to anon;
grant select,insert,update,delete on table public.training_quiz_answers to authenticated;
grant select on table public.training_quiz_attempts to anon;
grant select,insert,update,delete on table public.training_quiz_attempts to authenticated;
grant select on table public.training_quiz_grade_overrides to anon;
grant select,insert,update,delete on table public.training_quiz_grade_overrides to authenticated;
grant select on table public.training_quiz_question_adjustments to anon;
grant select,insert,update,delete on table public.training_quiz_question_adjustments to authenticated;
grant select on table public.training_quiz_questions to anon;
grant select,insert,update,delete on table public.training_quiz_questions to authenticated;
grant select on table public.training_quizzes to anon;
grant select,insert,update,delete on table public.training_quizzes to authenticated;
grant select on table public.training_registration_status_history to anon;
grant select,insert,update,delete on table public.training_registration_status_history to authenticated;
grant select on table public.training_registrations to anon;
grant select,insert,update,delete on table public.training_registrations to authenticated;
grant select on table public.training_sessions to anon;
grant select,insert,update,delete on table public.training_sessions to authenticated;
grant select on table public.training_submissions to anon;
grant select,insert,update,delete on table public.training_submissions to authenticated;
grant select on table public.training_task_assessment_overrides to anon;
grant select,insert,update,delete on table public.training_task_assessment_overrides to authenticated;
grant select on table public.training_task_mark_history to anon;
grant select,insert,update,delete on table public.training_task_mark_history to authenticated;
grant select on table public.training_task_marks to anon;
grant select,insert,update,delete on table public.training_task_marks to authenticated;
grant select on table public.training_translations to anon;
grant select,insert,update,delete on table public.training_translations to authenticated;
grant select on table public.training_waitlist_entries to anon;
grant select,insert,update,delete on table public.training_waitlist_entries to authenticated;
grant select on table public.trainings to anon;
grant select,insert,update,delete on table public.trainings to authenticated;
grant select on table public.user_invitations to anon;
grant select,insert,update,delete on table public.user_invitations to authenticated;
grant select on table public.user_profiles to anon;
grant select,insert,update,delete on table public.user_profiles to authenticated;
grant select on table public.user_role_assignments to anon;
grant select,insert,update,delete on table public.user_role_assignments to authenticated;
grant select on table public.verification_reviews to anon;
grant select,insert,update,delete on table public.verification_reviews to authenticated;
grant select on table public.verification_statuses to anon;
grant select,insert,update,delete on table public.verification_statuses to authenticated;
grant select on table public.volunteer_applications to anon;
grant select,insert,update,delete on table public.volunteer_applications to authenticated;
grant all on all tables in schema public,restricted to service_role;
grant usage on schema restricted to service_role;
grant usage,select on all sequences in schema public to authenticated,service_role;
revoke all on schema restricted from anon,authenticated;

set check_function_bodies = true;
set row_security = on;
set search_path = public;
commit;
