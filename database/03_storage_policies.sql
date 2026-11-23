-- Policies only: create the named buckets manually as described in DEPLOYMENT.md.
begin;
set local search_path = public, storage;
create policy "engagement_read_volunteer_cvs" on storage.objects for SELECT to public using (((bucket_id = 'volunteer-cvs'::text) AND current_user_has_permission('intake.read'::text)));
create policy "finance_manage_fee_proofs" on storage.objects for ALL to public using (((bucket_id = 'training-fee-proofs'::text) AND (current_user_has_permission('finance.read'::text) OR current_user_has_permission('finance.manage'::text)))) with check (((bucket_id = 'training-fee-proofs'::text) AND current_user_has_permission('finance.manage'::text)));
create policy "finance_read_receipts" on storage.objects for SELECT to public using (((bucket_id = 'training-receipts'::text) AND (current_user_has_permission('finance.read'::text) OR current_user_has_permission('finance.manage'::text))));
create policy "trainee_read_own_fee_proof" on storage.objects for SELECT to public using (((bucket_id = 'training-fee-proofs'::text) AND (EXISTS ( SELECT 1
   FROM training_charges c
  WHERE (((c.id)::text = (storage.foldername(objects.name))[1]) AND current_user_owns_training_registration(c.training_registration_id))))));
create policy "trainee_submit_fee_proof" on storage.objects for INSERT to public with check (((bucket_id = 'training-fee-proofs'::text) AND (EXISTS ( SELECT 1
   FROM training_charges c
  WHERE (((c.id)::text = (storage.foldername(objects.name))[1]) AND current_user_owns_training_registration(c.training_registration_id))))));
create policy "trainer_documents_self_manage" on storage.objects for ALL to public using (((bucket_id = 'trainer-documents'::text) AND ((storage.foldername(name))[1] = (current_user_trainer_id())::text))) with check (((bucket_id = 'trainer-documents'::text) AND ((storage.foldername(name))[1] = (current_user_trainer_id())::text)));
create policy "trainer_documents_self_read_application" on storage.objects for SELECT to public using (((bucket_id = 'trainer-documents'::text) AND (EXISTS ( SELECT 1
   FROM trainers t
  WHERE ((t.person_id = current_person_id()) AND ((t.cv_storage_path = objects.name) OR (objects.name = ANY (t.certificate_storage_paths))))))));
create policy "trainer_photos_self_manage" on storage.objects for ALL to public using (((bucket_id = 'trainer-photos'::text) AND ((storage.foldername(name))[1] = (current_person_id())::text))) with check (((bucket_id = 'trainer-photos'::text) AND ((storage.foldername(name))[1] = (current_person_id())::text)));
create policy "training_materials_trainer_storage_manage" on storage.objects for ALL to public using (((bucket_id = 'training-materials'::text) AND ((storage.foldername(name))[1] ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'::text) AND current_user_is_trainer_for(((storage.foldername(name))[1])::uuid))) with check (((bucket_id = 'training-materials'::text) AND ((storage.foldername(name))[1] ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'::text) AND current_user_is_trainer_for(((storage.foldername(name))[1])::uuid)));
create policy "training_read_certificates" on storage.objects for SELECT to public using (((bucket_id = 'training-certificates'::text) AND current_user_has_permission('training.read'::text)));
create policy "training_read_trainer_documents" on storage.objects for SELECT to public using (((bucket_id = 'trainer-documents'::text) AND current_user_has_permission('training.read'::text)));
commit;
