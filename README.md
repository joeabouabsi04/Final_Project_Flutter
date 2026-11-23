# UpSkills Learning – Mobile Programming Final Project (ULFG II, Semester 9)

## `database/` – Supabase deployment package

| File | What it does |
|---|---|
| `ULFG_II_Semester_9_Supabase_Deployment_Guide.pdf` | Instructor's deployment guide |
| `01_learning.sql` | Learning schema (public + restricted) |
| `02_accounting.sql` | Accounting schema |
| `03_storage_policies.sql` | Storage policies (buckets must be created manually) |
| `04_verify.sql` | Read-only verification checks |
| `05_summary_check.sql` | One-row summary of the checks (expect 142 / 6 / 17 / 0 / 0) |

## How to deploy (fresh Supabase project)

1. Create a new project at supabase.com/dashboard.
2. SQL Editor → run `01`, `02`, `03` in order (each once, new query each time).
3. Run `05_summary_check.sql` → expect **142 / 6 / 17 / 0 / 0**.
4. Storage → create buckets: `trainer-documents`, `volunteer-cvs`, `trainer-photos` (public), `training-certificates`, `training-fee-proofs`, `training-materials`, `training-receipts`.
5. Data API settings → Exposed schemas → add `accounting` (not `restricted`).

Do **not** add users or data before showing the empty-database check.
