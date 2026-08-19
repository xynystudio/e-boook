-- ============================================================
-- THE ARCHIVE
-- SUPABASE DATABASE + SECURITY
-- ============================================================

create extension if not exists pgcrypto;


-- ============================================================
-- 1. ADMIN TABLE
-- ============================================================

create table if not exists public.ebook_admins (
    user_id uuid primary key references auth.users(id) on delete cascade,
    created_at timestamptz not null default now()
);


-- ============================================================
-- 2. PAGE TABLE
-- ============================================================

create table if not exists public.ebook_pages (

    id uuid primary key default gen_random_uuid(),

    title text not null default '',

    image_path text not null unique,

    image_url text not null,

    page_order integer not null default 0,

    published boolean not null default true,

    created_at timestamptz not null default now(),

    updated_at timestamptz not null default now()
);


-- ============================================================
-- 3. INDEX
-- ============================================================

create index if not exists ebook_pages_order_idx
on public.ebook_pages(page_order);

create index if not exists ebook_pages_public_idx
on public.ebook_pages(published, page_order);


-- ============================================================
-- 4. UPDATED_AT
-- ============================================================

create or replace function public.ebook_set_updated_at()

returns trigger

language plpgsql

security invoker

as $$

begin

    new.updated_at = now();

    return new;

end;

$$;


drop trigger if exists ebook_pages_updated_at
on public.ebook_pages;


create trigger ebook_pages_updated_at

before update on public.ebook_pages

for each row

execute function public.ebook_set_updated_at();


-- ============================================================
-- 5. ADMIN CHECK FUNCTION
-- ============================================================

create or replace function public.is_ebook_admin()

returns boolean

language sql

stable

security definer

set search_path = public

as $$

    select exists (
        select 1
        from public.ebook_admins
        where user_id = auth.uid()
    );

$$;


revoke all
on function public.is_ebook_admin()
from public;


grant execute
on function public.is_ebook_admin()
to authenticated;


-- ============================================================
-- 6. ENABLE RLS
-- ============================================================

alter table public.ebook_admins
enable row level security;

alter table public.ebook_pages
enable row level security;


-- ============================================================
-- 7. ADMIN TABLE POLICIES
-- ============================================================

drop policy if exists
"admin_can_read_own_admin_record"
on public.ebook_admins;


create policy
"admin_can_read_own_admin_record"

on public.ebook_admins

for select

to authenticated

using (
    user_id = auth.uid()
);


-- ============================================================
-- 8. PUBLIC PAGE READ
-- ============================================================

drop policy if exists
"public_can_read_published_pages"
on public.ebook_pages;


create policy
"public_can_read_published_pages"

on public.ebook_pages

for select

to anon

using (
    published = true
);


-- ============================================================
-- 9. ADMIN PAGE READ
-- ============================================================

drop policy if exists
"admin_can_read_all_pages"
on public.ebook_pages;


create policy
"admin_can_read_all_pages"

on public.ebook_pages

for select

to authenticated

using (
    public.is_ebook_admin()
);


-- ============================================================
-- 10. ADMIN INSERT
-- ============================================================

drop policy if exists
"admin_can_insert_pages"
on public.ebook_pages;


create policy
"admin_can_insert_pages"

on public.ebook_pages

for insert

to authenticated

with check (
    public.is_ebook_admin()
);


-- ============================================================
-- 11. ADMIN UPDATE
-- ============================================================

drop policy if exists
"admin_can_update_pages"
on public.ebook_pages;


create policy
"admin_can_update_pages"

on public.ebook_pages

for update

to authenticated

using (
    public.is_ebook_admin()
)

with check (
    public.is_ebook_admin()
);


-- ============================================================
-- 12. ADMIN DELETE
-- ============================================================

drop policy if exists
"admin_can_delete_pages"
on public.ebook_pages;


create policy
"admin_can_delete_pages"

on public.ebook_pages

for delete

to authenticated

using (
    public.is_ebook_admin()
);


-- ============================================================
-- 13. GRANTS
-- ============================================================

grant select
on public.ebook_pages
to anon;

grant select, insert, update, delete
on public.ebook_pages
to authenticated;


-- ============================================================
-- 14. STORAGE BUCKET
-- ============================================================

insert into storage.buckets (
    id,
    name,
    public
)

values (
    'ebook-images',
    'ebook-images',
    true
)

on conflict (id)

do update set
    public = true;


-- ============================================================
-- 15. STORAGE PUBLIC READ
-- ============================================================

drop policy if exists
"public_can_read_ebook_images"
on storage.objects;


create policy
"public_can_read_ebook_images"

on storage.objects

for select

to public

using (
    bucket_id = 'ebook-images'
);


-- ============================================================
-- 16. STORAGE ADMIN INSERT
-- ============================================================

drop policy if exists
"admin_can_upload_ebook_images"
on storage.objects;


create policy
"admin_can_upload_ebook_images"

on storage.objects

for insert

to authenticated

with check (
    bucket_id = 'ebook-images'
    and public.is_ebook_admin()
);


-- ============================================================
-- 17. STORAGE ADMIN UPDATE
-- ============================================================

drop policy if exists
"admin_can_update_ebook_images"
on storage.objects;


create policy
"admin_can_update_ebook_images"

on storage.objects

for update

to authenticated

using (
    bucket_id = 'ebook-images'
    and public.is_ebook_admin()
)

with check (
    bucket_id = 'ebook-images'
    and public.is_ebook_admin()
);


-- ============================================================
-- 18. STORAGE ADMIN DELETE
-- ============================================================

drop policy if exists
"admin_can_delete_ebook_images"
on storage.objects;


create policy
"admin_can_delete_ebook_images"

on storage.objects

for delete

to authenticated

using (
    bucket_id = 'ebook-images'
    and public.is_ebook_admin()
);


-- ============================================================
-- END
-- ============================================================
