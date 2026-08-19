-- ============================================================
-- THE ARCHIVE
-- DATABASE + ADMIN SECURITY + STORAGE
-- ============================================================

create extension if not exists pgcrypto;

-- ============================================================
-- ADMIN ALLOWLIST
-- ============================================================

create table if not exists public.ebook_admins (
    user_id uuid primary key
        references auth.users(id)
        on delete cascade,

    created_at timestamptz not null default now()
);

-- ============================================================
-- PAGES
-- ============================================================

create table if not exists public.ebook_pages (
    id uuid primary key default gen_random_uuid(),

    title text not null default '',

    image_path text not null unique,

    image_url text not null,

    page_order integer not null default 1000,

    published boolean not null default false,

    created_at timestamptz not null default now(),

    updated_at timestamptz not null default now()
);

create index if not exists
ebook_pages_order_idx
on public.ebook_pages(page_order);

create index if not exists
ebook_pages_published_order_idx
on public.ebook_pages(published, page_order);

-- ============================================================
-- UPDATED AT
-- ============================================================

create or replace function public.ebook_touch_updated_at()
returns trigger
language plpgsql
security invoker
as $$
begin
    new.updated_at = now();
    return new;
end;
$$;

drop trigger if exists
ebook_pages_updated_at
on public.ebook_pages;

create trigger
ebook_pages_updated_at
before update on public.ebook_pages
for each row
execute function public.ebook_touch_updated_at();

-- ============================================================
-- ADMIN CHECK
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
-- RLS
-- ============================================================

alter table public.ebook_admins enable row level security;
alter table public.ebook_pages enable row level security;

-- ============================================================
-- ADMIN TABLE
-- ============================================================

drop policy if exists
admin_read_own_record
on public.ebook_admins;

create policy
admin_read_own_record
on public.ebook_admins
for select
to authenticated
using (
    user_id = auth.uid()
);

-- ============================================================
-- PUBLIC READ PUBLISHED PAGES
-- ============================================================

drop policy if exists
public_read_published_pages
on public.ebook_pages;

create policy
public_read_published_pages
on public.ebook_pages
for select
to anon
using (
    published = true
);

-- ============================================================
-- ADMIN READ
-- ============================================================

drop policy if exists
admin_read_all_pages
on public.ebook_pages;

create policy
admin_read_all_pages
on public.ebook_pages
for select
to authenticated
using (
    public.is_ebook_admin()
);

-- ============================================================
-- ADMIN INSERT
-- ============================================================

drop policy if exists
admin_insert_pages
on public.ebook_pages;

create policy
admin_insert_pages
on public.ebook_pages
for insert
to authenticated
with check (
    public.is_ebook_admin()
);

-- ============================================================
-- ADMIN UPDATE
-- ============================================================

drop policy if exists
admin_update_pages
on public.ebook_pages;

create policy
admin_update_pages
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
-- ADMIN DELETE
-- ============================================================

drop policy if exists
admin_delete_pages
on public.ebook_pages;

create policy
admin_delete_pages
on public.ebook_pages
for delete
to authenticated
using (
    public.is_ebook_admin()
);

-- ============================================================
-- DATA API GRANTS
-- ============================================================

grant select
on public.ebook_pages
to anon;

grant select, insert, update, delete
on public.ebook_pages
to authenticated;

grant select
on public.ebook_admins
to authenticated;

-- ============================================================
-- STORAGE BUCKET
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
-- PUBLIC IMAGE READ
-- ============================================================

drop policy if exists
public_read_ebook_images
on storage.objects;

create policy
public_read_ebook_images
on storage.objects
for select
to public
using (
    bucket_id = 'ebook-images'
);

-- ============================================================
-- ADMIN UPLOAD
-- ============================================================

drop policy if exists
admin_upload_ebook_images
on storage.objects;

create policy
admin_upload_ebook_images
on storage.objects
for insert
to authenticated
with check (
    bucket_id = 'ebook-images'
    and public.is_ebook_admin()
);

-- ============================================================
-- ADMIN UPDATE
-- ============================================================

drop policy if exists
admin_update_ebook_images
on storage.objects;

create policy
admin_update_ebook_images
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
-- ADMIN DELETE
-- ============================================================

drop policy if exists
admin_delete_ebook_images
on storage.objects;

create policy
admin_delete_ebook_images
on storage.objects
for delete
to authenticated
using (
    bucket_id = 'ebook-images'
    and public.is_ebook_admin()
);
