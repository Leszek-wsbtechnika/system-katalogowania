-- === KATALOG CZĘŚCI — Supabase setup ===
-- Uruchom w: Supabase → SQL Editor
-- Idempotentny — można uruchamiać wielokrotnie.

-- 1. TABELE
CREATE TABLE IF NOT EXISTS parts (
  id          BIGSERIAL PRIMARY KEY,
  category    TEXT NOT NULL DEFAULT '',
  name        TEXT NOT NULL,
  price_net   NUMERIC,
  price_gross NUMERIC,
  description TEXT DEFAULT '',
  photo       TEXT,
  added_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS links (
  id          BIGSERIAL PRIMARY KEY,
  url         TEXT NOT NULL,
  name        TEXT NOT NULL,
  category    TEXT DEFAULT 'Ogólne',
  rating      INTEGER DEFAULT 0,
  description TEXT DEFAULT '',
  note        TEXT DEFAULT '',
  added_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS custom_cats (
  name TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS profiles (
  id    UUID REFERENCES auth.users(id) ON DELETE CASCADE PRIMARY KEY,
  email TEXT,
  role  TEXT NOT NULL DEFAULT 'nowy'
        CHECK (role IN ('nowy','editor','admin'))
);

CREATE TABLE IF NOT EXISTS allowed_emails (
  email TEXT PRIMARY KEY,
  added_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. STORAGE BUCKET (publiczny — zdjęcia dostępne przez URL)
INSERT INTO storage.buckets (id, name, public)
VALUES ('photos', 'photos', true)
ON CONFLICT DO NOTHING;

-- 3. AUTO-TWORZENIE PROFILU PO REJESTRACJI
-- Domyślna rola 'nowy' — admin musi ręcznie promować do 'editor'/'admin'.
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
BEGIN
  INSERT INTO public.profiles (id, email, role)
  VALUES (NEW.id, NEW.email, 'nowy')
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 4. HELPER: rola bieżącego użytkownika
CREATE OR REPLACE FUNCTION public.get_my_role()
RETURNS TEXT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
  SELECT role FROM public.profiles WHERE id = auth.uid();
$$;

-- 4b. HELPER: profile z emailami dla panelu admina (tylko admin)
CREATE OR REPLACE FUNCTION public.get_profiles_with_email()
RETURNS TABLE(id uuid, role text, email text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
BEGIN
  IF public.get_my_role() <> 'admin' THEN
    RAISE EXCEPTION 'forbidden' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
    SELECT p.id, p.role, COALESCE(p.email, u.email) AS email
    FROM public.profiles p
    JOIN auth.users u ON u.id = p.id
    ORDER BY u.email;
END;
$$;

-- 4c. RPC: usuwanie użytkowników (tylko admin, kaskaduje profiles przez FK)
CREATE OR REPLACE FUNCTION public.delete_users(user_ids uuid[])
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
BEGIN
  IF public.get_my_role() <> 'admin' THEN
    RAISE EXCEPTION 'forbidden' USING ERRCODE = '42501';
  END IF;
  IF auth.uid() = ANY(user_ids) THEN
    RAISE EXCEPTION 'cannot delete self' USING ERRCODE = '22023';
  END IF;
  DELETE FROM auth.users WHERE id = ANY(user_ids);
END;
$$;

REVOKE ALL ON FUNCTION public.delete_users(uuid[]) FROM public, anon;
GRANT EXECUTE ON FUNCTION public.delete_users(uuid[]) TO authenticated;

-- 5. RLS
ALTER TABLE parts          ENABLE ROW LEVEL SECURITY;
ALTER TABLE links          ENABLE ROW LEVEL SECURITY;
ALTER TABLE custom_cats    ENABLE ROW LEVEL SECURITY;
ALTER TABLE profiles       ENABLE ROW LEVEL SECURITY;
ALTER TABLE allowed_emails ENABLE ROW LEVEL SECURITY;

-- Parts
DROP POLICY IF EXISTS "read_parts"   ON parts;
DROP POLICY IF EXISTS "insert_parts" ON parts;
DROP POLICY IF EXISTS "update_parts" ON parts;
DROP POLICY IF EXISTS "delete_parts" ON parts;
CREATE POLICY "read_parts"   ON parts FOR SELECT TO authenticated USING (true);
CREATE POLICY "insert_parts" ON parts FOR INSERT TO authenticated WITH CHECK (get_my_role() IN ('nowy','editor','admin'));
CREATE POLICY "update_parts" ON parts FOR UPDATE TO authenticated USING (get_my_role() IN ('editor','admin')) WITH CHECK (get_my_role() IN ('editor','admin'));
CREATE POLICY "delete_parts" ON parts FOR DELETE TO authenticated USING (get_my_role() = 'admin');

-- Links
DROP POLICY IF EXISTS "read_links"   ON links;
DROP POLICY IF EXISTS "insert_links" ON links;
DROP POLICY IF EXISTS "update_links" ON links;
DROP POLICY IF EXISTS "delete_links" ON links;
CREATE POLICY "read_links"   ON links FOR SELECT TO authenticated USING (true);
CREATE POLICY "insert_links" ON links FOR INSERT TO authenticated WITH CHECK (get_my_role() IN ('nowy','editor','admin'));
CREATE POLICY "update_links" ON links FOR UPDATE TO authenticated USING (get_my_role() IN ('editor','admin')) WITH CHECK (get_my_role() IN ('editor','admin'));
CREATE POLICY "delete_links" ON links FOR DELETE TO authenticated USING (get_my_role() = 'admin');

-- Custom cats
DROP POLICY IF EXISTS "read_cats"   ON custom_cats;
DROP POLICY IF EXISTS "insert_cats" ON custom_cats;
DROP POLICY IF EXISTS "delete_cats" ON custom_cats;
CREATE POLICY "read_cats"   ON custom_cats FOR SELECT TO authenticated USING (true);
CREATE POLICY "insert_cats" ON custom_cats FOR INSERT TO authenticated WITH CHECK (get_my_role() IN ('editor','admin'));
CREATE POLICY "delete_cats" ON custom_cats FOR DELETE TO authenticated USING (get_my_role() = 'admin');

-- Profiles
-- Zabezpieczenie przed self-promote do admina: column-level GRANT pozwala
-- zwykłemu użytkownikowi modyfikować TYLKO 'email'. Kolumna 'role' wymaga
-- uprawnienia, które ma tylko service_role / postgres. Admin zmienia role
-- przez funkcję set_user_role() poniżej.
DROP POLICY IF EXISTS "read_profile"   ON profiles;
DROP POLICY IF EXISTS "insert_profile" ON profiles;
DROP POLICY IF EXISTS "update_profile" ON profiles;
CREATE POLICY "read_profile"   ON profiles FOR SELECT TO authenticated USING (auth.uid() = id OR get_my_role() = 'admin');
CREATE POLICY "insert_profile" ON profiles FOR INSERT TO authenticated WITH CHECK (auth.uid() = id AND role = 'nowy');
CREATE POLICY "update_profile" ON profiles FOR UPDATE TO authenticated
  USING (auth.uid() = id OR get_my_role() = 'admin')
  WITH CHECK (auth.uid() = id OR get_my_role() = 'admin');

REVOKE UPDATE ON public.profiles FROM authenticated, anon;
GRANT  UPDATE (email) ON public.profiles TO authenticated;

-- 5b. ADMIN: zmiana roli innemu użytkownikowi (omija column-grant przez SECURITY DEFINER)
CREATE OR REPLACE FUNCTION public.set_user_role(target_id uuid, new_role text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
BEGIN
  IF public.get_my_role() <> 'admin' THEN
    RAISE EXCEPTION 'forbidden' USING ERRCODE = '42501';
  END IF;
  IF new_role NOT IN ('nowy','editor','admin') THEN
    RAISE EXCEPTION 'invalid role' USING ERRCODE = '22023';
  END IF;
  IF target_id = auth.uid() AND new_role <> 'admin' THEN
    RAISE EXCEPTION 'cannot demote self' USING ERRCODE = '22023';
  END IF;
  UPDATE public.profiles SET role = new_role WHERE id = target_id;
END;
$$;

REVOKE ALL ON FUNCTION public.set_user_role(uuid, text) FROM public, anon;
GRANT EXECUTE ON FUNCTION public.set_user_role(uuid, text) TO authenticated;

-- Allowed emails (whitelist)
-- Anon może SELECT bo sendOtpCode() sprawdza whitelist przed zalogowaniem.
-- Tylko admin może modyfikować listę.
DROP POLICY IF EXISTS "read_allowed_emails"   ON allowed_emails;
DROP POLICY IF EXISTS "insert_allowed_emails" ON allowed_emails;
DROP POLICY IF EXISTS "delete_allowed_emails" ON allowed_emails;
CREATE POLICY "read_allowed_emails"   ON allowed_emails FOR SELECT USING (true);
CREATE POLICY "insert_allowed_emails" ON allowed_emails FOR INSERT TO authenticated WITH CHECK (get_my_role() = 'admin');
CREATE POLICY "delete_allowed_emails" ON allowed_emails FOR DELETE TO authenticated USING (get_my_role() = 'admin');

-- Storage policies
-- Ścieżki:
--   `cat_images/*` — zdjęcia kategorii (tylko admin upload/delete)
--   `*`            — zdjęcia części (każdy z rolą może upload, edytor/admin może delete)
DROP POLICY IF EXISTS "upload_photos"       ON storage.objects;
DROP POLICY IF EXISTS "read_photos"         ON storage.objects;
DROP POLICY IF EXISTS "delete_photos"       ON storage.objects;
DROP POLICY IF EXISTS "upload_part_photos"  ON storage.objects;
DROP POLICY IF EXISTS "upload_cat_photos"   ON storage.objects;
DROP POLICY IF EXISTS "delete_part_photos"  ON storage.objects;
DROP POLICY IF EXISTS "delete_cat_photos"   ON storage.objects;

CREATE POLICY "read_photos" ON storage.objects FOR SELECT
  USING (bucket_id = 'photos');

CREATE POLICY "upload_part_photos" ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'photos'
    AND (storage.foldername(name))[1] IS DISTINCT FROM 'cat_images'
    AND public.get_my_role() IN ('nowy','editor','admin')
  );

CREATE POLICY "upload_cat_photos" ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'photos'
    AND (storage.foldername(name))[1] = 'cat_images'
    AND public.get_my_role() = 'admin'
  );

-- UPDATE pokrywa upsert:true dla cat_images (uploadCatImg używa upsert)
DROP POLICY IF EXISTS "update_cat_photos" ON storage.objects;
CREATE POLICY "update_cat_photos" ON storage.objects FOR UPDATE TO authenticated
  USING (
    bucket_id = 'photos'
    AND (storage.foldername(name))[1] = 'cat_images'
    AND public.get_my_role() = 'admin'
  )
  WITH CHECK (
    bucket_id = 'photos'
    AND (storage.foldername(name))[1] = 'cat_images'
    AND public.get_my_role() = 'admin'
  );

CREATE POLICY "delete_part_photos" ON storage.objects FOR DELETE TO authenticated
  USING (
    bucket_id = 'photos'
    AND (storage.foldername(name))[1] IS DISTINCT FROM 'cat_images'
    AND public.get_my_role() IN ('editor','admin')
  );

CREATE POLICY "delete_cat_photos" ON storage.objects FOR DELETE TO authenticated
  USING (
    bucket_id = 'photos'
    AND (storage.foldername(name))[1] = 'cat_images'
    AND public.get_my_role() = 'admin'
  );

-- 6. PO REJESTRACJI: zmień swoją rolę na admin (jednorazowo, bezpośrednio w SQL)
-- UPDATE public.profiles SET role = 'admin' WHERE email = 'twój@email.com';

-- 7. MIGRACJA: zmiana nazwy kategorii 'Przyczepa' → 'Przyczepki'
-- Uruchom TYLKO jeśli masz dane z kategorią 'Przyczepa':
-- UPDATE parts SET category = REPLACE(category, 'Przyczepa', 'Przyczepki')
--   WHERE category = 'Przyczepa' OR category LIKE 'Przyczepa/%';
-- UPDATE custom_cats SET name = REPLACE(name, 'Przyczepa', 'Przyczepki')
--   WHERE name = 'Przyczepa' OR name LIKE 'Przyczepa/%';

-- 8. ZDJĘCIA KATEGORII: przechowywane w Storage bucket 'photos' w folderze 'cat_images/'
-- Admin może uploadować przez przycisk 📷 w Zarządzaniu kategoriami.
-- Ścieżka: cat_images/{encodeURIComponent(nazwa_kategorii)}.jpg

-- 9. MIGRACJA EXISTING USERS: nowi po wdrożeniu dostają 'nowy'.
-- Istniejący użytkownicy zachowują 'editor' (default sprzed wdrożenia).
-- Jeśli chcesz wszystkich aktywnych editorów cofnąć do 'nowy':
-- UPDATE public.profiles SET role = 'nowy' WHERE role = 'editor';
