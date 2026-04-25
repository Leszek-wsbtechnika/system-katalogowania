-- === KATALOG CZĘŚCI — Supabase setup ===
-- Uruchom w: Supabase → SQL Editor

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
  role  TEXT NOT NULL DEFAULT 'editor'
        CHECK (role IN ('nowy','editor','admin'))
);

-- 2. STORAGE BUCKET (publiczny — zdjęcia dostępne przez URL)
INSERT INTO storage.buckets (id, name, public)
VALUES ('photos', 'photos', true)
ON CONFLICT DO NOTHING;

-- 3. AUTO-TWORZENIE PROFILU PO REJESTRACJI
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (id, email, role)
  VALUES (NEW.id, NEW.email, 'editor')
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 4. HELPER: rola bieżącego użytkownika
CREATE OR REPLACE FUNCTION public.get_my_role()
RETURNS TEXT AS $$
  SELECT role FROM public.profiles WHERE id = auth.uid();
$$ LANGUAGE sql STABLE SECURITY DEFINER;

-- 5. RLS
ALTER TABLE parts       ENABLE ROW LEVEL SECURITY;
ALTER TABLE links       ENABLE ROW LEVEL SECURITY;
ALTER TABLE custom_cats ENABLE ROW LEVEL SECURITY;
ALTER TABLE profiles    ENABLE ROW LEVEL SECURITY;

-- Parts
DROP POLICY IF EXISTS "read_parts"   ON parts;
DROP POLICY IF EXISTS "insert_parts" ON parts;
DROP POLICY IF EXISTS "update_parts" ON parts;
DROP POLICY IF EXISTS "delete_parts" ON parts;
CREATE POLICY "read_parts"   ON parts FOR SELECT TO authenticated USING (true);
CREATE POLICY "insert_parts" ON parts FOR INSERT TO authenticated WITH CHECK (get_my_role() IN ('nowy','editor','admin'));
CREATE POLICY "update_parts" ON parts FOR UPDATE TO authenticated USING (get_my_role() IN ('editor','admin'));
CREATE POLICY "delete_parts" ON parts FOR DELETE TO authenticated USING (get_my_role() = 'admin');

-- Links
DROP POLICY IF EXISTS "read_links"   ON links;
DROP POLICY IF EXISTS "insert_links" ON links;
DROP POLICY IF EXISTS "update_links" ON links;
DROP POLICY IF EXISTS "delete_links" ON links;
CREATE POLICY "read_links"   ON links FOR SELECT TO authenticated USING (true);
CREATE POLICY "insert_links" ON links FOR INSERT TO authenticated WITH CHECK (get_my_role() IN ('nowy','editor','admin'));
CREATE POLICY "update_links" ON links FOR UPDATE TO authenticated USING (get_my_role() IN ('editor','admin'));
CREATE POLICY "delete_links" ON links FOR DELETE TO authenticated USING (get_my_role() = 'admin');

-- Custom cats
DROP POLICY IF EXISTS "read_cats"   ON custom_cats;
DROP POLICY IF EXISTS "insert_cats" ON custom_cats;
DROP POLICY IF EXISTS "delete_cats" ON custom_cats;
CREATE POLICY "read_cats"   ON custom_cats FOR SELECT TO authenticated USING (true);
CREATE POLICY "insert_cats" ON custom_cats FOR INSERT TO authenticated WITH CHECK (get_my_role() IN ('editor','admin'));
CREATE POLICY "delete_cats" ON custom_cats FOR DELETE TO authenticated USING (get_my_role() = 'admin');

-- Profiles
DROP POLICY IF EXISTS "read_profile"   ON profiles;
DROP POLICY IF EXISTS "insert_profile" ON profiles;
CREATE POLICY "read_profile"   ON profiles FOR SELECT TO authenticated USING (auth.uid() = id OR get_my_role() = 'admin');
CREATE POLICY "insert_profile" ON profiles FOR INSERT TO authenticated WITH CHECK (auth.uid() = id);

-- Storage
DROP POLICY IF EXISTS "upload_photos" ON storage.objects;
DROP POLICY IF EXISTS "read_photos"   ON storage.objects;
DROP POLICY IF EXISTS "delete_photos" ON storage.objects;
CREATE POLICY "upload_photos" ON storage.objects FOR INSERT TO authenticated WITH CHECK (bucket_id = 'photos');
CREATE POLICY "read_photos"   ON storage.objects FOR SELECT USING (bucket_id = 'photos');
CREATE POLICY "delete_photos" ON storage.objects FOR DELETE TO authenticated USING (bucket_id = 'photos' AND get_my_role() IN ('editor','admin'));

-- 6. PO REJESTRACJI: zmień swoją rolę na admin
-- UPDATE public.profiles SET role = 'admin' WHERE email = 'twój@email.com';
