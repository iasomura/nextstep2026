--
-- PostgreSQL database dump
--

\restrict fyIdHRW30ux7cCqsfNkid9gh66ZgGwDEgYyDgdq0wUqNUDIx69TgNWI37VWFv8h

-- Dumped from database version 16.11 (Ubuntu 16.11-0ubuntu0.24.04.1)
-- Dumped by pg_dump version 16.11 (Ubuntu 16.11-0ubuntu0.24.04.1)

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
-- Name: public; Type: SCHEMA; Schema: -; Owner: pg_database_owner
--

CREATE SCHEMA public;


ALTER SCHEMA public OWNER TO pg_database_owner;

--
-- Name: SCHEMA public; Type: COMMENT; Schema: -; Owner: pg_database_owner
--

COMMENT ON SCHEMA public IS 'standard public schema';


--
-- Name: check_duplicate_before_insert(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.check_duplicate_before_insert() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- URLからドメインを自動抽出
    IF NEW.domain IS NULL OR NEW.domain = '' THEN
        NEW.domain := extract_domain_from_url(NEW.url);
    END IF;
    
    -- HTTPSでないURLは自動的にNOT_HTTPSステータスに
    IF NOT NEW.url LIKE 'https://%' THEN
        NEW.status := 'NOT_HTTPS';
        NEW.is_duplicate := FALSE;  -- HTTPでも重複フラグはFALSE
        RETURN NEW;
    END IF;
    
    -- 既にステータスが設定されている場合はスキップ
    IF NEW.status IS NOT NULL AND NEW.status != '' THEN
        RETURN NEW;
    END IF;
    
    -- certificatesテーブルとの重複チェック
    IF EXISTS (SELECT 1 FROM certificates WHERE domain = NEW.domain LIMIT 1) THEN
        NEW.is_duplicate := TRUE;
        NEW.duplicate_source := 'certificates';
        NEW.status := 'DUPLICATE';
        RETURN NEW;
    END IF;
    
    -- phishtankテーブルとの重複チェック
    -- 注: phishtankテーブルにdomainカラムがある場合のみ有効
    -- IF EXISTS (SELECT 1 FROM phishtank WHERE domain = NEW.domain LIMIT 1) THEN
    --     NEW.is_duplicate := TRUE;
    --     NEW.duplicate_source := 'phishtank';
    --     NEW.status := 'DUPLICATE';
    --     RETURN NEW;
    -- END IF;
    
    -- 同一テーブル内での重複チェック（既に同じドメインが存在する場合）
    IF EXISTS (
        SELECT 1 FROM jpcert_phishing_urls 
        WHERE domain = NEW.domain 
        AND id != COALESCE(NEW.id, -1)
        AND status = 'SUCCESS'  -- 成功したダウンロードのみチェック
        LIMIT 1
    ) THEN
        NEW.is_duplicate := TRUE;
        NEW.duplicate_source := 'jpcert_self';
        NEW.status := 'DUPLICATE';
        RETURN NEW;
    END IF;
    
    -- 重複がない場合はPENDINGステータスに
    NEW.is_duplicate := FALSE;
    NEW.status := 'PENDING';
    
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.check_duplicate_before_insert() OWNER TO postgres;

--
-- Name: check_phishtank_duplicates(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.check_phishtank_duplicates() RETURNS TABLE(phish_id bigint, duplicate_count bigint)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT 
        p.phish_id,
        COUNT(*) as duplicate_count
    FROM phishtank_entries p
    GROUP BY p.phish_id
    HAVING COUNT(*) > 1
    ORDER BY duplicate_count DESC;
END;
$$;


ALTER FUNCTION public.check_phishtank_duplicates() OWNER TO postgres;

--
-- Name: extract_domain_from_url(text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.extract_domain_from_url(url text) RETURNS text
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- プロトコルを除去してドメインを抽出
    -- 例: https://example.com/path → example.com
    -- 例: http://sub.example.com:8080/path → sub.example.com:8080
    RETURN SPLIT_PART(SPLIT_PART(url, '//', 2), '/', 1);
END;
$$;


ALTER FUNCTION public.extract_domain_from_url(url text) OWNER TO postgres;

--
-- Name: update_phishtank_updated_at(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.update_phishtank_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.update_phishtank_updated_at() OWNER TO postgres;

--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.update_updated_at_column() OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: certificates; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.certificates (
    id integer NOT NULL,
    domain text,
    cert_id numeric,
    cert_data bytea,
    download_date timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    status text,
    debug_info text,
    debug_info_jsonb jsonb
);


ALTER TABLE public.certificates OWNER TO postgres;

--
-- Name: certificates_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.certificates_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.certificates_id_seq OWNER TO postgres;

--
-- Name: certificates_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.certificates_id_seq OWNED BY public.certificates.id;


--
-- Name: jpcert_phishing_urls; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.jpcert_phishing_urls (
    id integer NOT NULL,
    date timestamp without time zone NOT NULL,
    url text NOT NULL,
    description text,
    domain text,
    cert_id numeric,
    cert_data bytea,
    download_date timestamp without time zone,
    status text,
    debug_info text,
    debug_info_jsonb jsonb,
    is_duplicate boolean DEFAULT false,
    duplicate_source text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.jpcert_phishing_urls OWNER TO postgres;

--
-- Name: jpcert_phishing_urls_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.jpcert_phishing_urls_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.jpcert_phishing_urls_id_seq OWNER TO postgres;

--
-- Name: jpcert_phishing_urls_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.jpcert_phishing_urls_id_seq OWNED BY public.jpcert_phishing_urls.id;


--
-- Name: phishing_sites; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.phishing_sites (
    alert jsonb,
    analytics_id jsonb,
    asn jsonb,
    asn_country jsonb,
    auth jsonb,
    "chain{}" jsonb,
    country jsonb,
    "create" jsonb,
    ddate jsonb,
    domain jsonb,
    dst_asn jsonb,
    dst_asn_country jsonb,
    dst_auth jsonb,
    dst_country jsonb,
    dst_domain jsonb,
    dst_emails jsonb,
    dst_ip jsonb,
    dst_name_servers jsonb,
    dst_registrant jsonb,
    dst_registrant_country jsonb,
    dst_registrar jsonb,
    dst_san jsonb,
    emails jsonb,
    file_hash jsonb,
    first_crawl jsonb,
    first_submit jsonb,
    google jsonb,
    "group" jsonb,
    id jsonb,
    image_hash jsonb,
    image_path jsonb,
    ip jsonb,
    last_crawl jsonb,
    lasturl jsonb,
    lasturl_domain jsonb,
    max_id jsonb,
    min_id jsonb,
    ml_result jsonb,
    monitor jsonb,
    name_servers jsonb,
    registrant jsonb,
    registrant_country jsonb,
    registrar jsonb,
    registrar_country jsonb,
    result jsonb,
    san jsonb,
    src jsonb,
    status jsonb,
    submit_date jsonb,
    target jsonb,
    target_category jsonb,
    threat jsonb,
    ua jsonb,
    update jsonb,
    url jsonb,
    whois_status jsonb,
    wrs jsonb
);


ALTER TABLE public.phishing_sites OWNER TO postgres;

--
-- Name: phishing_sites_new; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.phishing_sites_new (
    alert text,
    analytics_id text,
    asn numeric,
    asn_country text,
    auth text,
    chain text,
    country text,
    "create" timestamp without time zone,
    ddate timestamp without time zone,
    domain text,
    dst_asn numeric,
    dst_asn_country text,
    dst_auth text,
    dst_country text,
    dst_domain text,
    dst_emails text,
    dst_ip text,
    dst_name_servers text,
    dst_registrant text,
    dst_registrant_country text,
    dst_registrar text,
    dst_san text,
    emails text,
    file_hash text,
    first_crawl timestamp without time zone,
    first_submit timestamp without time zone,
    google boolean,
    "group" text,
    id numeric,
    image_hash text,
    image_path text,
    ip text,
    last_crawl timestamp without time zone,
    lasturl text,
    lasturl_domain text,
    max_id numeric,
    min_id numeric,
    ml_result jsonb,
    monitor boolean,
    name_servers text,
    registrant text,
    registrant_country text,
    registrar text,
    registrar_country text,
    result text,
    san text,
    src text,
    status text,
    submit_date timestamp without time zone,
    target text,
    target_category text,
    threat text,
    ua text,
    update timestamp without time zone,
    url text,
    whois_status text,
    wrs text
);


ALTER TABLE public.phishing_sites_new OWNER TO postgres;

--
-- Name: phishtank_entries; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.phishtank_entries (
    id integer NOT NULL,
    generated_at timestamp with time zone,
    batch_id uuid DEFAULT gen_random_uuid(),
    url text NOT NULL,
    phish_id bigint NOT NULL,
    phish_detail_url text,
    ip_address inet,
    cidr_block cidr,
    announcing_network bigint,
    rir text,
    detail_time timestamp with time zone,
    submission_time timestamp with time zone,
    verified boolean,
    verification_time timestamp with time zone,
    online boolean,
    target text,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    cert_data bytea,
    cert_status text,
    cert_debug_info jsonb,
    cert_download_date timestamp without time zone,
    cert_id numeric,
    cert_domain text
);


ALTER TABLE public.phishtank_entries OWNER TO postgres;

--
-- Name: COLUMN phishtank_entries.cert_status; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.phishtank_entries.cert_status IS 'Certificate download status: PENDING, SUCCESS, NOT_FOUND, SEARCH_ERROR, DOWNLOAD_ERROR, CONVERSION_ERROR, INVALID_URL, UNKNOWN_ERROR';


--
-- Name: COLUMN phishtank_entries.cert_debug_info; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.phishtank_entries.cert_debug_info IS 'Debug information including HTTP status codes, error messages, and processing details';


--
-- Name: COLUMN phishtank_entries.cert_download_date; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.phishtank_entries.cert_download_date IS 'Timestamp when the certificate was downloaded';


--
-- Name: COLUMN phishtank_entries.cert_id; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.phishtank_entries.cert_id IS 'Certificate ID from crt.sh';


--
-- Name: COLUMN phishtank_entries.cert_domain; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.phishtank_entries.cert_domain IS 'Domain extracted from URL for certificate search';


--
-- Name: phishtank_cert_progress; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.phishtank_cert_progress AS
 SELECT count(*) AS total_entries,
    count(
        CASE
            WHEN (cert_status IS NOT NULL) THEN 1
            ELSE NULL::integer
        END) AS processed_entries,
    count(
        CASE
            WHEN (cert_status = 'SUCCESS'::text) THEN 1
            ELSE NULL::integer
        END) AS success_count,
    count(
        CASE
            WHEN (cert_status = 'NOT_FOUND'::text) THEN 1
            ELSE NULL::integer
        END) AS not_found_count,
    count(
        CASE
            WHEN (cert_status ~~ '%ERROR'::text) THEN 1
            ELSE NULL::integer
        END) AS error_count,
    count(
        CASE
            WHEN ((cert_status IS NULL) AND (cert_data IS NULL)) THEN 1
            ELSE NULL::integer
        END) AS pending_count,
    round(((100.0 * (count(
        CASE
            WHEN (cert_status IS NOT NULL) THEN 1
            ELSE NULL::integer
        END))::numeric) / (count(*))::numeric), 2) AS progress_percentage
   FROM public.phishtank_entries;


ALTER VIEW public.phishtank_cert_progress OWNER TO postgres;

--
-- Name: phishtank_cert_stats; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.phishtank_cert_stats AS
 SELECT cert_status,
    count(*) AS entry_count,
    count(DISTINCT cert_domain) AS unique_domains,
    min(cert_download_date) AS earliest_download,
    max(cert_download_date) AS latest_download,
    count(
        CASE
            WHEN (cert_data IS NOT NULL) THEN 1
            ELSE NULL::integer
        END) AS with_cert_data
   FROM public.phishtank_entries
  GROUP BY cert_status
  ORDER BY (count(*)) DESC;


ALTER VIEW public.phishtank_cert_stats OWNER TO postgres;

--
-- Name: phishtank_entries_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.phishtank_entries_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.phishtank_entries_id_seq OWNER TO postgres;

--
-- Name: phishtank_entries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.phishtank_entries_id_seq OWNED BY public.phishtank_entries.id;


--
-- Name: phishtank_rir_stats; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.phishtank_rir_stats AS
 SELECT rir,
    count(*) AS entry_count,
    count(DISTINCT announcing_network) AS unique_asns,
    count(
        CASE
            WHEN (verified = true) THEN 1
            ELSE NULL::integer
        END) AS verified_count,
    count(
        CASE
            WHEN (online = true) THEN 1
            ELSE NULL::integer
        END) AS online_count
   FROM public.phishtank_entries
  WHERE (rir IS NOT NULL)
  GROUP BY rir
  ORDER BY (count(*)) DESC;


ALTER VIEW public.phishtank_rir_stats OWNER TO postgres;

--
-- Name: phishtank_stats; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.phishtank_stats AS
 SELECT count(*) AS total_entries,
    count(
        CASE
            WHEN (verified = true) THEN 1
            ELSE NULL::integer
        END) AS verified_entries,
    count(
        CASE
            WHEN (online = true) THEN 1
            ELSE NULL::integer
        END) AS online_entries,
    count(DISTINCT target) AS unique_targets,
    count(DISTINCT rir) AS unique_rirs,
    count(DISTINCT announcing_network) AS unique_asns,
    min(submission_time) AS earliest_submission,
    max(submission_time) AS latest_submission,
    min(generated_at) AS earliest_generated,
    max(generated_at) AS latest_generated
   FROM public.phishtank_entries;


ALTER VIEW public.phishtank_stats OWNER TO postgres;

--
-- Name: phishtank_target_stats; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.phishtank_target_stats AS
 SELECT target,
    count(*) AS entry_count,
    count(
        CASE
            WHEN (verified = true) THEN 1
            ELSE NULL::integer
        END) AS verified_count,
    count(
        CASE
            WHEN (online = true) THEN 1
            ELSE NULL::integer
        END) AS online_count,
    round((((count(
        CASE
            WHEN (verified = true) THEN 1
            ELSE NULL::integer
        END))::numeric / (count(*))::numeric) * (100)::numeric), 2) AS verification_rate,
    round((((count(
        CASE
            WHEN (online = true) THEN 1
            ELSE NULL::integer
        END))::numeric / (count(*))::numeric) * (100)::numeric), 2) AS online_rate
   FROM public.phishtank_entries
  WHERE (target IS NOT NULL)
  GROUP BY target
  ORDER BY (count(*)) DESC;


ALTER VIEW public.phishtank_target_stats OWNER TO postgres;

--
-- Name: trusted_certificates; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.trusted_certificates (
    id integer NOT NULL,
    domain text,
    cert_data bytea,
    issuer_name text,
    common_name text,
    not_before text,
    not_after text,
    serial_number text,
    san_domains text[],
    status text,
    download_date timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    debug_info jsonb
);


ALTER TABLE public.trusted_certificates OWNER TO postgres;

--
-- Name: trusted_certificates_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.trusted_certificates_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.trusted_certificates_id_seq OWNER TO postgres;

--
-- Name: trusted_certificates_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.trusted_certificates_id_seq OWNED BY public.trusted_certificates.id;


--
-- Name: certificates id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.certificates ALTER COLUMN id SET DEFAULT nextval('public.certificates_id_seq'::regclass);


--
-- Name: jpcert_phishing_urls id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.jpcert_phishing_urls ALTER COLUMN id SET DEFAULT nextval('public.jpcert_phishing_urls_id_seq'::regclass);


--
-- Name: phishtank_entries id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.phishtank_entries ALTER COLUMN id SET DEFAULT nextval('public.phishtank_entries_id_seq'::regclass);


--
-- Name: trusted_certificates id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.trusted_certificates ALTER COLUMN id SET DEFAULT nextval('public.trusted_certificates_id_seq'::regclass);


--
-- Name: certificates certificates_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT certificates_pkey PRIMARY KEY (id);


--
-- Name: jpcert_phishing_urls jpcert_phishing_urls_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.jpcert_phishing_urls
    ADD CONSTRAINT jpcert_phishing_urls_pkey PRIMARY KEY (id);


--
-- Name: phishtank_entries phishtank_entries_phish_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.phishtank_entries
    ADD CONSTRAINT phishtank_entries_phish_id_key UNIQUE (phish_id);


--
-- Name: phishtank_entries phishtank_entries_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.phishtank_entries
    ADD CONSTRAINT phishtank_entries_pkey PRIMARY KEY (id);


--
-- Name: trusted_certificates trusted_certificates_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.trusted_certificates
    ADD CONSTRAINT trusted_certificates_pkey PRIMARY KEY (id);


--
-- Name: trusted_certificates unique_domain; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.trusted_certificates
    ADD CONSTRAINT unique_domain UNIQUE (domain);


--
-- Name: idx_certificates_cert_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_certificates_cert_id ON public.certificates USING btree (cert_id);


--
-- Name: idx_certificates_debug_info_jsonb; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_certificates_debug_info_jsonb ON public.certificates USING gin (debug_info_jsonb);


--
-- Name: idx_certificates_domain; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_certificates_domain ON public.certificates USING btree (domain);


--
-- Name: idx_certificates_domain_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_certificates_domain_status ON public.certificates USING btree (domain, status);


--
-- Name: idx_certificates_download_date; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_certificates_download_date ON public.certificates USING btree (download_date);


--
-- Name: idx_certificates_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_certificates_status ON public.certificates USING btree (status);


--
-- Name: idx_jpcert_phishing_urls_cert_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_jpcert_phishing_urls_cert_id ON public.jpcert_phishing_urls USING btree (cert_id);


--
-- Name: idx_jpcert_phishing_urls_date; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_jpcert_phishing_urls_date ON public.jpcert_phishing_urls USING btree (date);


--
-- Name: idx_jpcert_phishing_urls_debug_info_jsonb; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_jpcert_phishing_urls_debug_info_jsonb ON public.jpcert_phishing_urls USING gin (debug_info_jsonb);


--
-- Name: idx_jpcert_phishing_urls_domain; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_jpcert_phishing_urls_domain ON public.jpcert_phishing_urls USING btree (domain);


--
-- Name: idx_jpcert_phishing_urls_download_date; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_jpcert_phishing_urls_download_date ON public.jpcert_phishing_urls USING btree (download_date);


--
-- Name: idx_jpcert_phishing_urls_is_duplicate; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_jpcert_phishing_urls_is_duplicate ON public.jpcert_phishing_urls USING btree (is_duplicate);


--
-- Name: idx_jpcert_phishing_urls_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_jpcert_phishing_urls_status ON public.jpcert_phishing_urls USING btree (status);


--
-- Name: idx_jpcert_urls_for_download; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_jpcert_urls_for_download ON public.jpcert_phishing_urls USING btree (status, is_duplicate) WHERE ((status = 'PENDING'::text) AND (is_duplicate = false));


--
-- Name: idx_phishtank_announcing_network; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_phishtank_announcing_network ON public.phishtank_entries USING btree (announcing_network);


--
-- Name: idx_phishtank_batch_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_phishtank_batch_id ON public.phishtank_entries USING btree (batch_id);


--
-- Name: idx_phishtank_cert_debug_info; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_phishtank_cert_debug_info ON public.phishtank_entries USING gin (cert_debug_info);


--
-- Name: idx_phishtank_cert_domain; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_phishtank_cert_domain ON public.phishtank_entries USING btree (cert_domain);


--
-- Name: idx_phishtank_cert_download_date; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_phishtank_cert_download_date ON public.phishtank_entries USING btree (cert_download_date);


--
-- Name: idx_phishtank_cert_processing; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_phishtank_cert_processing ON public.phishtank_entries USING btree (cert_status, cert_download_date) WHERE (cert_data IS NULL);


--
-- Name: idx_phishtank_cert_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_phishtank_cert_status ON public.phishtank_entries USING btree (cert_status);


--
-- Name: idx_phishtank_created_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_phishtank_created_at ON public.phishtank_entries USING btree (created_at);


--
-- Name: idx_phishtank_detail_time; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_phishtank_detail_time ON public.phishtank_entries USING btree (detail_time);


--
-- Name: idx_phishtank_generated_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_phishtank_generated_at ON public.phishtank_entries USING btree (generated_at);


--
-- Name: idx_phishtank_ip_address; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_phishtank_ip_address ON public.phishtank_entries USING btree (ip_address);


--
-- Name: idx_phishtank_online; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_phishtank_online ON public.phishtank_entries USING btree (online);


--
-- Name: idx_phishtank_phish_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_phishtank_phish_id ON public.phishtank_entries USING btree (phish_id);


--
-- Name: idx_phishtank_rir; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_phishtank_rir ON public.phishtank_entries USING btree (rir);


--
-- Name: idx_phishtank_submission_time; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_phishtank_submission_time ON public.phishtank_entries USING btree (submission_time);


--
-- Name: idx_phishtank_target; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_phishtank_target ON public.phishtank_entries USING btree (target);


--
-- Name: idx_phishtank_url; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_phishtank_url ON public.phishtank_entries USING btree (url);


--
-- Name: idx_phishtank_verification_time; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_phishtank_verification_time ON public.phishtank_entries USING btree (verification_time);


--
-- Name: idx_phishtank_verified; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_phishtank_verified ON public.phishtank_entries USING btree (verified);


--
-- Name: idx_trusted_certificates_domain; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_trusted_certificates_domain ON public.trusted_certificates USING btree (domain);


--
-- Name: idx_trusted_certificates_download_date; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_trusted_certificates_download_date ON public.trusted_certificates USING btree (download_date);


--
-- Name: idx_trusted_certificates_issuer_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_trusted_certificates_issuer_name ON public.trusted_certificates USING btree (issuer_name);


--
-- Name: idx_trusted_certificates_not_after; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_trusted_certificates_not_after ON public.trusted_certificates USING btree (not_after);


--
-- Name: idx_trusted_certificates_san_domains; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_trusted_certificates_san_domains ON public.trusted_certificates USING gin (san_domains);


--
-- Name: idx_trusted_certificates_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_trusted_certificates_status ON public.trusted_certificates USING btree (status);


--
-- Name: jpcert_phishing_urls trigger_check_duplicate; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trigger_check_duplicate BEFORE INSERT OR UPDATE ON public.jpcert_phishing_urls FOR EACH ROW EXECUTE FUNCTION public.check_duplicate_before_insert();


--
-- Name: phishtank_entries trigger_phishtank_updated_at; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trigger_phishtank_updated_at BEFORE UPDATE ON public.phishtank_entries FOR EACH ROW EXECUTE FUNCTION public.update_phishtank_updated_at();


--
-- Name: jpcert_phishing_urls trigger_update_timestamp; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trigger_update_timestamp BEFORE UPDATE ON public.jpcert_phishing_urls FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- PostgreSQL database dump complete
--

\unrestrict fyIdHRW30ux7cCqsfNkid9gh66ZgGwDEgYyDgdq0wUqNUDIx69TgNWI37VWFv8h

