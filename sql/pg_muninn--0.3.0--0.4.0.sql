-- pg_muninn 0.3.0 -> 0.4.0: the seal pins the compute, not only the weights.
--
-- The same weights do not give the same reading everywhere. With one GGUF, one adapter and one set of
-- heads, a reader computing on the CPU and one computing on a GPU (or llama.cpp quietly offloading the
-- large matrix products of a batch to the GPU while the layers stay on the CPU) write 256-bit codes
-- that differ in a few bits for the same text. Two processes holding the same seal could then record
-- readings that are not comparable, and find would mix them as one reader's.
--
-- So a reader is sealed with its compute signature too: the backend, the device, the kernels the
-- build carries and a hash of the libraries actually loaded. The reader process detects that
-- signature itself and refuses to read in a reader's name when it does not match, exactly as it
-- already refuses other weights. A reader registered before 0.4.0 has no compute signature and the
-- reader process refuses it as well: its readings are replaced through reader_switch to a reader
-- registered with one (they become foreign and are read again), never relabelled.

\echo Use "ALTER EXTENSION pg_muninn UPDATE TO '0.4.0'" to load this file. \quit

ALTER TABLE muninn.readers ADD COLUMN compute jsonb;
COMMENT ON COLUMN muninn.readers.compute IS
    'What the reader computes on, as its own process detected it: backend, device, kernels, sha256 of the libraries loaded. NULL: registered before 0.4.0, unpinned.';

-- The same weights on another backend are another reader.
ALTER TABLE muninn.readers DROP CONSTRAINT readers_model_sha_adapter_sha_heads_sha_key;
ALTER TABLE muninn.readers
    ADD CONSTRAINT readers_seal_key UNIQUE NULLS NOT DISTINCT (model_sha, adapter_sha, heads_sha, compute);

COMMENT ON TABLE muninn.readers IS
    'Sealed readers: a reader is identified by the sha256 of its weights (adapter and heads included) and by the compute it reads on. Readings by different readers are never compared.';

CREATE FUNCTION muninn._check_compute(p_compute jsonb)
RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF jsonb_typeof(p_compute) IS DISTINCT FROM 'object'
       OR coalesce(p_compute->>'backend', '') NOT IN ('cpu', 'cuda') THEN
        RAISE EXCEPTION 'muninn: a compute signature names its backend, cpu or cuda'
            USING HINT = 'Register through muninn-reader --register --backend cpu|cuda, which detects it.';
    END IF;
    IF coalesce(p_compute->>'device', '') = '' OR coalesce(p_compute->>'libs', '') !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'muninn: a compute signature names its device and the sha256 of the libraries it loaded';
    END IF;
    RETURN p_compute;
END;
$$;

-- The same rule as a constraint, written out so the table does not depend on a function's grants.
ALTER TABLE muninn.readers
    ADD CONSTRAINT readers_compute_check CHECK (compute IS NULL OR (
        jsonb_typeof(compute) = 'object'
        AND coalesce(compute->>'backend', '') IN ('cpu', 'cuda')
        AND coalesce(compute->>'device', '') <> ''
        AND coalesce(compute->>'libs', '') ~ '^[0-9a-f]{64}$'));

-- The manifest checks of 0.1.0, unchanged, so that the registration with and without a compute
-- signature cannot drift apart. Returns the dimensions a reading keeps.
CREATE FUNCTION muninn._manifest_dims(p_manifest jsonb)
RETURNS int
LANGUAGE plpgsql IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    hex  constant text := '^[0-9a-f]{64}$';
    dims int;
BEGIN
    IF jsonb_typeof(p_manifest) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'muninn: a manifest is a JSON object';
    END IF;
    IF coalesce(p_manifest->>'reader', '') = '' OR coalesce(p_manifest->>'version', '') = '' THEN
        RAISE EXCEPTION 'muninn: the manifest needs reader and version';
    END IF;
    IF coalesce(p_manifest->>'base_sha256', '') !~ hex THEN
        RAISE EXCEPTION 'muninn: base_sha256 is not sealed'
            USING HINT = 'Register through muninn-reader --register --manifest, which hashes the GGUF it serves.';
    END IF;
    IF coalesce(p_manifest->>'adapter_sha256', '') !~ hex THEN
        RAISE EXCEPTION 'muninn: adapter_sha256 must be a sha256';
    END IF;
    IF p_manifest ? 'heads_sha256' AND coalesce(p_manifest->>'heads_sha256', '') !~ hex THEN
        RAISE EXCEPTION 'muninn: heads_sha256 must be a sha256';
    END IF;
    IF coalesce(p_manifest->>'marker', '') = '' OR p_manifest->>'pooling' IS DISTINCT FROM 'none'
       OR p_manifest->>'read_at' IS DISTINCT FROM 'last_marker_token' THEN
        RAISE EXCEPTION 'muninn: this manifest is not of the marker contract (marker, pooling none, read_at last_marker_token)';
    END IF;
    IF jsonb_typeof(p_manifest->'mrl_dims') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'muninn: the manifest needs mrl_dims';
    END IF;
    -- A reading keeps the 1024-dim prefix when the reader has one (the rerank code), else its widest.
    SELECT CASE WHEN bool_or(d::int = 1024) THEN 1024 ELSE max(d::int) END INTO dims
      FROM jsonb_array_elements_text(p_manifest->'mrl_dims') d;
    IF dims IS NULL OR dims < 64 OR NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(p_manifest->'mrl_dims') d
                                                WHERE d::int = 64) THEN
        RAISE EXCEPTION 'muninn: mrl_dims must include 64 (the binary code) and at least one prefix to keep';
    END IF;
    RETURN dims;
END;
$$;

CREATE OR REPLACE FUNCTION muninn.reader_register(p_manifest jsonb)
RETURNS int
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    dims int := muninn._manifest_dims(p_manifest);
BEGIN
    RETURN muninn._reader_insert(
        (p_manifest->>'reader') || '-' || (p_manifest->>'version'),
        p_manifest->>'base_sha256', dims, p_manifest->>'adapter_sha256',
        p_manifest->>'heads_sha256', p_manifest);
END;
$$;

-- A trained reader sealed with its compute. Its name carries the backend (vec-0.1.0@cpu), so the
-- same weights can be served on the CPU and on a GPU as two readers that are never mixed.
CREATE FUNCTION muninn.reader_register(p_manifest jsonb, p_compute jsonb)
RETURNS int
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    dims int := muninn._manifest_dims(p_manifest);
    rid  int;
BEGIN
    PERFORM muninn._check_compute(p_compute);
    INSERT INTO muninn.readers (name, model_sha, adapter_sha, heads_sha, dims, manifest, compute)
    VALUES ((p_manifest->>'reader') || '-' || (p_manifest->>'version') || '@' || (p_compute->>'backend'),
            lower(p_manifest->>'base_sha256'), lower(p_manifest->>'adapter_sha256'),
            lower(p_manifest->>'heads_sha256'), dims, p_manifest, p_compute)
    RETURNING id INTO rid;
    RETURN rid;
END;
$$;

-- An off-the-shelf (pooled) reader sealed with its compute.
CREATE FUNCTION muninn.reader_register(p_name text, p_model_sha text, p_dims int, p_adapter_sha text,
                                       p_manifest jsonb, p_compute jsonb)
RETURNS int
LANGUAGE sql
SET search_path = pg_catalog, pg_temp
AS $$
    INSERT INTO muninn.readers (name, model_sha, adapter_sha, dims, manifest, compute)
    VALUES (p_name, lower(p_model_sha), lower(p_adapter_sha), p_dims, p_manifest, muninn._check_compute(p_compute))
    RETURNING id;
$$;

-- What a reader process must prove about its compute before it writes. NULL for a reader registered
-- before 0.4.0: the process refuses to read in that reader's name.
CREATE FUNCTION muninn.reader_compute(p_reader text)
RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT r.compute FROM muninn.readers r WHERE r.name = p_reader;
$$;

-- Whether the compute a process detected is the one its reader was sealed with. Compared here, as
-- jsonb, so key order or spacing in the process's report cannot make two equal signatures differ.
CREATE FUNCTION muninn.reader_compute_matches(p_reader text, p_have jsonb)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT r.compute IS NOT NULL AND r.compute = p_have FROM muninn.readers r WHERE r.name = p_reader;
$$;

REVOKE ALL ON FUNCTION muninn._check_compute(jsonb), muninn._manifest_dims(jsonb),
    muninn.reader_register(jsonb, jsonb), muninn.reader_register(text, text, int, text, jsonb, jsonb),
    muninn.reader_compute(text), muninn.reader_compute_matches(text, jsonb)
  FROM PUBLIC;
