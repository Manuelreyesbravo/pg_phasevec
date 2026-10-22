-- pg_phasevec 0.3.0 -> 0.4.0: the seal pins the compute, not only the weights.
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

\echo Use "ALTER EXTENSION pg_phasevec UPDATE TO '0.4.0'" to load this file. \quit

ALTER TABLE phasevec.readers ADD COLUMN compute jsonb;
COMMENT ON COLUMN phasevec.readers.compute IS
    'What the reader computes on, as its own process detected it: backend, device, kernels, sha256 of the libraries loaded. NULL: registered before 0.4.0, unpinned.';

-- The same weights on another backend are another reader.
ALTER TABLE phasevec.readers DROP CONSTRAINT readers_model_sha_adapter_sha_heads_sha_key;
ALTER TABLE phasevec.readers
    ADD CONSTRAINT readers_seal_key UNIQUE NULLS NOT DISTINCT (model_sha, adapter_sha, heads_sha, compute);

COMMENT ON TABLE phasevec.readers IS
    'Sealed readers: a reader is identified by the sha256 of its weights (adapter and heads included) and by the compute it reads on. Readings by different readers are never compared.';

CREATE FUNCTION phasevec._check_compute(p_compute jsonb)
RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF jsonb_typeof(p_compute) IS DISTINCT FROM 'object'
       OR coalesce(p_compute->>'backend', '') NOT IN ('cpu', 'cuda') THEN
        RAISE EXCEPTION 'phasevec: a compute signature names its backend, cpu or cuda'
            USING HINT = 'Register through phasevec-reader --register --backend cpu|cuda, which detects it.';
    END IF;
    IF coalesce(p_compute->>'device', '') = '' OR coalesce(p_compute->>'libs', '') !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'phasevec: a compute signature names its device and the sha256 of the libraries it loaded';
    END IF;
    RETURN p_compute;
END;
$$;

-- The same rule as a constraint, written out so the table does not depend on a function's grants.
ALTER TABLE phasevec.readers
    ADD CONSTRAINT readers_compute_check CHECK (compute IS NULL OR (
        jsonb_typeof(compute) = 'object'
        AND coalesce(compute->>'backend', '') IN ('cpu', 'cuda')
        AND coalesce(compute->>'device', '') <> ''
        AND coalesce(compute->>'libs', '') ~ '^[0-9a-f]{64}$'));

-- The manifest checks of 0.1.0, unchanged, so that the registration with and without a compute
-- signature cannot drift apart. Returns the dimensions a reading keeps.
CREATE FUNCTION phasevec._manifest_dims(p_manifest jsonb)
RETURNS int
LANGUAGE plpgsql IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    hex  constant text := '^[0-9a-f]{64}$';
    dims int;
BEGIN
    IF jsonb_typeof(p_manifest) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'phasevec: a manifest is a JSON object';
    END IF;
    IF coalesce(p_manifest->>'reader', '') = '' OR coalesce(p_manifest->>'version', '') = '' THEN
        RAISE EXCEPTION 'phasevec: the manifest needs reader and version';
    END IF;
    IF coalesce(p_manifest->>'base_sha256', '') !~ hex THEN
        RAISE EXCEPTION 'phasevec: base_sha256 is not sealed'
            USING HINT = 'Register through phasevec-reader --register --manifest, which hashes the GGUF it serves.';
    END IF;
    IF coalesce(p_manifest->>'adapter_sha256', '') !~ hex THEN
        RAISE EXCEPTION 'phasevec: adapter_sha256 must be a sha256';
    END IF;
    IF p_manifest ? 'heads_sha256' AND coalesce(p_manifest->>'heads_sha256', '') !~ hex THEN
        RAISE EXCEPTION 'phasevec: heads_sha256 must be a sha256';
    END IF;
    IF coalesce(p_manifest->>'marker', '') = '' OR p_manifest->>'pooling' IS DISTINCT FROM 'none'
       OR p_manifest->>'read_at' IS DISTINCT FROM 'last_marker_token' THEN
        RAISE EXCEPTION 'phasevec: this manifest is not of the marker contract (marker, pooling none, read_at last_marker_token)';
    END IF;
    IF jsonb_typeof(p_manifest->'mrl_dims') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'phasevec: the manifest needs mrl_dims';
    END IF;
    -- A reading keeps the 1024-dim prefix when the reader has one (the rerank code), else its widest.
    SELECT CASE WHEN bool_or(d::int = 1024) THEN 1024 ELSE max(d::int) END INTO dims
      FROM jsonb_array_elements_text(p_manifest->'mrl_dims') d;
    IF dims IS NULL OR dims < 64 OR NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(p_manifest->'mrl_dims') d
                                                WHERE d::int = 64) THEN
        RAISE EXCEPTION 'phasevec: mrl_dims must include 64 (the binary code) and at least one prefix to keep';
    END IF;
    RETURN dims;
END;
$$;

CREATE OR REPLACE FUNCTION phasevec.reader_register(p_manifest jsonb)
RETURNS int
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    dims int := phasevec._manifest_dims(p_manifest);
BEGIN
    RETURN phasevec._reader_insert(
        (p_manifest->>'reader') || '-' || (p_manifest->>'version'),
        p_manifest->>'base_sha256', dims, p_manifest->>'adapter_sha256',
        p_manifest->>'heads_sha256', p_manifest);
END;
$$;

-- A trained reader sealed with its compute. Its name carries the backend (vec-0.1.0@cpu), so the
-- same weights can be served on the CPU and on a GPU as two readers that are never mixed.
CREATE FUNCTION phasevec.reader_register(p_manifest jsonb, p_compute jsonb)
RETURNS int
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    dims int := phasevec._manifest_dims(p_manifest);
    rid  int;
BEGIN
    PERFORM phasevec._check_compute(p_compute);
    INSERT INTO phasevec.readers (name, model_sha, adapter_sha, heads_sha, dims, manifest, compute)
    VALUES ((p_manifest->>'reader') || '-' || (p_manifest->>'version') || '@' || (p_compute->>'backend'),
            lower(p_manifest->>'base_sha256'), lower(p_manifest->>'adapter_sha256'),
            lower(p_manifest->>'heads_sha256'), dims, p_manifest, p_compute)
    RETURNING id INTO rid;
    RETURN rid;
END;
$$;

-- An off-the-shelf (pooled) reader sealed with its compute.
CREATE FUNCTION phasevec.reader_register(p_name text, p_model_sha text, p_dims int, p_adapter_sha text,
                                       p_manifest jsonb, p_compute jsonb)
RETURNS int
LANGUAGE sql
SET search_path = pg_catalog, pg_temp
AS $$
    INSERT INTO phasevec.readers (name, model_sha, adapter_sha, dims, manifest, compute)
    VALUES (p_name, lower(p_model_sha), lower(p_adapter_sha), p_dims, p_manifest, phasevec._check_compute(p_compute))
    RETURNING id;
$$;

-- What a reader process must prove about its compute before it writes. NULL for a reader registered
-- before 0.4.0: the process refuses to read in that reader's name.
CREATE FUNCTION phasevec.reader_compute(p_reader text)
RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT r.compute FROM phasevec.readers r WHERE r.name = p_reader;
$$;

-- Whether the compute a process detected is the one its reader was sealed with. Compared here, as
-- jsonb, so key order or spacing in the process's report cannot make two equal signatures differ.
CREATE FUNCTION phasevec.reader_compute_matches(p_reader text, p_have jsonb)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT r.compute IS NOT NULL AND r.compute = p_have FROM phasevec.readers r WHERE r.name = p_reader;
$$;

REVOKE ALL ON FUNCTION phasevec._check_compute(jsonb), phasevec._manifest_dims(jsonb),
    phasevec.reader_register(jsonb, jsonb), phasevec.reader_register(text, text, int, text, jsonb, jsonb),
    phasevec.reader_compute(text), phasevec.reader_compute_matches(text, jsonb)
  FROM PUBLIC;
