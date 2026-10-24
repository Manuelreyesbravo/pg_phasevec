-- pg_phasevec 0.13.0: a reader may compute on the NPU.
--
-- Until now a compute signature named cpu or cuda, the two backends of phasevec-reader (llama.cpp). The
-- NPU reader (Qwen3-Embedding on the Ryzen AI NPU: GEMMs in bfp16/bf16 on the NPU, the rest on the CPU)
-- reads with other arithmetic, so its readings are another reader: same weights, another compute, never
-- mixed with the cpu or cuda readings of those weights (the seal is unique on weights AND compute).
-- Nothing else changes: it registers, proves its seal and records exactly like phasevec-reader.

CREATE OR REPLACE FUNCTION phasevec._check_compute(p_compute jsonb)
RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $f$
BEGIN
    IF jsonb_typeof(p_compute) IS DISTINCT FROM $q$object$q$
       OR coalesce(jsonb_extract_path_text(p_compute, $q$backend$q$), $q$$q$) NOT IN ($q$cpu$q$, $q$cuda$q$, $q$npu$q$) THEN
        RAISE EXCEPTION $q$phasevec: a compute signature names its backend, cpu, cuda or npu$q$
            USING HINT = $q$Register through phasevec-reader --register --backend (cpu or cuda), or the NPU reader, which detect it.$q$;
    END IF;
    IF coalesce(jsonb_extract_path_text(p_compute, $q$device$q$), $q$$q$) = $q$$q$
       OR coalesce(jsonb_extract_path_text(p_compute, $q$libs$q$), $q$$q$) !~ $q$^[0-9a-f]{64}$$q$ THEN
        RAISE EXCEPTION $q$phasevec: a compute signature names its device and the sha256 of the libraries it loaded$q$;
    END IF;
    RETURN p_compute;
END;
$f$;

ALTER TABLE phasevec.readers DROP CONSTRAINT readers_compute_check;
ALTER TABLE phasevec.readers
    ADD CONSTRAINT readers_compute_check CHECK (compute IS NULL OR (
        jsonb_typeof(compute) = $q$object$q$
        AND coalesce(jsonb_extract_path_text(compute, $q$backend$q$), $q$$q$) IN ($q$cpu$q$, $q$cuda$q$, $q$npu$q$)
        AND coalesce(jsonb_extract_path_text(compute, $q$device$q$), $q$$q$) IS DISTINCT FROM $q$$q$
        AND coalesce(jsonb_extract_path_text(compute, $q$libs$q$), $q$$q$) ~ $q$^[0-9a-f]{64}$$q$));
