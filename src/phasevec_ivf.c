/*
 * pg_phasevec 0.8.0 (was phasevec_b 0.2, Track B). A coarse index over the codes pg_phasevec already stores, behind find_v2.
 *
 * build  spherical k-means in float over a sample (64 readings per list), every reading assigned by
 *        the dot of its int8 code with the centroids, plus a SECOND list per reading chosen as SOAR
 *        does (the list whose residual is least parallel to the first one's), so a neighbour that
 *        sits on a border is found from either side. One row per list in phasevec.ivf_lists: for the readings
 *        whose FIRST list it is, ordinals, keys (one blob), text hashes, 256-bit codes and int8 codes;
 *        for its SOAR copies only what the sweep reads (ordinal and 256-bit code, 36 bytes).
 * sweep  probes the nprobe lists whose centroids are nearest the question, scores every reading
 *        there ASYMMETRICALLY (the question's int8 code against the reading's 256 sign bits, through
 *        a 32 x 256 table built per question), keeps the best m, reranks them by the int8 cosine
 *        (the same score as phasevec.find) and returns the best kk WITH the text hash each code was
 *        read from. It decides nothing about freshness: find_v2 validates every candidate against
 *        phasevec.sources in the caller's snapshot, so a stale list can cost recall, never provenance.
 *
 * 0.1 compared signs with signs (Hamming) and built k-majority centroids in Hamming: at 100k it
 * topped out at recall@10 0.855 (pgvector 0.952). Simulated on the tune queries, the asymmetric
 * score alone takes the candidates' recall at m=200 from 0.84 to 0.98 with the same 32 bytes.
 */
#include "postgres.h"

#include <math.h>

#include "catalog/pg_type.h"
#include "common/pg_prng.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "storage/dsm_registry.h"
#include "storage/ipc.h"
#include "storage/lwlock.h"
#include "utils/dsa.h"
#include "utils/array.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "utils/tuplestore.h"
#include "utils/varlena.h"
#include "catalog/pg_collation.h"
#include "utils/varbit.h"

PG_MODULE_MAGIC;

#define CB 32					/* bytes in a 256-bit code */
#define HB 32					/* bytes in a text hash (sha256) */
#define PER_LIST 64				/* k-means sample: readings per list */
#define SOAR_CAND 8				/* second-list candidates: the nearest lists after the first */
#define SOAR_LAMBDA 1.0f

static inline int
ham256(const uint8 *a, const uint8 *b)
{
	uint64		x[4], y[4];

	memcpy(x, a, CB);
	memcpy(y, b, CB);
	return __builtin_popcountll(x[0] ^ y[0]) + __builtin_popcountll(x[1] ^ y[1]) +
		__builtin_popcountll(x[2] ^ y[2]) + __builtin_popcountll(x[3] ^ y[3]);
}

static const uint8 *
code256_bytes(Datum d)
{
	VarBit	   *vb = DatumGetVarBitP(d);

	if (VARBITLEN(vb) != 256)
		elog(ERROR, "phasevec ivf: a code256 of %d bits", VARBITLEN(vb));
	return VARBITS(vb);
}

static inline float
dotf(const float *a, const float *b, int dims)
{
	float		s[8] = {0, 0, 0, 0, 0, 0, 0, 0};
	int			i = 0;

	/* eight partial sums: the compiler may not reassociate one sum, it can vectorize eight */
	for (; i + 8 <= dims; i += 8)
		for (int t = 0; t < 8; t++)
			s[t] += a[i + t] * b[i + t];
	for (; i < dims; i++)
		s[0] += a[i] * b[i];
	return ((s[0] + s[1]) + (s[2] + s[3])) + ((s[4] + s[5]) + (s[6] + s[7]));
}

/* the int8 code of reading i as a unit float vector */
static void
unit_of(const int8 *c, int dims, float *out)
{
	float		nn = 0;

	for (int i = 0; i < dims; i++)
	{
		out[i] = (float) c[i];
		nn += out[i] * out[i];
	}
	nn = nn > 0 ? 1.0f / sqrtf(nn) : 0;
	for (int i = 0; i < dims; i++)
		out[i] *= nn;
}

static void
normalize(float *v, int dims)
{
	float		nn = sqrtf(dotf(v, v, dims));

	if (nn > 0)
		for (int i = 0; i < dims; i++)
			v[i] /= nn;
}

/* ------------------------------------------------------------------------------------ build -- */

static bool have_added(void);

PG_FUNCTION_INFO_V1(phasevec_ivf_build);
Datum
phasevec_ivf_build(PG_FUNCTION_ARGS)
{
	int32		watch = PG_GETARG_INT32(0);
	int32		reader = PG_GETARG_INT32(1);
	int32		dims = PG_GETARG_INT32(2);
	int32		k = PG_GETARG_INT32(3);
	int32		iters = PG_GETARG_INT32(4);
	int32		nsample = PG_GETARG_INT32(5);
	bool		soar = PG_GETARG_BOOL(6);
	Oid			at[2] = {INT4OID, INT4OID};
	Datum		av[2] = {Int32GetDatum(watch), Int32GetDatum(reader)};
	Portal		portal;
	size_t		cap = 1 << 16, n = 0, kcap = 1 << 20, klen = 0, ns;
	uint8	   *c256, *hash;
	int8	   *c8;
	char	   *kbuf;
	size_t	   *koff;
	float	   *cents, *gram = NULL, *x, *dot;
	int		   *a1, *a2, *sizes, *ssizes, *start, *sstart, *cnt, *order, *sorder;
	pg_prng_state prng;
	SPIPlanPtr	ins;
	Oid			it[12] = {INT4OID, INT4OID, INT4OID, BYTEAOID, BYTEAOID, BYTEAOID, BYTEAOID, BYTEAOID, BYTEAOID,
		INT4OID, BYTEAOID, BYTEAOID};

	if (k < 1 || dims < 256)
		elog(ERROR, "phasevec ivf: k >= 1 and dims >= 256");
	SPI_connect();
	c256 = MemoryContextAllocHuge(CurrentMemoryContext, cap * CB);
	c8 = MemoryContextAllocHuge(CurrentMemoryContext, cap * dims);
	hash = MemoryContextAllocHuge(CurrentMemoryContext, cap * HB);
	koff = MemoryContextAllocHuge(CurrentMemoryContext, (cap + 1) * sizeof(size_t));
	kbuf = MemoryContextAllocHuge(CurrentMemoryContext, kcap);

	portal = SPI_cursor_open_with_args(NULL,
									   "SELECT key, text_hash, code256, code FROM phasevec.readings "
									   "WHERE watch = $1 AND reader = $2 AND failed IS NULL AND code256 IS NOT NULL",
									   2, at, av, NULL, true, 0);
	for (;;)
	{
		SPI_cursor_fetch(portal, true, 10000);
		if (SPI_processed == 0)
			break;
		for (uint64 r = 0; r < SPI_processed; r++)
		{
			HeapTuple	tup = SPI_tuptable->vals[r];
			TupleDesc	td = SPI_tuptable->tupdesc;
			bool		isnull;
			text	   *key = DatumGetTextPP(SPI_getbinval(tup, td, 1, &isnull));
			bytea	   *h = DatumGetByteaPP(SPI_getbinval(tup, td, 2, &isnull));
			Datum		cd = SPI_getbinval(tup, td, 4, &isnull);
			size_t		kl = VARSIZE_ANY_EXHDR(key);

			if (n == cap)
			{
				cap *= 2;
				c256 = repalloc_huge(c256, cap * CB);
				c8 = repalloc_huge(c8, cap * dims);
				hash = repalloc_huge(hash, cap * HB);
				koff = repalloc_huge(koff, (cap + 1) * sizeof(size_t));
			}
			if (VARSIZE_ANY_EXHDR(h) != HB)
				elog(ERROR, "phasevec ivf: a text hash of %zu bytes", (size_t) VARSIZE_ANY_EXHDR(h));
			memcpy(hash + n * HB, VARDATA_ANY(h), HB);
			memcpy(c256 + n * CB, code256_bytes(SPI_getbinval(tup, td, 3, &isnull)), CB);
			{
				ArrayType  *a = DatumGetArrayTypeP(cd);
				const int16 *p;

				if (ARR_NDIM(a) != 1 || ARR_HASNULL(a) || ARR_DIMS(a)[0] != dims)
					elog(ERROR, "phasevec ivf: an int8 code that is not %d plain dimensions", dims);
				p = (const int16 *) ARR_DATA_PTR(a);
				for (int i = 0; i < dims; i++)
					c8[n * dims + i] = (int8) p[i];
				if ((Pointer) a != DatumGetPointer(cd))
					pfree(a);
			}
			while (klen + kl > kcap)
			{
				kcap *= 2;
				kbuf = repalloc_huge(kbuf, kcap);
			}
			koff[n] = klen;
			memcpy(kbuf + klen, VARDATA_ANY(key), kl);
			klen += kl;
			n++;
		}
		SPI_freetuptable(SPI_tuptable);
		CHECK_FOR_INTERRUPTS();
	}
	koff[n] = klen;
	SPI_cursor_close(portal);
	if (n == 0)
		elog(ERROR, "phasevec ivf: watch %d has no readings to index", watch);
	if (n > (size_t) PG_INT32_MAX)
		elog(ERROR, "phasevec ivf: more than 2^31 readings");
	if ((size_t) k > n)
		k = (int) n;

	/* spherical k-means on a sample: seeds = k random readings, empties reseeded */
	pg_prng_seed(&prng, 42);
	ns = Min(n, (size_t) k * PER_LIST);
	if (nsample >= k && (size_t) nsample < ns)
		ns = nsample;
	cents = MemoryContextAllocHuge(CurrentMemoryContext, sizeof(float) * k * dims);
	{
		float	   *xs = MemoryContextAllocHuge(CurrentMemoryContext, sizeof(float) * ns * dims);
		float	   *sum = MemoryContextAllocHuge(CurrentMemoryContext, sizeof(float) * k * dims);
		int		   *csz = palloc(sizeof(int) * k);
		size_t	   *smp = MemoryContextAllocHuge(CurrentMemoryContext, sizeof(size_t) * n);

		for (size_t i = 0; i < n; i++)
			smp[i] = i;
		for (size_t i = 0; i < ns; i++)		/* partial Fisher-Yates: the first ns are a sample */
		{
			size_t		j = (size_t) pg_prng_uint64_range(&prng, i, n - 1), t = smp[i];

			smp[i] = smp[j];
			smp[j] = t;
		}
		for (size_t i = 0; i < ns; i++)
			unit_of(c8 + smp[i] * dims, dims, xs + i * dims);
		for (int j = 0; j < k; j++)
			memcpy(cents + (size_t) j * dims, xs + (size_t) j * dims, sizeof(float) * dims);
		for (int it2 = 0; it2 < iters; it2++)
		{
			memset(sum, 0, sizeof(float) * k * dims);
			memset(csz, 0, sizeof(int) * k);
			for (size_t i = 0; i < ns; i++)
			{
				const float *xi = xs + i * dims;
				int			best = 0;
				float		bd = -INFINITY;

				for (int j = 0; j < k; j++)
				{
					float		d = dotf(xi, cents + (size_t) j * dims, dims);

					if (d > bd)
					{
						bd = d;
						best = j;
					}
				}
				csz[best]++;
				for (int d = 0; d < dims; d++)
					sum[(size_t) best * dims + d] += xi[d];
			}
			for (int j = 0; j < k; j++)
			{
				float	   *ct = cents + (size_t) j * dims;

				if (csz[j] == 0)
					memcpy(ct, xs + (size_t) pg_prng_uint64_range(&prng, 0, ns - 1) * dims, sizeof(float) * dims);
				else
				{
					memcpy(ct, sum + (size_t) j * dims, sizeof(float) * dims);
					normalize(ct, dims);
				}
			}
			CHECK_FOR_INTERRUPTS();
		}
		pfree(xs);
		pfree(sum);
		pfree(smp);
	}
	if (soar)
	{
		gram = MemoryContextAllocHuge(CurrentMemoryContext, sizeof(float) * k * k);
		for (int i = 0; i < k; i++)
			for (int j = 0; j < k; j++)
				gram[(size_t) i * k + j] = dotf(cents + (size_t) i * dims, cents + (size_t) j * dims, dims);
	}

	/*
	 * Every reading: its nearest list, and (SOAR) a second one. With x and the centroids unit
	 * vectors and r = x - c1: ||x - cj||^2 = 2 - 2 x.cj, and r.(x - cj) = (1 - x.c1) - (x.cj - c1.cj).
	 * The second list minimizes ||x - cj||^2 + lambda (r/|r| . (x - cj))^2 over the SOAR_CAND
	 * nearest lists after the first: a list whose residual does not repeat the first one's.
	 */
	a1 = MemoryContextAllocHuge(CurrentMemoryContext, sizeof(int) * n);
	a2 = MemoryContextAllocHuge(CurrentMemoryContext, sizeof(int) * n);
	sizes = palloc0(sizeof(int) * k);
	ssizes = palloc0(sizeof(int) * k);
	x = palloc(sizeof(float) * dims);
	dot = palloc(sizeof(float) * k);
	for (size_t i = 0; i < n; i++)
	{
		int			best = 0;

		unit_of(c8 + i * dims, dims, x);
		for (int j = 0; j < k; j++)
		{
			dot[j] = dotf(x, cents + (size_t) j * dims, dims);
			if (dot[j] > dot[best])
				best = j;
		}
		a1[i] = best;
		sizes[best]++;
		a2[i] = -1;
		if (soar && k > 1)
		{
			int			top[SOAR_CAND];
			int			nt = 0;
			float		rr = 2.0f - 2.0f * dot[best];

			for (int j = 0; j < k; j++)		/* the SOAR_CAND nearest lists other than best */
			{
				int			p;

				if (j == best)
					continue;
				if (nt == SOAR_CAND && dot[j] <= dot[top[nt - 1]])
					continue;
				p = nt < SOAR_CAND ? nt++ : nt - 1;
				while (p > 0 && dot[top[p - 1]] < dot[j])
				{
					top[p] = top[p - 1];
					p--;
				}
				top[p] = j;
			}
			if (rr > 1e-12f)
			{
				float		bp = INFINITY, rx = 1.0f - dot[best], inv = 1.0f / sqrtf(rr);

				for (int t = 0; t < nt; t++)
				{
					int			j = top[t];
					float		proj = (rx - (dot[j] - gram[(size_t) best * k + j])) * inv;
					float		pen = 2.0f - 2.0f * dot[j] + SOAR_LAMBDA * proj * proj;

					if (pen < bp)
					{
						bp = pen;
						a2[i] = j;
					}
				}
				ssizes[a2[i]]++;
			}
		}
		if ((i & 0xffff) == 0)
			CHECK_FOR_INTERRUPTS();
	}
	start = palloc(sizeof(int) * (k + 1));
	sstart = palloc(sizeof(int) * (k + 1));
	start[0] = sstart[0] = 0;
	for (int j = 0; j < k; j++)
	{
		start[j + 1] = start[j] + sizes[j];
		sstart[j + 1] = sstart[j] + ssizes[j];
	}
	order = MemoryContextAllocHuge(CurrentMemoryContext, sizeof(int) * (size_t) (start[k] ? start[k] : 1));
	sorder = MemoryContextAllocHuge(CurrentMemoryContext, sizeof(int) * (size_t) (sstart[k] ? sstart[k] : 1));
	cnt = palloc0(sizeof(int) * k);
	for (size_t i = 0; i < n; i++)
		order[start[a1[i]] + cnt[a1[i]]++] = (int) i;
	memset(cnt, 0, sizeof(int) * k);
	for (size_t i = 0; i < n; i++)
		if (a2[i] >= 0)
			sorder[sstart[a2[i]] + cnt[a2[i]]++] = (int) i;

	SPI_execute_with_args("DELETE FROM phasevec.ivf_lists WHERE watch = $1", 1, at, av, NULL, false, 0);
	if (have_added())
		SPI_execute_with_args("DELETE FROM phasevec.ivf_added WHERE watch = $1", 1, at, av, NULL, false, 0);
	SPI_execute_with_args("DELETE FROM phasevec.ivf_cents WHERE watch = $1", 1, at, av, NULL, false, 0);
	/*
	 * 0.10.0 passes keep_delta: phasevec.ivf_build empties only the delta rows this build could see.
	 * Called by the 0.8.0/0.9.0 SQL (seven arguments) the build empties it all, as it always did.
	 */
	if (!(PG_NARGS() > 7 && PG_GETARG_BOOL(7)))
		SPI_execute_with_args("DELETE FROM phasevec.ivf_dirty WHERE watch = $1", 1, at, av, NULL, false, 0);
	{
		Oid			ct[7] = {INT4OID, INT4OID, INT4OID, INT4OID, INT4OID, BOOLOID, BYTEAOID};
		bytea	   *cb = MemoryContextAllocHuge(CurrentMemoryContext, VARHDRSZ + sizeof(float) * k * dims);
		Datum		cv[7];

		SET_VARSIZE(cb, VARHDRSZ + sizeof(float) * k * dims);
		memcpy(VARDATA(cb), cents, sizeof(float) * k * dims);
		cv[0] = Int32GetDatum(watch);
		cv[1] = Int32GetDatum(reader);
		cv[2] = Int32GetDatum(k);
		cv[3] = Int32GetDatum(dims);
		cv[4] = Int32GetDatum((int32) n);
		cv[5] = BoolGetDatum(soar);
		cv[6] = PointerGetDatum(cb);
		SPI_execute_with_args("INSERT INTO phasevec.ivf_cents (watch, reader, k, dims, n, soar, c) VALUES ($1, $2, $3, $4, $5, $6, $7)",
							  7, ct, cv, NULL, false, 0);
	}
	ins = SPI_prepare("INSERT INTO phasevec.ivf_lists (watch, list, n, docs, keys, koff, hashes, c256, c8, sn, sdocs, sc256) "
					  "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)", 12, it);
	{
		MemoryContext per = AllocSetContextCreate(CurrentMemoryContext, "phasevec ivf list", ALLOCSET_DEFAULT_SIZES);

		for (int j = 0; j < k; j++)
		{
			MemoryContext old = MemoryContextSwitchTo(per);
			int			sz = start[j + 1] - start[j], ssz = sstart[j + 1] - sstart[j];
			size_t		kb = 0;
			bytea	   *bd, *bk, *bo, *bh, *bc, *b8, *sd, *sc;
			int32	   *docs, *off, *sdocs;
			Datum		v[12];

			for (int t = 0; t < sz; t++)
			{
				size_t		i = order[start[j] + t];

				kb += koff[i + 1] - koff[i];
			}
			bd = palloc(VARHDRSZ + sizeof(int32) * sz);
			bk = palloc(VARHDRSZ + kb);
			bo = palloc(VARHDRSZ + sizeof(int32) * (sz + 1));
			bh = palloc(VARHDRSZ + (size_t) sz * HB);
			bc = palloc(VARHDRSZ + (size_t) sz * CB);
			b8 = palloc(VARHDRSZ + (size_t) sz * dims);
			SET_VARSIZE(bd, VARHDRSZ + sizeof(int32) * sz);
			SET_VARSIZE(bk, VARHDRSZ + kb);
			SET_VARSIZE(bo, VARHDRSZ + sizeof(int32) * (sz + 1));
			SET_VARSIZE(bh, VARHDRSZ + (size_t) sz * HB);
			SET_VARSIZE(bc, VARHDRSZ + (size_t) sz * CB);
			SET_VARSIZE(b8, VARHDRSZ + (size_t) sz * dims);
			docs = (int32 *) VARDATA(bd);
			off = (int32 *) VARDATA(bo);
			kb = 0;
			for (int t = 0; t < sz; t++)
			{
				size_t		i = order[start[j] + t];
				size_t		kl = koff[i + 1] - koff[i];

				docs[t] = (int32) i;
				off[t] = (int32) kb;
				memcpy(VARDATA(bk) + kb, kbuf + koff[i], kl);
				kb += kl;
				memcpy(VARDATA(bh) + (size_t) t * HB, hash + i * HB, HB);
				memcpy(VARDATA(bc) + (size_t) t * CB, c256 + i * CB, CB);
				memcpy(VARDATA(b8) + (size_t) t * dims, c8 + i * dims, dims);
			}
			off[sz] = (int32) kb;
			sd = palloc(VARHDRSZ + sizeof(int32) * ssz);
			sc = palloc(VARHDRSZ + (size_t) ssz * CB);
			SET_VARSIZE(sd, VARHDRSZ + sizeof(int32) * ssz);
			SET_VARSIZE(sc, VARHDRSZ + (size_t) ssz * CB);
			sdocs = (int32 *) VARDATA(sd);
			for (int t = 0; t < ssz; t++)
			{
				size_t		i = sorder[sstart[j] + t];

				sdocs[t] = (int32) i;
				memcpy(VARDATA(sc) + (size_t) t * CB, c256 + i * CB, CB);
			}
			v[0] = Int32GetDatum(watch);
			v[1] = Int32GetDatum(j);
			v[2] = Int32GetDatum(sz);
			v[3] = PointerGetDatum(bd);
			v[4] = PointerGetDatum(bk);
			v[5] = PointerGetDatum(bo);
			v[6] = PointerGetDatum(bh);
			v[7] = PointerGetDatum(bc);
			v[8] = PointerGetDatum(b8);
			v[9] = Int32GetDatum(ssz);
			v[10] = PointerGetDatum(sd);
			v[11] = PointerGetDatum(sc);
			SPI_execute_plan(ins, v, NULL, false, 0);
			MemoryContextSwitchTo(old);
			MemoryContextReset(per);
			CHECK_FOR_INTERRUPTS();
		}
	}
	SPI_finish();
	PG_RETURN_INT32(k);
}

/* ------------------------------------------------------------------------------------ sweep -- */

/*
 * The index, read once per backend and kept: per list the ordinals and 256-bit codes it sweeps (in
 * list order, SOAR copies included); per reading ONCE its int8 code, text hash, 256-bit code and key.
 * It is a copy of phasevec.ivf_cents / phasevec.ivf_lists, which change only when phasevec.ivf_build rewrites them: the cache is
 * keyed by the phasevec.ivf_cents row's xmin and reloaded when it moves. It holds nothing about freshness:
 * find_v2 still validates every candidate against phasevec.sources in the caller's snapshot.
 */
typedef struct BIndex
{
	MemoryContext cx;
	int32		watch;
	TransactionId xmin;
	int			k, dims, n;
	float	   *cents;			/* k x dims */
	int		   *lstart;			/* k + 1: where each list starts among the entries */
	int32	   *edoc;			/* entries: the reading's ordinal */
	uint8	   *ec256;			/* entries: its 256-bit code (swept in list order) */
	int8	   *c8;				/* n x dims */
	uint8	   *c256;			/* n x 32 */
	uint8	   *hash;			/* n x 32 */
	char	   *keys;
	int64	   *koff;			/* n + 1 */
	bool		shared;			/* the arrays point into the shared copy (0.10.0), held by this query */
	int			slot;
} BIndex;

static BIndex g_ix = {NULL, 0, InvalidTransactionId, 0, 0, 0};

/* phasevec.ivf_added exists from 0.10.0 on: an older SQL with this library has no chunks. */
static bool
have_added(void)
{
	SPI_execute("SELECT to_regclass('phasevec.ivf_added') IS NOT NULL", true, 1);
	return SPI_processed == 1 && DatumGetBool(SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &(bool){false}));
}

static void
load_index(int32 watch, TransactionId xmin, int k, int dims, int n, bytea *cb)
{
	Oid			at[1] = {INT4OID};
	Datum		av[1] = {Int32GetDatum(watch)};
	MemoryContext old;
	BIndex		ix = {0};
	uint8	   *have;
	int64		ne = 0, kcap = 1 << 20, klen = 0;
	int		   *lsize, *bsize, *fill;
	bool		added;
	char	   *ktmp;
	int64	   *kpos;
	int32	   *klen_of;

	if (g_ix.cx)
		MemoryContextDelete(g_ix.cx);
	g_ix.cx = NULL;
	ix.cx = AllocSetContextCreate(TopMemoryContext, "phasevec ivf index", ALLOCSET_DEFAULT_SIZES);
	old = MemoryContextSwitchTo(ix.cx);
	ix.watch = watch;
	ix.xmin = xmin;
	ix.k = k;
	ix.dims = dims;
	ix.n = n;
	ix.cents = MemoryContextAllocHuge(ix.cx, sizeof(float) * k * dims);
	memcpy(ix.cents, VARDATA_ANY(cb), sizeof(float) * k * dims);
	ix.c8 = MemoryContextAllocHuge(ix.cx, (size_t) n * dims);
	ix.c256 = MemoryContextAllocHuge(ix.cx, (size_t) n * CB);
	ix.hash = MemoryContextAllocHuge(ix.cx, (size_t) n * HB);
	ix.lstart = palloc0(sizeof(int) * (k + 1));
	have = MemoryContextAllocHuge(ix.cx, (size_t) n);
	memset(have, 0, n);
	kpos = MemoryContextAllocHuge(ix.cx, sizeof(int64) * n);
	klen_of = MemoryContextAllocHuge(ix.cx, sizeof(int32) * n);
	ktmp = MemoryContextAllocHuge(ix.cx, kcap);
	lsize = palloc0(sizeof(int) * k);
	MemoryContextSwitchTo(old);

	/* sizes first, so the entries are laid out in list order */
	SPI_execute_with_args("SELECT list, n + sn FROM phasevec.ivf_lists WHERE watch = $1", 1, at, av, NULL, true, 0);
	for (uint64 r = 0; r < SPI_processed; r++)
	{
		bool		isnull;
		int			l = DatumGetInt32(SPI_getbinval(SPI_tuptable->vals[r], SPI_tuptable->tupdesc, 1, &isnull));

		if (l < 0 || l >= k)
			elog(ERROR, "phasevec ivf: list %d outside 0..%d", l, k - 1);
		lsize[l] = DatumGetInt32(SPI_getbinval(SPI_tuptable->vals[r], SPI_tuptable->tupdesc, 2, &isnull));
	}
	/* the chunks absorbed since the build (0.10.0) add to their lists */
	bsize = palloc(sizeof(int) * k);
	memcpy(bsize, lsize, sizeof(int) * k);
	added = have_added();
	if (added)
	{
		SPI_execute_with_args("SELECT list, sum(n + sn)::int FROM phasevec.ivf_added WHERE watch = $1 GROUP BY list",
							  1, at, av, NULL, true, 0);
		for (uint64 r = 0; r < SPI_processed; r++)
		{
			bool		isnull;
			int			l = DatumGetInt32(SPI_getbinval(SPI_tuptable->vals[r], SPI_tuptable->tupdesc, 1, &isnull));

			if (l < 0 || l >= k)
				elog(ERROR, "phasevec ivf: list %d outside 0..%d", l, k - 1);
			lsize[l] += DatumGetInt32(SPI_getbinval(SPI_tuptable->vals[r], SPI_tuptable->tupdesc, 2, &isnull));
		}
	}
	for (int j = 0; j < k; j++)
		ix.lstart[j + 1] = ix.lstart[j] + lsize[j];
	ne = ix.lstart[k];
	fill = palloc(sizeof(int) * k);
	for (int j = 0; j < k; j++)
		fill[j] = ix.lstart[j] + bsize[j];
	ix.edoc = MemoryContextAllocHuge(ix.cx, sizeof(int32) * (ne ? ne : 1));
	ix.ec256 = MemoryContextAllocHuge(ix.cx, (size_t) (ne ? ne : 1) * CB);

	/* then each list, one at a time (a list is a few hundred kB once detoasted) */
	for (int j = 0; j < k; j++)
	{
		Datum		lv[2] = {Int32GetDatum(watch), Int32GetDatum(j)};
		Oid			lt[2] = {INT4OID, INT4OID};
		HeapTuple	tup;
		TupleDesc	td;
		bool		isnull;
		const int32 *docs, *koff, *sdocs;
		const char *keys;
		const uint8 *hashes, *c256, *sc256;
		const int8 *c8;
		int			sz, ssz, e0 = ix.lstart[j];

		if (bsize[j] == 0)
			continue;
		SPI_execute_with_args("SELECT n, docs, keys, koff, hashes, c256, c8, sn, sdocs, sc256 FROM phasevec.ivf_lists "
							  "WHERE watch = $1 AND list = $2",
							  2, lt, lv, NULL, true, 1);
		if (SPI_processed != 1)
			elog(ERROR, "phasevec ivf: list %d of watch %d vanished while loading", j, watch);
		tup = SPI_tuptable->vals[0];
		td = SPI_tuptable->tupdesc;
		sz = DatumGetInt32(SPI_getbinval(tup, td, 1, &isnull));
		ssz = DatumGetInt32(SPI_getbinval(tup, td, 8, &isnull));
		if (sz + ssz != bsize[j])
			elog(ERROR, "phasevec ivf: list %d changed while loading", j);
		docs = (const int32 *) VARDATA_ANY(DatumGetByteaPP(SPI_getbinval(tup, td, 2, &isnull)));
		keys = VARDATA_ANY(DatumGetByteaPP(SPI_getbinval(tup, td, 3, &isnull)));
		koff = (const int32 *) VARDATA_ANY(DatumGetByteaPP(SPI_getbinval(tup, td, 4, &isnull)));
		hashes = (const uint8 *) VARDATA_ANY(DatumGetByteaPP(SPI_getbinval(tup, td, 5, &isnull)));
		c256 = (const uint8 *) VARDATA_ANY(DatumGetByteaPP(SPI_getbinval(tup, td, 6, &isnull)));
		c8 = (const int8 *) VARDATA_ANY(DatumGetByteaPP(SPI_getbinval(tup, td, 7, &isnull)));
		sdocs = (const int32 *) VARDATA_ANY(DatumGetByteaPP(SPI_getbinval(tup, td, 9, &isnull)));
		sc256 = (const uint8 *) VARDATA_ANY(DatumGetByteaPP(SPI_getbinval(tup, td, 10, &isnull)));
		for (int t = 0; t < ssz; t++)		/* the SOAR copies: ordinal and code, after the list's own */
		{
			if (sdocs[t] < 0 || sdocs[t] >= n)
				elog(ERROR, "phasevec ivf: a reading ordinal %d outside 0..%d", sdocs[t], n - 1);
			ix.edoc[e0 + sz + t] = sdocs[t];
			memcpy(ix.ec256 + (size_t) (e0 + sz + t) * CB, sc256 + (size_t) t * CB, CB);
		}
		for (int t = 0; t < sz; t++)
		{
			int32		d = docs[t];

			if (d < 0 || d >= n)
				elog(ERROR, "phasevec ivf: a reading ordinal %d outside 0..%d", d, n - 1);
			ix.edoc[e0 + t] = d;
			memcpy(ix.ec256 + (size_t) (e0 + t) * CB, c256 + (size_t) t * CB, CB);
			if (have[d])
				elog(ERROR, "phasevec ivf: reading %d is the first list of two", d);
			{
				int32		kl = koff[t + 1] - koff[t];

				have[d] = 1;
				memcpy(ix.c8 + (size_t) d * dims, c8 + (size_t) t * dims, dims);
				memcpy(ix.c256 + (size_t) d * CB, c256 + (size_t) t * CB, CB);
				memcpy(ix.hash + (size_t) d * HB, hashes + (size_t) t * HB, HB);
				while (klen + kl > kcap)
				{
					kcap *= 2;
					ktmp = repalloc_huge(ktmp, kcap);
				}
				memcpy(ktmp + klen, keys + koff[t], kl);
				kpos[d] = klen;
				klen_of[d] = kl;
				klen += kl;
			}
		}
		SPI_freetuptable(SPI_tuptable);
		CHECK_FOR_INTERRUPTS();
	}
	/* the chunks: their own readings (full rows) and SOAR copies, after each list's base entries */
	if (added)
	{
		Portal		pc = SPI_cursor_open_with_args(NULL,
												   "SELECT list, n, docs, keys, koff, hashes, c256, c8, sn, sdocs, sc256 "
												   "FROM phasevec.ivf_added WHERE watch = $1 ORDER BY seq", 1, at, av, NULL, true, 0);

		for (;;)
		{
			SPI_cursor_fetch(pc, true, 100);
			if (SPI_processed == 0)
				break;
			for (uint64 r = 0; r < SPI_processed; r++)
			{
				HeapTuple	tup = SPI_tuptable->vals[r];
				TupleDesc	td = SPI_tuptable->tupdesc;
				bool		isnull;
				int			l = DatumGetInt32(SPI_getbinval(tup, td, 1, &isnull));
				int			sz = DatumGetInt32(SPI_getbinval(tup, td, 2, &isnull));
				const int32 *docs = (const int32 *) VARDATA_ANY(DatumGetByteaPP(SPI_getbinval(tup, td, 3, &isnull)));
				const char *keys = VARDATA_ANY(DatumGetByteaPP(SPI_getbinval(tup, td, 4, &isnull)));
				const int32 *koff = (const int32 *) VARDATA_ANY(DatumGetByteaPP(SPI_getbinval(tup, td, 5, &isnull)));
				const uint8 *hashes = (const uint8 *) VARDATA_ANY(DatumGetByteaPP(SPI_getbinval(tup, td, 6, &isnull)));
				const uint8 *c256 = (const uint8 *) VARDATA_ANY(DatumGetByteaPP(SPI_getbinval(tup, td, 7, &isnull)));
				const int8 *c8 = (const int8 *) VARDATA_ANY(DatumGetByteaPP(SPI_getbinval(tup, td, 8, &isnull)));
				int			ssz = DatumGetInt32(SPI_getbinval(tup, td, 9, &isnull));
				const int32 *sdocs = (const int32 *) VARDATA_ANY(DatumGetByteaPP(SPI_getbinval(tup, td, 10, &isnull)));
				const uint8 *sc256 = (const uint8 *) VARDATA_ANY(DatumGetByteaPP(SPI_getbinval(tup, td, 11, &isnull)));

				if (l < 0 || l >= k || fill[l] + sz + ssz > ix.lstart[l + 1])
					elog(ERROR, "phasevec ivf: a chunk of list %d changed while loading", l);
				for (int t = 0; t < sz; t++)
				{
					int32		d = docs[t];
					int32		kl = koff[t + 1] - koff[t];

					if (d < 0 || d >= n || have[d])
						elog(ERROR, "phasevec ivf: an absorbed reading ordinal %d is out of place", d);
					ix.edoc[fill[l]] = d;
					memcpy(ix.ec256 + (size_t) fill[l] * CB, c256 + (size_t) t * CB, CB);
					fill[l]++;
					have[d] = 1;
					memcpy(ix.c8 + (size_t) d * dims, c8 + (size_t) t * dims, dims);
					memcpy(ix.c256 + (size_t) d * CB, c256 + (size_t) t * CB, CB);
					memcpy(ix.hash + (size_t) d * HB, hashes + (size_t) t * HB, HB);
					while (klen + kl > kcap)
					{
						kcap *= 2;
						ktmp = repalloc_huge(ktmp, kcap);
					}
					memcpy(ktmp + klen, keys + koff[t], kl);
					kpos[d] = klen;
					klen_of[d] = kl;
					klen += kl;
				}
				for (int t = 0; t < ssz; t++)
				{
					if (sdocs[t] < 0 || sdocs[t] >= n)
						elog(ERROR, "phasevec ivf: a reading ordinal %d outside 0..%d", sdocs[t], n - 1);
					ix.edoc[fill[l]] = sdocs[t];
					memcpy(ix.ec256 + (size_t) fill[l] * CB, sc256 + (size_t) t * CB, CB);
					fill[l]++;
				}
			}
			SPI_freetuptable(SPI_tuptable);
			CHECK_FOR_INTERRUPTS();
		}
		SPI_cursor_close(pc);
	}
	/* keys by ordinal, so a reading's key is keys[koff[d] .. koff[d + 1]) */
	ix.keys = MemoryContextAllocHuge(ix.cx, klen ? klen : 1);
	ix.koff = MemoryContextAllocHuge(ix.cx, sizeof(int64) * (n + 1));
	klen = 0;
	for (int d = 0; d < n; d++)
	{
		if (!have[d])
			elog(ERROR, "phasevec ivf: reading %d is in no list", d);
		ix.koff[d] = klen;
		memcpy(ix.keys + klen, ktmp + kpos[d], klen_of[d]);
		klen += klen_of[d];
	}
	ix.koff[n] = klen;
	pfree(ktmp);
	pfree(kpos);
	pfree(klen_of);
	pfree(have);
	g_ix = ix;
}


/* ------------------------------------------------------------------------- the shared copy -- */

/*
 * 0.10.0: the index, once loaded by one backend, is published in a named DSA area (no
 * shared_preload_libraries needed) and every other backend of the cluster sweeps that copy in place.
 * Measured before (sql/171 ycache_frio): the first find_ivf of a new connection paid 39-43 ms loading
 * its own copy at 100k, and every connection kept ~40 MB of it. A copy is keyed by database, watch and
 * the xmin of its phasevec.ivf_cents row (a build or an absorb moves it); a query holds a reference
 * while it sweeps, and a replaced copy is freed when its last reader lets go. Without room (no DSA
 * memory, every slot in use) the backend keeps its private copy, as before 0.10.0.
 * phasevec.shared_ivf_cache = off turns it off for the session.
 */
extern bool phasevec_shared_ivf_cache;
bool		phasevec_shared_ivf_cache = true;

#define SLOTS 32

typedef struct Slot
{
	bool		used, dead;
	Oid			db;
	int32		watch;
	TransactionId xmin;
	dsa_pointer blob;
	Size		size;
	int			refs;
	uint64		tick;
} Slot;

typedef struct Ctl
{
	LWLock		lock;
	uint64		tick;
	Slot		slot[SLOTS];
} Ctl;

typedef struct Blob
{
	int32		k, dims, n;
	int64		ne, klen;
	Size		cents, lstart, edoc, ec256, c8, c256, hash, koff, keys;
} Blob;

static Ctl *g_ctl = NULL;
static dsa_area *g_area = NULL;

static void
ctl_init(void *ptr, void *arg)
{
	Ctl		   *ctl = ptr;

	memset(ctl, 0, sizeof(Ctl));
	LWLockInitialize(&ctl->lock, LWLockNewTrancheId("phasevec_ivf_cache"));
}

static void release_index(void);

static void
release_at_exit(int code, Datum arg)
{
	release_index();
}

static bool
attach_shared(void)
{
	bool		found;

	if (g_ctl)
		return true;
	g_ctl = GetNamedDSMSegment("phasevec_ivf_cache", sizeof(Ctl), ctl_init, &found, NULL);
	g_area = GetNamedDSA("phasevec_ivf_cache_dsa", &found);
	before_shmem_exit(release_at_exit, (Datum) 0);
	return true;
}

static void
free_slot(Slot *sl)
{
	if (sl->blob != InvalidDsaPointer)
		dsa_free(g_area, sl->blob);
	memset(sl, 0, sizeof(Slot));
	sl->blob = InvalidDsaPointer;
}

/* The query is done with the shared copy it swept (also on error, and at backend exit). */
static void
release_index(void)
{
	Slot	   *sl;

	if (!g_ix.shared || !g_ctl)
		return;
	LWLockAcquire(&g_ctl->lock, LW_EXCLUSIVE);
	sl = &g_ctl->slot[g_ix.slot];
	if (sl->refs > 0)
		sl->refs--;
	if (sl->dead && sl->refs == 0)
		free_slot(sl);
	LWLockRelease(&g_ctl->lock);
	g_ix.shared = false;
	g_ix.watch = 0;
	g_ix.xmin = InvalidTransactionId;
}

/* The shared copy of (this database, watch, xmin), if there is one: g_ix points into it, held. */
static bool
use_shared(int32 watch, TransactionId xmin)
{
	int			found = -1;
	char	   *b;
	Blob	   *h;

	LWLockAcquire(&g_ctl->lock, LW_EXCLUSIVE);
	for (int i = 0; i < SLOTS; i++)
	{
		Slot	   *sl = &g_ctl->slot[i];

		if (sl->used && !sl->dead && sl->db == MyDatabaseId && sl->watch == watch && sl->xmin == xmin)
		{
			sl->refs++;
			sl->tick = ++g_ctl->tick;
			found = i;
			break;
		}
	}
	LWLockRelease(&g_ctl->lock);
	if (found < 0)
		return false;
	if (g_ix.cx)				/* the private copy is not needed any more */
		MemoryContextDelete(g_ix.cx);
	b = dsa_get_address(g_area, g_ctl->slot[found].blob);
	h = (Blob *) b;
	g_ix.cx = NULL;
	g_ix.watch = watch;
	g_ix.xmin = xmin;
	g_ix.k = h->k;
	g_ix.dims = h->dims;
	g_ix.n = h->n;
	g_ix.cents = (float *) (b + h->cents);
	g_ix.lstart = (int *) (b + h->lstart);
	g_ix.edoc = (int32 *) (b + h->edoc);
	g_ix.ec256 = (uint8 *) (b + h->ec256);
	g_ix.c8 = (int8 *) (b + h->c8);
	g_ix.c256 = (uint8 *) (b + h->c256);
	g_ix.hash = (uint8 *) (b + h->hash);
	g_ix.koff = (int64 *) (b + h->koff);
	g_ix.keys = b + h->keys;
	g_ix.shared = true;
	g_ix.slot = found;
	return true;
}

/* Copies the private g_ix into the DSA area and publishes it; false if there was no room. */
static bool
publish_index(void)
{
	Blob		h = {0};
	Size		at = MAXALIGN(sizeof(Blob));
	dsa_pointer dp;
	char	   *b;
	int			slot = -1, lru = -1;

	h.k = g_ix.k;
	h.dims = g_ix.dims;
	h.n = g_ix.n;
	h.ne = g_ix.lstart[g_ix.k];
	h.klen = g_ix.koff[g_ix.n];
#define SECTION(f, bytes) do { h.f = at; at += MAXALIGN((Size) (bytes)); } while (0)
	SECTION(koff, sizeof(int64) * (g_ix.n + 1));
	SECTION(cents, sizeof(float) * g_ix.k * g_ix.dims);
	SECTION(lstart, sizeof(int) * (g_ix.k + 1));
	SECTION(edoc, sizeof(int32) * h.ne);
	SECTION(ec256, (Size) h.ne * CB);
	SECTION(c8, (Size) g_ix.n * g_ix.dims);
	SECTION(c256, (Size) g_ix.n * CB);
	SECTION(hash, (Size) g_ix.n * HB);
	SECTION(keys, h.klen ? h.klen : 1);
#undef SECTION
	dp = dsa_allocate_extended(g_area, at, DSA_ALLOC_HUGE | DSA_ALLOC_NO_OOM);
	if (dp == InvalidDsaPointer)
		return false;
	b = dsa_get_address(g_area, dp);
	memcpy(b, &h, sizeof(Blob));
	memcpy(b + h.koff, g_ix.koff, sizeof(int64) * (g_ix.n + 1));
	memcpy(b + h.cents, g_ix.cents, sizeof(float) * g_ix.k * g_ix.dims);
	memcpy(b + h.lstart, g_ix.lstart, sizeof(int) * (g_ix.k + 1));
	memcpy(b + h.edoc, g_ix.edoc, sizeof(int32) * h.ne);
	memcpy(b + h.ec256, g_ix.ec256, (Size) h.ne * CB);
	memcpy(b + h.c8, g_ix.c8, (Size) g_ix.n * g_ix.dims);
	memcpy(b + h.c256, g_ix.c256, (Size) g_ix.n * CB);
	memcpy(b + h.hash, g_ix.hash, (Size) g_ix.n * HB);
	memcpy(b + h.keys, g_ix.keys, h.klen);

	LWLockAcquire(&g_ctl->lock, LW_EXCLUSIVE);
	for (int i = 0; i < SLOTS; i++)
	{
		Slot	   *sl = &g_ctl->slot[i];

		if (!sl->used || sl->dead || sl->db != MyDatabaseId || sl->watch != g_ix.watch)
			continue;
		if (sl->xmin == g_ix.xmin)
		{
			/* another backend published the same copy meanwhile: keep theirs */
			LWLockRelease(&g_ctl->lock);
			dsa_free(g_area, dp);
			return true;
		}
		/* an older copy of this watch: no new reader takes it; freed when its last one lets go */
		sl->dead = true;
		if (sl->refs == 0)
			free_slot(sl);
	}
	for (int i = 0; i < SLOTS && slot < 0; i++)
		if (!g_ctl->slot[i].used)
			slot = i;
	if (slot < 0)
		for (int i = 0; i < SLOTS; i++)
			if (g_ctl->slot[i].refs == 0 && (lru < 0 || g_ctl->slot[i].tick < g_ctl->slot[lru].tick))
				lru = i;
	if (slot < 0 && lru >= 0)
	{
		free_slot(&g_ctl->slot[lru]);
		slot = lru;
	}
	if (slot < 0)
	{
		LWLockRelease(&g_ctl->lock);
		dsa_free(g_area, dp);
		return false;
	}
	g_ctl->slot[slot].used = true;
	g_ctl->slot[slot].dead = false;
	g_ctl->slot[slot].db = MyDatabaseId;
	g_ctl->slot[slot].watch = g_ix.watch;
	g_ctl->slot[slot].xmin = g_ix.xmin;
	g_ctl->slot[slot].blob = dp;
	g_ctl->slot[slot].size = at;
	g_ctl->slot[slot].refs = 0;
	g_ctl->slot[slot].tick = ++g_ctl->tick;
	LWLockRelease(&g_ctl->lock);
	return true;
}

/*
 * The index of (watch, xmin) for this query: the shared copy, or the private one. True if g_ix
 * already holds it; false if the caller must load it (load_index) and then call it again.
 */
static bool
acquire_index(int32 watch, TransactionId xmin, bool just_loaded)
{
	if (phasevec_shared_ivf_cache && attach_shared())
	{
		if (just_loaded)
			publish_index();
		if (use_shared(watch, xmin))
			return true;
	}
	return g_ix.cx != NULL && g_ix.watch == watch && g_ix.xmin == xmin;
}

typedef struct Cand
{
	int32		s;				/* asymmetric score: higher is nearer */
	int32		doc;			/* the reading's ordinal */
	double		score;			/* the int8 cosine, after the rerank */
} Cand;

static int
key_cmp(const Cand *a, const Cand *b)
{
	int64		oa = g_ix.koff[a->doc], ob = g_ix.koff[b->doc];
	int			na = (int) (g_ix.koff[a->doc + 1] - oa), nb = (int) (g_ix.koff[b->doc + 1] - ob);
	int			c = memcmp(g_ix.keys + oa, g_ix.keys + ob, Min(na, nb));

	/* byte order (C collation): ties between equal scores break the same way every time */
	return c != 0 ? c : (na > nb) - (na < nb);
}

/* min-heap on (s, key desc): the root is the worst of the m kept */
static inline bool
worse(const Cand *a, const Cand *b)
{
	return a->s != b->s ? a->s < b->s : key_cmp(a, b) > 0;
}

static void
sift_down(Cand *h, int n, int i)
{
	for (;;)
	{
		int			l = 2 * i + 1, r = l + 1, w = i;

		if (l < n && worse(&h[l], &h[w]))
			w = l;
		if (r < n && worse(&h[r], &h[w]))
			w = r;
		if (w == i)
			return;
		{
			Cand		t = h[i];

			h[i] = h[w];
			h[w] = t;
		}
		i = w;
	}
}

static void
sift_up(Cand *h, int i)
{
	while (i > 0)
	{
		int			p = (i - 1) / 2;

		if (!worse(&h[i], &h[p]))
			return;
		{
			Cand		t = h[i];

			h[i] = h[p];
			h[p] = t;
		}
		i = p;
	}
}

static int
by_score(const void *x, const void *y)
{
	const Cand *a = x, *b = y;

	if (a->score != b->score)
		return a->score < b->score ? 1 : -1;
	return key_cmp(a, b);
}

typedef struct Probe
{
	float		d;
	int			j;
} Probe;

static int
by_d(const void *x, const void *y)
{
	const Probe *a = x, *b = y;

	if (a->d != b->d)
		return a->d < b->d ? 1 : -1;
	return a->j - b->j;
}

/* The question: its int8 code, its norm, its sign bits and the table of the asymmetric score. */
typedef struct Question
{
	const uint8 *qb;
	int		   *q;
	float	   *qf;
	int			nq;
	double		qnorm;
	int32		lut[CB][256];
} Question;

static Question *
question_of(VarBit *qv, ArrayType *qa)
{
	Question   *Q = palloc(sizeof(Question));
	Datum	   *qe;
	bool	   *qn;

	if (VARBITLEN(qv) != 256)
		elog(ERROR, "phasevec ivf: the question's code256 has %d bits", VARBITLEN(qv));
	Q->qb = VARBITS(qv);
	deconstruct_array_builtin(qa, INT2OID, &qe, &qn, &Q->nq);
	if (Q->nq < 256)
		elog(ERROR, "phasevec ivf: the question has %d dimensions, fewer than its 256 sign bits", Q->nq);
	Q->q = palloc(sizeof(int) * Q->nq);
	Q->qf = palloc(sizeof(float) * Q->nq);
	Q->qnorm = 0;
	for (int i = 0; i < Q->nq; i++)
	{
		if (qn[i])
			elog(ERROR, "phasevec ivf: the question has a NULL dimension");
		Q->q[i] = DatumGetInt16(qe[i]);
		Q->qf[i] = (float) Q->q[i];
		Q->qnorm += (double) Q->q[i] * Q->q[i];
	}
	Q->qnorm = sqrt(Q->qnorm);

	/*
	 * The table: bit t (most significant first) of byte b is dimension 8b + t. A reading's score is
	 * sum over its bits of (+q if set, -q if not): lut[b][v] = -sum(q of the byte) + 2 * sum(q of
	 * v's set bits), built by adding one set bit at a time.
	 */
	for (int b = 0; b < CB; b++)
	{
		int32		base = 0;

		for (int t = 0; t < 8; t++)
			base -= Q->q[8 * b + t];
		Q->lut[b][0] = base;
		for (int v = 1; v < 256; v++)
			Q->lut[b][v] = Q->lut[b][v & (v - 1)] + 2 * Q->q[8 * b + 7 - __builtin_ctz(v)];
	}
	return Q;
}

/* The index of a watch in g_ix, held until release_index(). Inside SPI. */
static void
hold_index(int32 watch)
{
	Oid			at[1] = {INT4OID};
	Datum		av[1] = {Int32GetDatum(watch)};
	HeapTuple	tup;
	TupleDesc	td;
	bool		isnull;
	int			ck, cdims, cn;
	TransactionId xmin;

	static SPIPlanPtr plan = NULL;

	if (plan == NULL)
	{
		SPIPlanPtr	p = SPI_prepare("SELECT k, dims, n, c, xmin::text::bigint FROM phasevec.ivf_cents WHERE watch = $1", 1, at);

		if (p == NULL)
			elog(ERROR, "phasevec ivf: cannot prepare the centroids' query");
		SPI_keepplan(p);
		plan = p;
	}
	SPI_execute_plan(plan, av, NULL, true, 1);
	if (SPI_processed != 1)
		elog(ERROR, "phasevec ivf: watch %d has no coarse index", watch);
	tup = SPI_tuptable->vals[0];
	td = SPI_tuptable->tupdesc;
	ck = DatumGetInt32(SPI_getbinval(tup, td, 1, &isnull));
	cdims = DatumGetInt32(SPI_getbinval(tup, td, 2, &isnull));
	cn = DatumGetInt32(SPI_getbinval(tup, td, 3, &isnull));
	xmin = (TransactionId) DatumGetInt64(SPI_getbinval(tup, td, 5, &isnull));
	if (!acquire_index(watch, xmin, false))
	{
		bytea	   *cb = DatumGetByteaPP(SPI_getbinval(tup, td, 4, &isnull));

		if (VARSIZE_ANY_EXHDR(cb) != sizeof(float) * ck * cdims)
			elog(ERROR, "phasevec ivf: the centroids of watch %d are not %d x %d floats", watch, ck, cdims);
		load_index(watch, xmin, ck, cdims, cn, cb);
		if (!acquire_index(watch, xmin, true))
			elog(ERROR, "phasevec ivf: the index of watch %d was loaded and is not there", watch);
	}
}

/*
 * The m best of the nprobe nearest lists by the asymmetric score, reranked by the int8 cosine exactly
 * as phasevec.find scores, best first. The index must be held.
 */
static Cand *
sweep_top(const Question *Q, int nprobe, int m, int *ncp)
{
	int			dims = g_ix.dims, k = g_ix.k, nc = 0;
	Probe	   *pr;
	Cand	   *heap;
	uint8	   *seen;

	if (Q->nq != dims)
		elog(ERROR, "phasevec ivf: the question has %d dimensions, the index %d", Q->nq, dims);
	if (nprobe > k)
		nprobe = k;
	pr = palloc(sizeof(Probe) * k);
	for (int j = 0; j < k; j++)
	{
		pr[j].d = dotf(Q->qf, g_ix.cents + (size_t) j * dims, dims);
		pr[j].j = j;
	}
	qsort(pr, k, sizeof(Probe), by_d);
	heap = palloc(sizeof(Cand) * Max(m, 1));
	seen = palloc0((g_ix.n + 7) / 8);
	for (int p = 0; p < nprobe; p++)
	{
		int			j = pr[p].j;

		for (int e = g_ix.lstart[j]; e < g_ix.lstart[j + 1]; e++)
		{
			int32		d = g_ix.edoc[e];
			const uint8 *c = g_ix.ec256 + (size_t) e * CB;
			int32		s = 0;
			Cand		cd;

			if (seen[d >> 3] & (1 << (d & 7)))		/* SOAR's second copy: already scored */
				continue;
			seen[d >> 3] |= 1 << (d & 7);
			for (int b = 0; b < CB; b++)
				s += Q->lut[b][c[b]];
			cd.s = s;
			cd.doc = d;
			cd.score = 0;
			if (nc < m)
			{
				heap[nc] = cd;
				sift_up(heap, nc++);
			}
			else if (worse(&heap[0], &cd))
			{
				heap[0] = cd;
				sift_down(heap, nc, 0);
			}
		}
	}
	for (int i = 0; i < nc; i++)
	{
		const int8 *c = g_ix.c8 + (size_t) heap[i].doc * dims;
		int64		dt = 0, nn = 0;

		for (int d = 0; d < dims; d++)
		{
			dt += (int64) c[d] * Q->q[d];
			nn += (int64) c[d] * c[d];
		}
		heap[i].score = (nn == 0 || Q->qnorm == 0) ? -INFINITY : (double) dt / (sqrt((double) nn) * Q->qnorm);
	}
	qsort(heap, nc, sizeof(Cand), by_score);
	*ncp = nc;
	return heap;
}

PG_FUNCTION_INFO_V1(phasevec_ivf_sweep);
Datum
phasevec_ivf_sweep(PG_FUNCTION_ARGS)
{
	int32		watch = PG_GETARG_INT32(0);
	Question   *Q = question_of(PG_GETARG_VARBIT_P(1), PG_GETARG_ARRAYTYPE_P(2));
	int32		nprobe = PG_GETARG_INT32(3);
	int32		m = PG_GETARG_INT32(4);
	int32		kk = PG_GETARG_INT32(5);
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;

	InitMaterializedSRF(fcinfo, 0);
	SPI_connect();
	hold_index(watch);
	PG_TRY();
	{
		int			nc;
		Cand	   *heap = sweep_top(Q, nprobe, m, &nc);

		for (int i = 0; i < nc && i < kk; i++)
		{
			int32		d = heap[i].doc;
			bytea	   *h = palloc(VARHDRSZ + HB);
			Datum		v[4];
			bool		nulls[4] = {false, false, false, false};

			SET_VARSIZE(h, VARHDRSZ + HB);
			memcpy(VARDATA(h), g_ix.hash + (size_t) d * HB, HB);
			v[0] = PointerGetDatum(cstring_to_text_with_len(g_ix.keys + g_ix.koff[d], (int) (g_ix.koff[d + 1] - g_ix.koff[d])));
			v[1] = PointerGetDatum(h);
			v[2] = Float8GetDatum(heap[i].score);
			v[3] = Int32GetDatum(ham256(Q->qb, g_ix.c256 + (size_t) d * CB));
			tuplestore_putvalues(rsinfo->setResult, rsinfo->setDesc, v, nulls);
		}
	}
	PG_FINALLY();
	{
		release_index();
	}
	PG_END_TRY();
	SPI_finish();
	return (Datum) 0;
}

/* ------------------------------------------------------------------------------------ delta -- */

/*
 * 0.10.0: the delta (readings recorded after the build, phasevec.ivf_dirty) scored here instead of in
 * SQL. In SQL every delta row cost an unnest of its code and of the question's (~31 us at 256
 * dimensions, measured in b_100k: 1000 rows put 31 ms on a 0.9 ms question), so the index had to be
 * rebuilt every few dozen writes. Here: one pass over the delta's readings, the int8 cosine exactly as
 * phasevec.find scores it (integer sums, then one division), and the best kk come back WITH the text
 * hash each code was read from, to be validated by find_ivf against phasevec.sources like the lists'.
 */
typedef struct DeltaHit
{
	char	   *key;
	int			klen;
	uint8		hash[HB];
	double		score;
	int			ham;
} DeltaHit;

static int
by_delta_score(const void *x, const void *y)
{
	const DeltaHit *a = x, *b = y;

	if (a->score != b->score)
		return a->score < b->score ? 1 : -1;
	if (a->klen != b->klen)
		return a->klen - b->klen;
	return memcmp(a->key, b->key, a->klen);
}

/* Every reading of the delta, scored as phasevec.find scores, best first. Inside SPI. */
static DeltaHit *
delta_top(int32 watch, int32 reader, const Question *Q, size_t *nhp)
{
	Oid			at[2] = {INT4OID, INT4OID};
	Datum		av[2] = {Int32GetDatum(watch), Int32GetDatum(reader)};
	Portal		portal;
	DeltaHit   *hits;
	size_t		nh = 0, cap = 64;

	static SPIPlanPtr plan = NULL;

	if (plan == NULL)
	{
		SPIPlanPtr	p = SPI_prepare("SELECT r.key, r.text_hash, r.code256, r.code FROM phasevec.ivf_dirty d "
									"JOIN phasevec.readings r ON r.watch = d.watch AND r.key = d.key AND r.reader = $2 "
									"AND r.failed IS NULL AND r.code256 IS NOT NULL WHERE d.watch = $1", 2, at);

		if (p == NULL)
			elog(ERROR, "phasevec ivf: cannot prepare the delta's query");
		SPI_keepplan(p);
		plan = p;
	}
	hits = palloc(sizeof(DeltaHit) * cap);
	portal = SPI_cursor_open(NULL, plan, av, NULL, true);
	for (;;)
	{
		SPI_cursor_fetch(portal, true, 1000);
		if (SPI_processed == 0)
			break;
		for (uint64 r = 0; r < SPI_processed; r++)
		{
			HeapTuple	tup = SPI_tuptable->vals[r];
			TupleDesc	td = SPI_tuptable->tupdesc;
			bool		isnull;
			text	   *key = DatumGetTextPP(SPI_getbinval(tup, td, 1, &isnull));
			bytea	   *h = DatumGetByteaPP(SPI_getbinval(tup, td, 2, &isnull));
			const uint8 *c256 = code256_bytes(SPI_getbinval(tup, td, 3, &isnull));
			ArrayType  *ca = DatumGetArrayTypeP(SPI_getbinval(tup, td, 4, &isnull));
			const int16 *c;
			int64		dt = 0, nn = 0;
			DeltaHit   *x;

			if (ARR_NDIM(ca) != 1 || ARR_HASNULL(ca) || ARR_DIMS(ca)[0] != Q->nq || VARSIZE_ANY_EXHDR(h) != HB)
				elog(ERROR, "phasevec ivf: a reading of the delta is not a %d-dimension code with its hash", Q->nq);
			c = (const int16 *) ARR_DATA_PTR(ca);
			for (int d = 0; d < Q->nq; d++)
			{
				dt += (int64) c[d] * Q->q[d];
				nn += (int64) c[d] * c[d];
			}
			if (nh == cap)
			{
				cap *= 2;
				hits = repalloc_huge(hits, sizeof(DeltaHit) * cap);
			}
			x = &hits[nh++];
			x->klen = VARSIZE_ANY_EXHDR(key);
			x->key = palloc(x->klen);
			memcpy(x->key, VARDATA_ANY(key), x->klen);
			memcpy(x->hash, VARDATA_ANY(h), HB);
			x->score = (nn == 0 || Q->qnorm == 0) ? -INFINITY : (double) dt / (sqrt((double) nn) * Q->qnorm);
			x->ham = ham256(Q->qb, c256);
		}
		SPI_freetuptable(SPI_tuptable);
	}
	SPI_cursor_close(portal);
	qsort(hits, nh, sizeof(DeltaHit), by_delta_score);
	*nhp = nh;
	return hits;
}

PG_FUNCTION_INFO_V1(phasevec_ivf_delta);
Datum
phasevec_ivf_delta(PG_FUNCTION_ARGS)
{
	int32		watch = PG_GETARG_INT32(0);
	int32		reader = PG_GETARG_INT32(1);
	Question   *Q = question_of(PG_GETARG_VARBIT_P(2), PG_GETARG_ARRAYTYPE_P(3));
	int32		kk = PG_GETARG_INT32(4);
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	DeltaHit   *hits;
	size_t		nh;

	InitMaterializedSRF(fcinfo, 0);
	SPI_connect();
	hits = delta_top(watch, reader, Q, &nh);
	for (size_t i = 0; i < nh && i < (size_t) kk; i++)
	{
		bytea	   *h = palloc(VARHDRSZ + HB);
		Datum		v[4];
		bool		nulls[4] = {false, false, false, false};

		SET_VARSIZE(h, VARHDRSZ + HB);
		memcpy(VARDATA(h), hits[i].hash, HB);
		v[0] = PointerGetDatum(cstring_to_text_with_len(hits[i].key, hits[i].klen));
		v[1] = PointerGetDatum(h);
		v[2] = Float8GetDatum(hits[i].score);
		v[3] = Int32GetDatum(hits[i].ham);
		tuplestore_putvalues(rsinfo->setResult, rsinfo->setDesc, v, nulls);
	}
	SPI_finish();
	return (Datum) 0;
}

/* ----------------------------------------------------------------------------------- absorb -- */

/*
 * 0.10.0: the delta absorbed into the lists, without k-means. Each delta reading the caller's
 * snapshot can see (its txid visible in the pg_snapshot passed as text) gets a new ordinal after the
 * index's n, is assigned to its nearest list and (SOAR) a second one by the build's own rule, against
 * the centroids as they are, and is appended to those lists. The lists' older entries for the same
 * rows stay: their text hash no longer matches phasevec.sources, so find_ivf's validation drops them,
 * as it drops any stale entry. phasevec.ivf_build rebuilds from scratch when enough was absorbed.
 * Returns how many readings were absorbed; phasevec.ivf_absorb empties those delta rows.
 */
typedef struct Absorbed
{
	int			a1, a2;
	char	   *key;
	int			klen;
	uint8		hash[HB];
	uint8		c256[CB];
	int8	   *c8;
} Absorbed;

static bytea *
bytea_cat(bytea *old, const void *add, size_t addlen)
{
	size_t		ol = old ? VARSIZE_ANY_EXHDR(old) : 0;
	bytea	   *b = palloc(VARHDRSZ + ol + addlen);

	SET_VARSIZE(b, VARHDRSZ + ol + addlen);
	if (ol)
		memcpy(VARDATA(b), VARDATA_ANY(old), ol);
	if (addlen)
		memcpy(VARDATA(b) + ol, add, addlen);
	return b;
}

/*
 * The held index (g_ix) grown by what was absorbed, built in memory: list j keeps its entries and gains
 * the absorbed readings whose first (or SOAR) list it is; the readings get the ordinals after n.
 * False if the held index is not the one absorbed into (another build or absorb moved it meanwhile).
 */
static bool
grow_index(const Absorbed *ab, size_t na, int n0, BIndex *nx)
{
	int			k = g_ix.k, dims = g_ix.dims;
	int		   *add;
	int64		ne = 0, kold, kadd = 0;

	if (g_ix.n != n0)
		return false;
	memset(nx, 0, sizeof(BIndex));
	nx->k = k;
	nx->dims = dims;
	nx->n = n0 + (int) na;
	add = palloc0(sizeof(int) * k);
	for (size_t i = 0; i < na; i++)
	{
		add[ab[i].a1]++;
		if (ab[i].a2 >= 0)
			add[ab[i].a2]++;
		kadd += ab[i].klen;
	}
	nx->lstart = palloc(sizeof(int) * (k + 1));
	nx->lstart[0] = 0;
	for (int j = 0; j < k; j++)
		nx->lstart[j + 1] = nx->lstart[j] + (g_ix.lstart[j + 1] - g_ix.lstart[j]) + add[j];
	ne = nx->lstart[k];
	nx->cents = g_ix.cents;		/* the centroids do not move: publish copies them */
	nx->edoc = MemoryContextAllocHuge(CurrentMemoryContext, sizeof(int32) * (ne ? ne : 1));
	nx->ec256 = MemoryContextAllocHuge(CurrentMemoryContext, (size_t) (ne ? ne : 1) * CB);
	for (int j = 0; j < k; j++)
	{
		int			at = nx->lstart[j], old = g_ix.lstart[j + 1] - g_ix.lstart[j];

		memcpy(nx->edoc + at, g_ix.edoc + g_ix.lstart[j], sizeof(int32) * old);
		memcpy(nx->ec256 + (size_t) at * CB, g_ix.ec256 + (size_t) g_ix.lstart[j] * CB, (size_t) old * CB);
		at += old;
		for (size_t i = 0; i < na; i++)
			if (ab[i].a1 == j || ab[i].a2 == j)
			{
				nx->edoc[at] = (int32) (n0 + i);
				memcpy(nx->ec256 + (size_t) at * CB, ab[i].c256, CB);
				at++;
			}
	}
	nx->c8 = MemoryContextAllocHuge(CurrentMemoryContext, (size_t) nx->n * dims);
	nx->c256 = MemoryContextAllocHuge(CurrentMemoryContext, (size_t) nx->n * CB);
	nx->hash = MemoryContextAllocHuge(CurrentMemoryContext, (size_t) nx->n * HB);
	memcpy(nx->c8, g_ix.c8, (size_t) n0 * dims);
	memcpy(nx->c256, g_ix.c256, (size_t) n0 * CB);
	memcpy(nx->hash, g_ix.hash, (size_t) n0 * HB);
	kold = g_ix.koff[n0];
	nx->keys = MemoryContextAllocHuge(CurrentMemoryContext, (size_t) (kold + kadd + 1));
	nx->koff = MemoryContextAllocHuge(CurrentMemoryContext, sizeof(int64) * (nx->n + 1));
	memcpy(nx->keys, g_ix.keys, kold);
	memcpy(nx->koff, g_ix.koff, sizeof(int64) * (n0 + 1));
	for (size_t i = 0; i < na; i++)
	{
		size_t		d = n0 + i;

		memcpy(nx->c8 + d * dims, ab[i].c8, dims);
		memcpy(nx->c256 + d * CB, ab[i].c256, CB);
		memcpy(nx->hash + d * HB, ab[i].hash, HB);
		memcpy(nx->keys + nx->koff[d], ab[i].key, ab[i].klen);
		nx->koff[d + 1] = nx->koff[d] + ab[i].klen;
	}
	return true;
}

PG_FUNCTION_INFO_V1(phasevec_ivf_absorb);
Datum
phasevec_ivf_absorb(PG_FUNCTION_ARGS)
{
	int32		watch = PG_GETARG_INT32(0);
	int32		reader = PG_GETARG_INT32(1);
	text	   *snap = PG_GETARG_TEXT_PP(2);
	Oid			at[3] = {INT4OID, INT4OID, TEXTOID};
	Datum		av[3] = {Int32GetDatum(watch), Int32GetDatum(reader), PointerGetDatum(snap)};
	int			k, dims, n0;
	bool		soar;
	float	   *cents, *gram = NULL, *x, *dot;
	Portal		portal;
	Absorbed   *ab;
	size_t		na = 0, cap = 256;

	SPI_connect();
	SPI_execute_with_args("SELECT k, dims, n, soar, c FROM phasevec.ivf_cents WHERE watch = $1 AND reader = $2",
						  2, at, av, NULL, false, 1);
	if (SPI_processed != 1)
		elog(ERROR, "phasevec ivf: watch %d has no coarse index of reader %d to absorb into", watch, reader);
	{
		HeapTuple	tup = SPI_tuptable->vals[0];
		TupleDesc	td = SPI_tuptable->tupdesc;
		bool		isnull;
		bytea	   *cb;

		k = DatumGetInt32(SPI_getbinval(tup, td, 1, &isnull));
		dims = DatumGetInt32(SPI_getbinval(tup, td, 2, &isnull));
		n0 = DatumGetInt32(SPI_getbinval(tup, td, 3, &isnull));
		soar = DatumGetBool(SPI_getbinval(tup, td, 4, &isnull));
		cb = DatumGetByteaPP(SPI_getbinval(tup, td, 5, &isnull));
		if (VARSIZE_ANY_EXHDR(cb) != sizeof(float) * k * dims)
			elog(ERROR, "phasevec ivf: the centroids of watch %d are not %d x %d floats", watch, k, dims);
		cents = palloc(sizeof(float) * k * dims);
		memcpy(cents, VARDATA_ANY(cb), sizeof(float) * k * dims);
	}
	if (soar)
	{
		gram = palloc(sizeof(float) * k * k);
		for (int i = 0; i < k; i++)
			for (int j = 0; j < k; j++)
				gram[(size_t) i * k + j] = dotf(cents + (size_t) i * dims, cents + (size_t) j * dims, dims);
	}
	x = palloc(sizeof(float) * dims);
	dot = palloc(sizeof(float) * k);
	ab = palloc(sizeof(Absorbed) * cap);

	portal = SPI_cursor_open_with_args(NULL,
									   "SELECT r.key, r.text_hash, r.code256, r.code FROM phasevec.ivf_dirty d "
									   "JOIN phasevec.readings r ON r.watch = d.watch AND r.key = d.key AND r.reader = $2 "
									   "AND r.failed IS NULL AND r.code256 IS NOT NULL "
									   "WHERE d.watch = $1 AND pg_catalog.pg_visible_in_snapshot(d.txid, $3::pg_snapshot) "
									   "ORDER BY d.key",
									   3, at, av, NULL, true, 0);
	for (;;)
	{
		SPI_cursor_fetch(portal, true, 1000);
		if (SPI_processed == 0)
			break;
		for (uint64 r = 0; r < SPI_processed; r++)
		{
			HeapTuple	tup = SPI_tuptable->vals[r];
			TupleDesc	td = SPI_tuptable->tupdesc;
			bool		isnull;
			text	   *key = DatumGetTextPP(SPI_getbinval(tup, td, 1, &isnull));
			bytea	   *h = DatumGetByteaPP(SPI_getbinval(tup, td, 2, &isnull));
			ArrayType  *ca = DatumGetArrayTypeP(SPI_getbinval(tup, td, 4, &isnull));
			const int16 *p;
			Absorbed   *e;
			int			best = 0;

			if (ARR_NDIM(ca) != 1 || ARR_HASNULL(ca) || ARR_DIMS(ca)[0] != dims || VARSIZE_ANY_EXHDR(h) != HB)
				elog(ERROR, "phasevec ivf: a reading of the delta is not a %d-dimension code with its hash", dims);
			if (na == cap)
			{
				cap *= 2;
				ab = repalloc_huge(ab, sizeof(Absorbed) * cap);
			}
			e = &ab[na++];
			e->klen = VARSIZE_ANY_EXHDR(key);
			e->key = palloc(e->klen);
			memcpy(e->key, VARDATA_ANY(key), e->klen);
			memcpy(e->hash, VARDATA_ANY(h), HB);
			memcpy(e->c256, code256_bytes(SPI_getbinval(tup, td, 3, &isnull)), CB);
			e->c8 = palloc(dims);
			p = (const int16 *) ARR_DATA_PTR(ca);
			for (int i = 0; i < dims; i++)
				e->c8[i] = (int8) p[i];

			/* the build's assignment, against the centroids as they are */
			unit_of(e->c8, dims, x);
			for (int j = 0; j < k; j++)
			{
				dot[j] = dotf(x, cents + (size_t) j * dims, dims);
				if (dot[j] > dot[best])
					best = j;
			}
			e->a1 = best;
			e->a2 = -1;
			if (soar && k > 1)
			{
				int			top[SOAR_CAND];
				int			nt = 0;
				float		rr = 2.0f - 2.0f * dot[best];

				for (int j = 0; j < k; j++)
				{
					int			q;

					if (j == best)
						continue;
					if (nt == SOAR_CAND && dot[j] <= dot[top[nt - 1]])
						continue;
					q = nt < SOAR_CAND ? nt++ : nt - 1;
					while (q > 0 && dot[top[q - 1]] < dot[j])
					{
						top[q] = top[q - 1];
						q--;
					}
					top[q] = j;
				}
				if (rr > 1e-12f)
				{
					float		bp = INFINITY, rx = 1.0f - dot[best], inv = 1.0f / sqrtf(rr);

					for (int t = 0; t < nt; t++)
					{
						int			j = top[t];
						float		proj = (rx - (dot[j] - gram[(size_t) best * k + j])) * inv;
						float		pen = 2.0f - 2.0f * dot[j] + SOAR_LAMBDA * proj * proj;

						if (pen < bp)
						{
							bp = pen;
							e->a2 = j;
						}
					}
				}
			}
		}
		SPI_freetuptable(SPI_tuptable);
		CHECK_FOR_INTERRUPTS();
	}
	SPI_cursor_close(portal);
	if ((size_t) n0 + na > (size_t) PG_INT32_MAX)
		elog(ERROR, "phasevec ivf: more than 2^31 readings");

	/*
	 * The grown index, built from the copy in memory before the lists change (0.10.0): published below
	 * under the xmin this absorb gives phasevec.ivf_cents, so no backend has to read the lists again.
	 */
	{
		bool		grown = false;
		BIndex		nx;

	if (na > 0 && phasevec_shared_ivf_cache)
	{
		hold_index(watch);
		PG_TRY();
		{
			grown = grow_index(ab, na, n0, &nx);
		}
		PG_FINALLY();
		{
			release_index();
		}
		PG_END_TRY();
	}
	/*
	 * Each list that gains entries gets ONE new row in phasevec.ivf_added (0.10.0): nothing is rewritten.
	 * Until then every touched list (~130 kB of TOAST) was rewritten to add a few entries: 50 readings cost
	 * 88-237 ms and 8-20 MB of WAL (b_100k, 22-10).
	 */
	if (na > 0)
	{
		Oid			it[12] = {INT4OID, INT4OID, INT4OID, BYTEAOID, BYTEAOID, BYTEAOID, BYTEAOID, BYTEAOID, BYTEAOID,
							  INT4OID, BYTEAOID, BYTEAOID};
		SPIPlanPtr	ins = SPI_prepare("INSERT INTO phasevec.ivf_added (watch, list, n, docs, keys, koff, hashes, c256, c8, sn, sdocs, sc256) "
									  "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)", 12, it);
		MemoryContext per = AllocSetContextCreate(CurrentMemoryContext, "phasevec ivf absorb", ALLOCSET_DEFAULT_SIZES);

		if (ins == NULL)
			elog(ERROR, "phasevec ivf: cannot prepare the chunk insert");
		for (int j = 0; j < k; j++)
		{
			MemoryContext old;
			int			add = 0, sadd = 0, t = 0, u = 0;
			size_t		kadd = 0, kk = 0;
			int32	   *nd, *no, *nsd;
			char	   *nk;
			uint8	   *nh, *nc, *nsc;
			int8	   *n8;
			Datum		v[12];

			for (size_t i = 0; i < na; i++)
			{
				if (ab[i].a1 == j)
				{
					add++;
					kadd += ab[i].klen;
				}
				else if (ab[i].a2 == j)
					sadd++;
			}
			if (add == 0 && sadd == 0)
				continue;
			old = MemoryContextSwitchTo(per);
			nd = palloc(sizeof(int32) * Max(add, 1));
			no = palloc(sizeof(int32) * (add + 1));
			nk = palloc(Max(kadd, 1));
			nh = palloc((size_t) Max(add, 1) * HB);
			nc = palloc((size_t) Max(add, 1) * CB);
			n8 = palloc((size_t) Max(add, 1) * dims);
			nsd = palloc(sizeof(int32) * Max(sadd, 1));
			nsc = palloc((size_t) Max(sadd, 1) * CB);
			no[0] = 0;
			for (size_t i = 0; i < na; i++)
			{
				if (ab[i].a1 == j)
				{
					nd[t] = (int32) (n0 + i);
					memcpy(nk + kk, ab[i].key, ab[i].klen);
					kk += ab[i].klen;
					no[t + 1] = (int32) kk;
					memcpy(nh + (size_t) t * HB, ab[i].hash, HB);
					memcpy(nc + (size_t) t * CB, ab[i].c256, CB);
					memcpy(n8 + (size_t) t * dims, ab[i].c8, dims);
					t++;
				}
				else if (ab[i].a2 == j)
				{
					nsd[u] = (int32) (n0 + i);
					memcpy(nsc + (size_t) u * CB, ab[i].c256, CB);
					u++;
				}
			}
			v[0] = Int32GetDatum(watch);
			v[1] = Int32GetDatum(j);
			v[2] = Int32GetDatum(add);
			v[3] = PointerGetDatum(bytea_cat(NULL, nd, sizeof(int32) * add));
			v[4] = PointerGetDatum(bytea_cat(NULL, nk, kadd));
			v[5] = PointerGetDatum(bytea_cat(NULL, no, sizeof(int32) * (add + 1)));
			v[6] = PointerGetDatum(bytea_cat(NULL, nh, (size_t) add * HB));
			v[7] = PointerGetDatum(bytea_cat(NULL, nc, (size_t) add * CB));
			v[8] = PointerGetDatum(bytea_cat(NULL, n8, (size_t) add * dims));
			v[9] = Int32GetDatum(sadd);
			v[10] = PointerGetDatum(bytea_cat(NULL, nsd, sizeof(int32) * sadd));
			v[11] = PointerGetDatum(bytea_cat(NULL, nsc, (size_t) sadd * CB));
			SPI_execute_plan(ins, v, NULL, false, 0);
			MemoryContextSwitchTo(old);
			MemoryContextReset(per);
			CHECK_FOR_INTERRUPTS();
		}
		{
			Oid			ct[3] = {INT4OID, INT4OID, INT4OID};
			Datum		cv[3] = {Int32GetDatum(watch), Int32GetDatum((int32) (n0 + na)), Int32GetDatum((int32) na)};

			SPI_execute_with_args("UPDATE phasevec.ivf_cents SET n = $2, absorbed = absorbed + $3 WHERE watch = $1",
								  3, ct, cv, NULL, false, 0);
		}
		/*
		 * Published under the row's new xmin, read back (a subtransaction would give it another xid).
		 * Before this commits no snapshot sees that xmin, so nobody takes the copy early; if it aborts,
		 * the copy is never asked for and is evicted like any other.
		 */
		if (grown && attach_shared())
		{
			Oid			xt[1] = {INT4OID};
			Datum		xv[1] = {Int32GetDatum(watch)};
			bool		isnull;
			BIndex		saved = g_ix;

			SPI_execute_with_args("SELECT xmin::text::bigint FROM phasevec.ivf_cents WHERE watch = $1", 1, xt, xv, NULL, false, 1);
			if (SPI_processed == 1)
			{
				nx.watch = watch;
				nx.xmin = (TransactionId) DatumGetInt64(SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &isnull));
				nx.cx = NULL;
				nx.shared = false;
				g_ix = nx;
				PG_TRY();
				{
					publish_index();
				}
				PG_FINALLY();
				{
					g_ix = saved;
				}
				PG_END_TRY();
			}
		}
	}
	}
	SPI_finish();
	PG_RETURN_INT32((int32) na);
}

/* -------------------------------------------------------------------------------------- find -- */

/*
 * 0.10.0: find_ivf's work in one C call. Measured (sql/174, the concurrency probe of 22-10): the sweep
 * alone answers 26,040 questions a second with 16 clients and find_ivf 12,784, below pgvector's 15,856;
 * the SQL validation around the sweep cost as much as the sweep. Here the sweep's kk best and the
 * delta's kk best are validated in ONE prepared statement per backend, against phasevec.readings (the
 * watch's reader, read from that very text) and phasevec.sources (that text is still the row's), in the
 * caller's snapshot as before; each key keeps its best valid score, and the k best come back, ordered
 * as the SQL ordered them (score, then key in the database's collation). The checks and the coverage
 * refusal stay in phasevec.find_ivf.
 */
typedef struct Found
{
	char	   *key;
	int			klen;
	uint8		hash[HB];
	double		score;
	int			ham;
	bool		valid;
	Datum		fam, read_at, trunc;
	bool		fam_null, read_at_null, trunc_null;
} Found;

static int
found_cmp(const void *x, const void *y)
{
	const Found *a = x, *b = y;

	if (a->score != b->score)
		return a->score < b->score ? 1 : -1;
	return varstr_cmp(a->key, a->klen, b->key, b->klen, DEFAULT_COLLATION_OID);
}

static SPIPlanPtr g_validate = NULL;

/*
 * The k best valid answers among the sweep's kk best and the delta's kk best, as find_ivf returns them.
 * Inside SPI; the Found array and what it points to live in the SPI context.
 */
static int
find_valid(int32 watch, int32 reader, const Question *Q, int nprobe, int m, int kk, int k, Found **outp)
{
	Found	   *f = palloc(sizeof(Found) * (2 * (size_t) Max(kk, 1)));
	Found	   *res;
	int			nf = 0, out = 0;

	hold_index(watch);
	PG_TRY();
	{
		int			nc;
		Cand	   *heap = sweep_top(Q, nprobe, m, &nc);

		for (int i = 0; i < nc && i < kk; i++)
		{
			int32		d = heap[i].doc;
			Found	   *x = &f[nf++];

			x->klen = (int) (g_ix.koff[d + 1] - g_ix.koff[d]);
			x->key = palloc(x->klen + 1);
			memcpy(x->key, g_ix.keys + g_ix.koff[d], x->klen);
			memcpy(x->hash, g_ix.hash + (size_t) d * HB, HB);
			x->score = heap[i].score;
			x->ham = ham256(Q->qb, g_ix.c256 + (size_t) d * CB);
			x->valid = false;
		}
	}
	PG_FINALLY();
	{
		release_index();
	}
	PG_END_TRY();
	{
		size_t		nh;
		DeltaHit   *dh = delta_top(watch, reader, Q, &nh);

		for (size_t i = 0; i < nh && i < (size_t) kk; i++)
		{
			Found	   *x = &f[nf++];

			x->klen = dh[i].klen;
			x->key = dh[i].key;
			memcpy(x->hash, dh[i].hash, HB);
			x->score = dh[i].score;
			x->ham = dh[i].ham;
			x->valid = false;
		}
	}
	if (nf > 0)
	{
		Datum	   *kd = palloc(sizeof(Datum) * nf), *hd = palloc(sizeof(Datum) * nf);
		Datum		v[4];
		Oid			vt[4] = {INT4OID, TEXTARRAYOID, BYTEAARRAYOID, INT4OID};

		for (int i = 0; i < nf; i++)
		{
			bytea	   *h = palloc(VARHDRSZ + HB);

			SET_VARSIZE(h, VARHDRSZ + HB);
			memcpy(VARDATA(h), f[i].hash, HB);
			kd[i] = PointerGetDatum(cstring_to_text_with_len(f[i].key, f[i].klen));
			hd[i] = PointerGetDatum(h);
		}
		if (g_validate == NULL)
		{
			SPIPlanPtr	p = SPI_prepare(
				"SELECT c.i::int, r.familiarity, r.read_at, r.truncated "
				"FROM unnest($2::text[], $3::bytea[]) WITH ORDINALITY c(key, h, i) "
				"JOIN phasevec.readings r ON r.watch = $1 AND r.key = c.key AND r.reader = $4 "
				"  AND r.failed IS NULL AND r.text_hash = c.h "
				"JOIN phasevec.sources s ON s.watch = $1 AND s.key = c.key AND s.text_hash = c.h",
				4, vt);

			if (p == NULL)
				elog(ERROR, "phasevec ivf: cannot prepare the validation: %s", SPI_result_code_string(SPI_result));
			SPI_keepplan(p);
			g_validate = p;
		}
		v[0] = Int32GetDatum(watch);
		v[1] = PointerGetDatum(construct_array_builtin(kd, nf, TEXTOID));
		v[2] = PointerGetDatum(construct_array(hd, nf, BYTEAOID, -1, false, TYPALIGN_INT));
		v[3] = Int32GetDatum(reader);
		/* read-only: the caller's snapshot, as the SQL validation had */
		if (SPI_execute_plan(g_validate, v, NULL, true, 0) != SPI_OK_SELECT)
			elog(ERROR, "phasevec ivf: the validation failed");
		for (uint64 r = 0; r < SPI_processed; r++)
		{
			HeapTuple	tup = SPI_tuptable->vals[r];
			TupleDesc	td = SPI_tuptable->tupdesc;
			bool		isnull;
			int			i = DatumGetInt32(SPI_getbinval(tup, td, 1, &isnull)) - 1;
			Found	   *x = &f[i];

			x->valid = true;
			x->fam = SPI_getbinval(tup, td, 2, &x->fam_null);
			x->read_at = SPI_getbinval(tup, td, 3, &x->read_at_null);
			x->trunc = SPI_getbinval(tup, td, 4, &x->trunc_null);
		}
	}
	qsort(f, nf, sizeof(Found), found_cmp);
	res = palloc(sizeof(Found) * Max(k, 1));
	for (int i = 0; i < nf && out < k; i++)
	{
		bool		dup = false;

		if (!f[i].valid)
			continue;
		/* a key in a list and in the delta keeps its best valid score: the first one seen */
		for (int j = 0; j < out && !dup; j++)
			dup = res[j].klen == f[i].klen && memcmp(res[j].key, f[i].key, f[i].klen) == 0;
		if (!dup)
			res[out++] = f[i];
	}
	*outp = res;
	return out;
}

static void
emit_found(ReturnSetInfo *rsinfo, const Found *f, int n, bool has_doubt, float4 doubt)
{
	for (int i = 0; i < n; i++)
	{
		Datum		v[7];
		bool		nulls[7] = {false, false, false, false, false, false, false};

		v[0] = PointerGetDatum(cstring_to_text_with_len(f[i].key, f[i].klen));
		v[1] = Float8GetDatum(f[i].score);
		v[2] = Int32GetDatum(f[i].ham);
		v[3] = PointerGetDatum(cstring_to_text(has_doubt && !f[i].fam_null && DatumGetFloat4(f[i].fam) < doubt
											   ? "doubtful" : "fresh"));
		v[4] = f[i].fam;
		nulls[4] = f[i].fam_null;
		v[5] = f[i].read_at;
		nulls[5] = f[i].read_at_null;
		v[6] = f[i].trunc;
		nulls[6] = f[i].trunc_null;
		tuplestore_putvalues(rsinfo->setResult, rsinfo->setDesc, v, nulls);
	}
}

PG_FUNCTION_INFO_V1(phasevec_ivf_find);
Datum
phasevec_ivf_find(PG_FUNCTION_ARGS)
{
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	Question   *Q;
	Found	   *f;
	int			n;

	for (int a = 0; a < 8; a++)
		if (PG_ARGISNULL(a))
			elog(ERROR, "phasevec ivf: _ivf_find takes no NULL but its doubt threshold");
	Q = question_of(PG_GETARG_VARBIT_P(2), PG_GETARG_ARRAYTYPE_P(3));
	InitMaterializedSRF(fcinfo, 0);
	SPI_connect();
	n = find_valid(PG_GETARG_INT32(0), PG_GETARG_INT32(1), Q, PG_GETARG_INT32(4), PG_GETARG_INT32(5),
				   PG_GETARG_INT32(6), PG_GETARG_INT32(7), &f);
	emit_found(rsinfo, f, n, !PG_ARGISNULL(8), PG_ARGISNULL(8) ? 0 : PG_GETARG_FLOAT4(8));
	SPI_finish();
	return (Datum) 0;
}

/*
 * phasevec.find_ivf itself (0.10.0): find_v2's contract of 0.8.0 unchanged -- the same checks, the
 * same messages, the same coverage refusal (computed by the same SQL, so its rounding is the same),
 * the same columns and scores -- in one C call with prepared plans. The PL/pgSQL version cost a
 * quarter of the throughput with 16 clients (the probe of 22-10).
 */
PG_FUNCTION_INFO_V1(phasevec_find_ivf);
Datum
phasevec_find_ivf(PG_FUNCTION_ARGS)
{
	static SPIPlanPtr wplan = NULL, cplan = NULL;
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	text	   *wname;
	ArrayType  *qa;
	int32		k, m, nprobe;
	bool		partial;
	int32		watch, reader, dims;
	bool		has_index, has_doubt, isnull;
	float4		doubt = 0;
	Datum		min_cov;
	Question   *Q;
	Found	   *f;
	int			n, kk;

	if (PG_ARGISNULL(0))
		ereport(ERROR, (errcode(ERRCODE_RAISE_EXCEPTION), errmsg("phasevec: no watch named <NULL>")));
	wname = PG_GETARG_TEXT_PP(0);
	qa = PG_ARGISNULL(2) ? NULL : PG_GETARG_ARRAYTYPE_P(2);
	k = PG_ARGISNULL(3) ? -1 : PG_GETARG_INT32(3);
	partial = !PG_ARGISNULL(4) && PG_GETARG_BOOL(4);
	m = PG_ARGISNULL(5) ? -1 : PG_GETARG_INT32(5);
	nprobe = PG_ARGISNULL(7) ? 16 : PG_GETARG_INT32(7);

	InitMaterializedSRF(fcinfo, 0);
	SPI_connect();
	if (wplan == NULL)
	{
		Oid			t[1] = {TEXTOID};
		SPIPlanPtr	p = SPI_prepare("SELECT w.id, w.reader, w.min_coverage, w.doubt_below, rd.dims, "
									"EXISTS (SELECT 1 FROM phasevec.ivf_cents c WHERE c.watch = w.id AND c.reader = w.reader) "
									"FROM phasevec.watches w JOIN phasevec.readers rd ON rd.id = w.reader WHERE w.name = $1", 1, t);
		Oid			t2[2] = {TEXTOID, NUMERICOID};
		SPIPlanPtr	p2 = SPI_prepare("SELECT x.fresh < $2, round(x.fresh * 100, 1)::text, round($2 * 100, 1)::text, "
									 "coalesce(x.missing, 'nothing read yet') FROM ("
									 "SELECT coalesce(sum(c.share) FILTER (WHERE c.state IN ('fresh', 'doubtful')), 0) AS fresh, "
									 "string_agg(format('%s %s%%', c.state, round(c.share * 100, 1)), ', ') "
									 "  FILTER (WHERE c.state IN ('stale', 'pending', 'failed') AND c.n > 0) AS missing "
									 "FROM phasevec.coverage($1) c) x", 2, t2);

		if (p == NULL || p2 == NULL)
			elog(ERROR, "phasevec: cannot prepare find_ivf's queries");
		SPI_keepplan(p);
		SPI_keepplan(p2);
		wplan = p;
		cplan = p2;
	}
	{
		Datum		a[1] = {PointerGetDatum(wname)};
		HeapTuple	tup;
		TupleDesc	td;

		SPI_execute_plan(wplan, a, NULL, true, 1);
		if (SPI_processed != 1)
			ereport(ERROR, (errcode(ERRCODE_RAISE_EXCEPTION), errmsg("phasevec: no watch named %s", text_to_cstring(wname))));
		tup = SPI_tuptable->vals[0];
		td = SPI_tuptable->tupdesc;
		watch = DatumGetInt32(SPI_getbinval(tup, td, 1, &isnull));
		reader = DatumGetInt32(SPI_getbinval(tup, td, 2, &isnull));
		min_cov = SPI_datumTransfer(SPI_getbinval(tup, td, 3, &isnull), false, -1);
		doubt = DatumGetFloat4(SPI_getbinval(tup, td, 4, &has_doubt));
		has_doubt = !has_doubt;
		dims = DatumGetInt32(SPI_getbinval(tup, td, 5, &isnull));
		has_index = DatumGetBool(SPI_getbinval(tup, td, 6, &isnull));
	}
	if (qa == NULL || ARR_NDIM(qa) != 1 || ArrayGetNItems(ARR_NDIM(qa), ARR_DIMS(qa)) != dims)
		ereport(ERROR, (errcode(ERRCODE_RAISE_EXCEPTION), errmsg("phasevec: the question must be read by the watch's reader (%d dimensions)", dims)));
	if (k < 1 || k > 1000 || m < k || m > 100000)
		ereport(ERROR, (errcode(ERRCODE_RAISE_EXCEPTION), errmsg("phasevec: k must be in 1..1000 and m in k..100000")));
	if (PG_ARGISNULL(6))
		ereport(ERROR, (errcode(ERRCODE_RAISE_EXCEPTION), errmsg("phasevec: find_v2 sweeps the 256-bit codes: pass the question's code256")));
	if (!has_index)
		ereport(ERROR, (errcode(ERRCODE_RAISE_EXCEPTION), errmsg("phasevec: watch %s has no coarse index for its reader", text_to_cstring(wname)),
						errhint("Build it with phasevec.ivf_build(watch).")));
	{
		Datum		a[2] = {PointerGetDatum(wname), min_cov};
		HeapTuple	tup;
		TupleDesc	td;

		SPI_execute_plan(cplan, a, NULL, true, 1);
		tup = SPI_tuptable->vals[0];
		td = SPI_tuptable->tupdesc;
		if (DatumGetBool(SPI_getbinval(tup, td, 1, &isnull)) && !partial)
			ereport(ERROR, (errcode(ERRCODE_RAISE_EXCEPTION), errmsg("phasevec: watch %s covers %s%% of its rows and declared %s%%: %s",
								   text_to_cstring(wname), SPI_getvalue(tup, td, 2), SPI_getvalue(tup, td, 3),
								   SPI_getvalue(tup, td, 4)),
							errhint("Answering from what happens to be read would look like a full answer. "
									"Pass p_partial => true to accept it knowingly.")));
	}
	Q = question_of(PG_GETARG_VARBIT_P(6), qa);
	/* k + 2 validated first; if fewer than k survive (stale rows near the question), all m. Never padded. */
	kk = Min(m, k + 2);
	for (;;)
	{
		n = find_valid(watch, reader, Q, nprobe, m, kk, k, &f);
		if (n >= k || kk >= m)
			break;
		kk = m;
	}
	emit_found(rsinfo, f, n, has_doubt, doubt);
	SPI_finish();
	return (Datum) 0;
}
