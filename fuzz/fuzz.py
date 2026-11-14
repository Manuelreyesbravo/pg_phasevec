#!/usr/bin/env python3
"""Model-based fuzzer for pg_phasevec's claim lifecycle (see spec.md, threat-model.md).

Runs random sequences of operations against a disposable PostgreSQL cluster that this
process creates, uses and destroys itself (initdb, then pg_ctl stop and rm on exit).
After every step it compares a pure-Python reference model with what _verdict(), brief(),
truth_coverage() and replacement() serve, and checks the invariants of spec.md.

Python 3 standard library only: every statement goes through a psql subprocess.

  nice -n 19 python3 fuzz.py --pg /path/to/pg --seed 1 --minutes 3
"""
import argparse
import hashlib
import json
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import time

KEYS = ["1", "2", "3", "4", "5"]
TEXTS = ["ok one", "ok two", "nope", "nope two", "ok one"]  # "ok one" twice: text comes back
TENANTS = ["a", "b"]
OWNER = "fz_owner"          # bootstrap superuser: owns the extension and the table
AUTHORS = ["fz_author", "fz_author_b"]
READER = "fz_reader"
OUTSIDER = "fz_outsider"
WRITER = "fz_writer"
ROLES = AUTHORS + [READER, OUTSIDER, WRITER]
PROOFS = {
    "ok": ("SELECT coalesce((SELECT n.body LIKE '%ok%' FROM public.notes n WHERE n.id = {k}), "
           "false)"),
    "true": "SELECT true",
    "false": "SELECT false",
    "none": None,
}
# Proofs whose truth is the settings they run under (env_assert): which flag() search_path finds
# (fz_s1's is true, fz_s2's false, none: an error, refuted), and how DateStyle orders a date.
ENV_PROOFS = {
    "sp": "SELECT flag()",
    "ds": "SELECT '03/04/2026'::date = date '2026-03-04'",
}
DEFAULT_SP = '"$user", public'
SP_CHOICES = ["fz_s1, public", "fz_s2, public", None]
DS_CHOICES = ["SQL, DMY", "German", "ISO, MDY", "Postgres, DMY", "SQL, MDY", None]
WRAPPER_SP = {"wrapper": "fz_s1, pg_catalog", "wrapper_local": "fz_s2, pg_catalog"}
SEP = "\x1f"
NIL = "00000000-0000-0000-0000-000000000000"
# FZ_RECIPE_TS=1: the watch's recipe prints a timestamptz column, whose text
# depends on the session's TimeZone (0.19.0 noted rows in the writer's settings, 0.20.0 renders in
# pinned ones: UTC). The default is the plain 'r.body' of every earlier run.
if os.environ.get("FZ_RECIPE_TS") == "1":
    RECIPE_COLS = ", at timestamptz NOT NULL DEFAULT '2026-11-01 10:00:00-03'"
    RECIPE = "$r$r.body || ' @ ' || r.at$r$"
else:
    RECIPE_COLS, RECIPE = "", "'r.body'"
NULL = "<NULL>"


def proof_sql(kind, k):
    if kind in ENV_PROOFS:
        return ENV_PROOFS[kind]
    return None if PROOFS[kind] is None else PROOFS[kind].format(k=k)


def env_sets(sp, ds):
    """SET statements for a session's search_path (a list of names, not one quoted name) and
    DateStyle; None leaves the setting as the session has it."""
    return ((f"SET search_path = {sp};" if sp else "")
            + (f"SET DateStyle = {q(ds)};" if ds else ""))


def ds_order(ds):
    """The field order a DateStyle value gives (None: the cluster's default, MDY)."""
    if ds is None:
        return "MDY"
    u = ds.upper()
    for o in ("DMY", "MDY", "YMD"):
        if o in u:
            return o
    return "DMY" if "GERMAN" in u else None


def env_value(kind, sp, order):
    """What an env proof answers under search_path sp and DateStyle order `order`."""
    if kind == "sp":
        return sp is not None and sp.startswith("fz_s1")
    return order == "MDY"


# ------------------------------------------------------------------------------- cluster --
class Cluster:
    def __init__(self, pg, port, keep=False):
        self.pg = pg
        self.port = port
        # FZ_BASE_DIR: where the cluster's directory goes (default /dev/shm)
        self.base = tempfile.mkdtemp(prefix="pvfz-", dir=os.environ.get("FZ_BASE_DIR", "/dev/shm"))
        self.data = os.path.join(self.base, "data")
        self.sock = self.base
        self.keep = keep
        self.up = False
        self.calls = 0       # statements sent; a step that sends none was skipped by the model

    def bin(self, name):
        return os.path.join(self.pg, "bin", name)

    def start(self):
        subprocess.run([self.bin("initdb"), "-D", self.data, "-U", OWNER, "-A", "trust", "-E",
                        "UTF8", "--no-locale", "--no-sync"], check=True, capture_output=True)
        opts = (f"-p {self.port} -k {self.sock} -c listen_addresses='' -c fsync=off "
                "-c max_worker_processes=16 -c max_connections=40 -c shared_buffers=32MB "
                "-c synchronous_commit=off -c log_min_messages=warning")
        subprocess.run([self.bin("pg_ctl"), "-D", self.data, "-o", opts, "-l",
                        os.path.join(self.base, "log"), "-w", "start"], check=True,
                       capture_output=True)
        self.up = True

    def stop(self):
        if self.up:
            subprocess.run([self.bin("pg_ctl"), "-D", self.data, "-m", "immediate", "-w", "stop"],
                           capture_output=True)
            self.up = False
        if not self.keep:
            shutil.rmtree(self.base, ignore_errors=True)

    def argv(self, role, db):
        return [self.bin("psql"), "-X", "-q", "-A", "-t", "-F", SEP, "-P", f"null={NULL}",
                "-v", "ON_ERROR_STOP=1", "-h", self.sock, "-p", str(self.port), "-U", role,
                "-d", db]

    def sql(self, role, sql, db="fz", timeout=60):
        self.calls += 1
        p = subprocess.run(self.argv(role, db), input=sql, capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode, p.stdout, p.stderr

    def popen(self, role, sql, db="fz"):
        self.calls += 1
        p = subprocess.Popen(self.argv(role, db), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
        p.stdin.write(sql)
        p.stdin.close()
        return p

    def must(self, role, sql, db="fz"):
        rc, out, err = self.sql(role, sql, db)
        if rc != 0:
            raise RuntimeError(f"setup failed as {role}: {err.strip()}\n{sql[:400]}")
        return out


def free_port(want):
    """The cluster listens on no TCP port (listen_addresses ''), only on a socket in its own
    directory: the number only names that socket, so it cannot collide with another server."""
    if not 1 <= want <= 65535:
        raise SystemExit(f"port {want} is outside 1-65535")
    return want


# -------------------------------------------------------------------------------- schema --
TEMPLATE_SQL = """
CREATE EXTENSION pg_phasevec{ver};
CREATE TABLE public.notes (id int PRIMARY KEY, body text NOT NULL, tenant text NOT NULL{cols});
-- one policy for every role, by name, so that roles can be dropped and made again
CREATE POLICY p ON public.notes USING (CASE current_user WHEN 'fz_reader' THEN tenant = 'a'
                                                        WHEN 'fz_author_b' THEN tenant = 'b'
                                                        ELSE true END) WITH CHECK (true);
SELECT phasevec.reader_register('r1', repeat('a', 64), 4) > 0;
SELECT phasevec.watch('notes', 'public.notes'::regclass, 'id', {recipe}, 'r1') > 0;
INSERT INTO public.notes VALUES (1, 'ok one', 'a'), (2, 'nope', 'a'), (3, 'ok two', 'b'),
                                (4, 'ok one', 'b');
-- env_assert: a function found through search_path, and fz_author's wrappers (owner set in GRANTS)
CREATE SCHEMA fz_s1;
CREATE SCHEMA fz_s2;
CREATE SCHEMA fz_env;
GRANT USAGE ON SCHEMA fz_s1, fz_s2, fz_env TO PUBLIC;
CREATE FUNCTION fz_s1.flag() RETURNS boolean LANGUAGE sql AS 'SELECT true';
CREATE FUNCTION fz_s2.flag() RETURNS boolean LANGUAGE sql AS 'SELECT false';
CREATE FUNCTION fz_env.assert_via(k text, p text) RETURNS void LANGUAGE sql SECURITY DEFINER
    SET search_path = fz_s1, pg_catalog SET DateStyle = ISO
    AS $f$ SELECT phasevec.assert('notes', k, p) $f$;
CREATE FUNCTION fz_env.assert_local(k text, p text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = fz_s2, pg_catalog
    AS $f$ BEGIN SET LOCAL DateStyle = 'Postgres'; PERFORM phasevec.assert('notes', k, p); END $f$;
REVOKE ALL ON FUNCTION fz_env.assert_via(text, text), fz_env.assert_local(text, text) FROM PUBLIC;
CREATE SCHEMA fz_c;
GRANT USAGE, CREATE ON SCHEMA fz_c TO PUBLIC;
"""

GRANTS_SQL = """
GRANT USAGE ON SCHEMA phasevec TO fz_author, fz_author_b, fz_reader, fz_outsider, fz_writer;
GRANT SELECT ON public.notes TO fz_author, fz_author_b, fz_reader;
GRANT UPDATE ON public.notes TO fz_author, fz_author_b;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.notes TO fz_writer;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz)
    TO fz_author, fz_author_b;
GRANT EXECUTE ON FUNCTION phasevec.verify(text, int, interval, interval, int, float8),
                          phasevec.verify_one(text, text, int, float8) TO fz_author, fz_author_b;
GRANT EXECUTE ON FUNCTION phasevec.refute(text, text, text),
                          phasevec.supersede(text, text, text, text),
                          phasevec.unsupersede(text, text) TO fz_author;
GRANT EXECUTE ON FUNCTION phasevec.adopt(text, regrole, text[], text[]) TO fz_author;
GRANT EXECUTE ON FUNCTION phasevec.brief(text, int) TO fz_reader, fz_outsider;
GRANT SELECT ON phasevec.truth TO fz_reader, fz_outsider;
ALTER FUNCTION fz_env.assert_via(text, text) OWNER TO fz_author;
ALTER FUNCTION fz_env.assert_local(text, text) OWNER TO fz_author;
GRANT EXECUTE ON FUNCTION fz_env.assert_via(text, text), fz_env.assert_local(text, text)
    TO fz_reader, fz_author_b;
"""
GRANTS_B = """
GRANT USAGE ON SCHEMA phasevec TO fz_author_b;
GRANT SELECT, UPDATE ON public.notes TO fz_author_b;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz)
    TO fz_author_b;
GRANT EXECUTE ON FUNCTION phasevec.verify(text, int, interval, interval, int, float8),
                          phasevec.verify_one(text, text, int, float8) TO fz_author_b;
GRANT EXECUTE ON FUNCTION fz_env.assert_via(text, text), fz_env.assert_local(text, text)
    TO fz_author_b;
"""


def q(s):
    return "NULL" if s is None else "'" + s.replace("'", "''") + "'"


# --------------------------------------------------------------------------------- model --
class Claim:
    def __init__(self):
        self.proof = None        # proof kind (PROOFS key) or None
        self.author = None       # role name, or None (asserted before 0.20.0)
        self.gen = None          # incarnation of that role name (DROP ROLE makes a new one)
        self.asserted = None     # text the author vouched for (None: no row it could see)
        self.verdict = "unproven"
        self.replaced_by = None
        self.halted = False
        self.expired = False
        self.retired = False     # refute()d and not asserted since
        self.refuted_text = None  # row text when it was retired
        self.uncertain = False
        # the row it is about (phasevec.sources.born when its author made
        # it; NIL when the key had no row; None: made before 0.20.0), whether its author made it
        # with a steward's right alone, and whether its author is still bound here (rebind())
        self.row = None
        self.by_steward = False
        self.here = True

    def copy(self):
        c = Claim()
        c.__dict__.update(self.__dict__)
        return c

    def env_set(self, kind, sp, ds):
        """The settings an env proof runs with (README: what is in effect where assert() is
        called, as its author has it there), and what it answers under them."""
        self.env_sp, self.env_ds = sp, ds
        self.envval = env_value(kind, sp, ds_order(ds))


class Model:
    def __init__(self):
        self.rows = {"1": ("ok one", "a"), "2": ("nope", "a"), "3": ("ok two", "b"),
                     "4": ("ok one", "b")}
        self.claims = {}
        self.rls = False
        self.rls_epoch = 0       # bumped by every RLS toggle (see INV-VERIFIED-HOLDS/proof)
        self.horizon = False     # max_age made tiny: every proof verdict is past its horizon
        self.version = "0.20.0"
        self.gen = {r: 0 for r in ROLES + [OWNER]}
        self.stewards = set()    # phasevec.steward() of watch notes
        # the authors that hold UPDATE on public.notes (GRANTS_SQL,
        # GRANTS_B); the update_grant step revokes and grants fz_author's
        self.updaters = set(AUTHORS)
        # phasevec.sources.born per key, as the database last showed it,
        # and the keys a step gave a new row (a new born, INV-BORN)
        self.born = {}
        self.reborn = set()

    def text(self, k):
        r = self.rows.get(k)
        return r[0] if r else None

    def sees(self, role, k):
        r = self.rows.get(k)
        if r is None:
            return False
        if role == OUTSIDER:
            return False
        if not self.rls or role in (OWNER, "fz_author", WRITER):
            return True
        return (role == READER and r[1] == "a") or (role == "fz_author_b" and r[1] == "b")

    def author_known(self, c):
        return c.author is not None and c.gen == self.gen[c.author]

    def dead(self, k, c):
        """another row is under the key than the one the
        claim was made about."""
        return (c is not None and c.row is not None and k in self.rows
                and self.born.get(k) is not None and self.born[k] != c.row)

    def author_alive(self, c, k):
        """Its author still counts: the role (OID and name), bound here (not rebind()), and its
        row is still the one it claimed."""
        return self.author_known(c) and c.here and not self.dead(k, c)

    def row_now(self, k):
        return self.born.get(k, NIL) if k in self.rows else NIL

    def how(self, role, k):
        """The right that lets role change the claim on k, as
        _claim_how orders them: owner, author, writer (first claim), steward; None: refused."""
        c = self.claims.get(k)
        if role == OWNER:
            return "owner" if (c is not None or k in self.rows) else None
        if c is None or self.dead(k, c):
            if k not in self.rows:
                return None
            if self.writes(role, k):
                return "writer"
            return "steward" if self.steward_reaches(role, k) else None
        if not c.by_steward and self.author_alive(c, k) and self.privs(role, c.author):
            return "author"
        return "steward" if self.steward_reaches(role, k) else None

    def writes(self, role, k):
        """UPDATE on the table, and the row passing the role's row-level
        security for an UPDATE (policy p is FOR ALL: what it lets the role see)."""
        return k in self.rows and role in self.updaters and self.sees(role, k)

    def steward_reaches(self, role, k):
        """A steward's right reaches the rows row-level security does
        not keep it from (all, without it)."""
        return role in self.stewards and (not self.rls or self.sees(role, k))

    def may_change(self, role, k):
        """(The owner's rule (b).) Nobody claims by coming
        first. A claim that exists is changed by the table's owner, a steward of the watch that
        is not kept from its row by row-level security, or a role with the privileges of its
        author while the author is still that role (a claim whose author is gone or unknown: the
        owner or a steward only). A key with no claim gets one only if its row exists, from the
        owner, such a steward, or a role that may UPDATE the row (writes()); reading it is not
        enough. 0.19.0 had no such rule."""
        if self.version != "0.20.0":
            return True
        # a dead claim is claimed as a key with no claim; a claim made
        # with a steward's right alone gives its author none of its own (Model.how)
        return self.how(role, k) is not None

    def may_adopt(self, caller):
        """adopt() changes claims: the owner's or a steward's."""
        return self.version != "0.20.0" or caller == OWNER or caller in self.stewards

    def closes_cycle(self, old, new):
        """supersede(old, new) is refused when new's replacement chain leads back to old."""
        seen, k = set(), new
        while k is not None and k not in seen:
            if k == old:
                return True
            seen.add(k)
            c = self.claims.get(k)
            k = c.replaced_by if (c is not None and c.verdict == "replaced") else None
        return False

    def privs(self, role, author):
        return role == OWNER or role == author

    def proof_value(self, c, k):
        if c.proof in ENV_PROOFS:
            return c.envval
        if c.proof == "true":
            return True
        if c.proof == "false":
            return False
        t = self.text(k)
        return self.sees(c.author or OWNER, k) and t is not None and "ok" in t

    def served(self, k):
        """What _verdict() serves for key k (owner's view), as the code computes it."""
        c = self.claims.get(k)
        if c is None:
            return None
        # a claim about a row that is gone says nothing of the next one, whatever it read:
        # 'replaced' and 'expired' included (_claim_dead is the first test of _verdict_of)
        if self.dead(k, c):
            return "unproven"
        if c.verdict == "replaced":
            return "replaced"
        if c.expired:
            return "expired"
        if c.verdict in ("verified", "refuted") and c.proof is not None and not c.halted \
                and self.horizon:
            return "unproven"
        # (F5, fixed in 6068555) a proof's verdict is its author's; once no role has
        # that OID and name it reads unproven at once, as verify() would record it (_verdict_of)
        if c.verdict in ("verified", "refuted") and c.proof is not None \
                and c.author is not None and not self.author_alive(c, k):
            return "unproven"
        if c.verdict in ("verified", "refuted") and c.asserted != self.text(k):
            return "unproven"
        return c.verdict

    # --- operations (mirror the code; spec.md says where the code is the reference) ---
    def assert_(self, author, k, proof, expired, caller=None):
        how = self.how(caller or author, k) if self.version == "0.20.0" else None
        c = self.claims.get(k)
        was_replaced = c is not None and c.verdict == "replaced"
        n = c.copy() if c else Claim()
        n.proof = proof if proof != "none" else None
        n.author, n.gen = author, self.gen[author]
        n.row, n.here, n.by_steward = self.row_now(k), True, how == "steward"
        n.asserted = self.text(k) if (n.proof is not None and self.sees(author, k)) else None
        n.verdict = "replaced" if was_replaced else "unproven"
        n.halted, n.expired, n.retired, n.refuted_text = False, expired, False, None
        n.refute_ignored = False
        n.adopted_retired = False
        self.claims[k] = n

    def refute(self, k, role="fz_author"):
        c = self.claims.get(k)
        how = self.how(role, k) if self.version == "0.20.0" else None
        if self.version == "0.20.0":
            # 578af0f : refute() retires any claim, a replaced one too (it
            # stays replaced), drops the proof and records the text it refutes (U:432-445)
            if c is None:
                c = Claim()
                c.verdict = "refuted"
                self.claims[k] = c
            # the role that retired it is its author
            c.author, c.gen = role, self.gen[role]
            c.row, c.here, c.by_steward = self.row_now(k), True, how == "steward"
            if c.verdict != "replaced":
                c.verdict = "refuted"
            c.proof, c.halted, c.asserted = None, False, self.text(k)
            c.retired, c.refuted_text, c.refute_ignored = True, self.text(k), False
            return
        # 0.19.0: refute() of a replaced claim does nothing, and keeps the proof otherwise
        if c is not None and c.verdict == "replaced":
            c.refute_ignored = True
            c.retired, c.refuted_text = True, self.text(k)
            return
        if c is None:
            c = Claim()
            c.asserted = self.text(k)
            self.claims[k] = c
        c.verdict = "refuted"
        c.halted = False
        c.retired, c.refuted_text, c.reason19 = True, self.text(k), True

    def supersede(self, old, new, role="fz_author"):
        c = self.claims.get(old)
        how = self.how(role, old) if (c is None and self.version == "0.20.0") else None
        if c is not None:
            c.refute_ignored = False
        if c is None:
            c = Claim()
            if self.version == "0.20.0" and role in self.gen:
                c.author, c.gen = role, self.gen[role]     # the placeholder's author
                c.row, c.here, c.by_steward = self.row_now(old), True, how == "steward"
            self.claims[old] = c
        c.verdict, c.replaced_by = "replaced", new
        # supersede() sets changed_at: the order the update reads to break a 0.19.0 cycle
        self.sup_clock = getattr(self, "sup_clock", 0) + 1
        c.sup_at = self.sup_clock

    def unsupersede(self, k):
        c = self.claims.get(k)
        if c is not None and c.verdict == "replaced":
            # 578af0f: a retired claim comes back refuted, any other unproven (U:447-461);
            # F8 (3910404): a halted one too keeps its refuted (nothing judges it again)
            halted = c.halted and c.proof is not None
            c.verdict = "refuted" if (c.retired and c.proof is None) or halted else "unproven"
            c.replaced_by = None

    def judge(self, role, k, c):
        """verify()/verify_one() on one claim. Returns False when the model cannot say."""
        if c.proof is None or c.verdict == "replaced" or c.halted:
            return True
        if self.version != "0.20.0":       # 0.19.0: the verifier's rights, no claim binding
            c.verdict = "verified" if self.proof_value(c, k) else "refuted"
            c.retired, c.reason19 = False, False
            c.asserted = self.text(k)
            return True
        if c.author is None:
            return True                     # no author: does not run
        if not self.author_alive(c, k):
            c.verdict = "unproven"          # a gone author is due for anyone: unproven
            return True
        if not self.privs(role, c.author):
            return True
        t = self.text(k)
        if c.asserted != t:
            if c.verdict not in ("verified", "refuted"):
                c.verdict = "unproven"
            return True
        if not self.sees(c.author, k):
            c.uncertain = True
            return False
        c.verdict = "verified" if self.proof_value(c, k) else "refuted"
        c.rls_at = self.rls_epoch
        return True

    def adopt(self, author, caller="fz_author"):
        if not self.may_adopt(caller):
            return False
        for k, c in self.claims.items():
            # under row-level security an orphan on a row the
            # caller (or the new author) does not see is left alone; without it, every orphan
            if self.version == "0.20.0" and self.rls and caller != OWNER \
                    and not (self.sees(caller, k) and self.sees(author, k)):
                continue
            if c.proof is not None and c.verdict != "replaced" and not self.author_alive(c, k):
                keep = (c.retired, c.refuted_text)
                self.assert_(author, k, c.proof, c.expired, caller=caller)
                if c.proof in ENV_PROOFS:
                    # adopt() records the settings where it is called: a plain session
                    self.claims[k].env_set(c.proof, DEFAULT_SP, None)
                # adopt() is not an author asserting: a retired claim must stay retired
                # (README), so the model keeps the retirement for INV-RETIRED
                n = self.claims[k]
                n.retired, n.refuted_text = keep
                n.adopted_retired = keep[0]
        return True

    def rebind(self):
        """phasevec.rebind() by the table's owner: every claim whose
        author is not the owner is an orphan, and the watch has no steward."""
        for c in self.claims.values():
            if c.author is not None and c.author != OWNER:
                c.here = False
        self.stewards.clear()

    def upgrade(self):
        self.version = "0.20.0"
        self.updaters = set(AUTHORS)   # GRANTS_SQL, run with the update
        for k, c in self.claims.items():
            c.author = None
            c.row = None
            # 578af0f: the update retires what 0.19.0's refute() refuted (U:674-690): a refuted
            # claim with no proof or refuted by refute(), and a replaced one with a reason
            reason = getattr(c, "reason19", False)
            retire = ((c.verdict == "refuted" and (c.proof is None or (c.retired and reason)))
                      or (c.verdict == "replaced" and reason))
            if c.verdict == "verified":
                c.verdict, c.asserted = "unproven", None
            elif c.verdict == "refuted":
                c.asserted = self.text(k)
            else:
                c.asserted = None
            if retire:
                c.proof, c.halted = None, False
                c.retired, c.refute_ignored = True, False
                if c.verdict == "replaced":
                    c.asserted = self.text(k)
                # 0.19.0 kept no text for a claim: the update ties it to the row's text as it
                # is now (U:668-673 at 8902c9b), so with no row at the update it is about no
                # text, and a row that comes back later is another text (the [NOTE] of
                # INV-RETIRED; seed 58820081)
                c.refuted_text = self.text(k)
            elif c.retired:
                # refute() of a replaced claim did nothing under 0.19.0: no column shows it, so
                # the update cannot retire it (U:678-680, "the application refutes it again")
                c.retired, c.refuted_text = False, None
        # of each supersede cycle 0.19.0 took, the newest link (changed_at, then the greatest
        # key) is undone as unsupersede() undoes it, after the claims are retired
        # (_migrate_claims); a harness false positive
        # (findings/model-INV-MODEL.cycle019-seed2950108.json) was this step missing here
        while True:
            on = [k for k, c in self.claims.items() if c.verdict == "replaced"
                  and c.replaced_by is not None and self.closes_cycle(k, c.replaced_by)]
            if not on:
                break
            k = max(on, key=lambda k: (getattr(self.claims[k], "sup_at", 0), k))
            self.unsupersede(k)


# ----------------------------------------------------------------------------- operations --
def gen_op(rng, m):
    k = rng.choice(KEYS)
    k2 = rng.choice(KEYS)
    w = [
        ("write", 14), ("assert", 14), ("verify", 10), ("verify_one", 5), ("refute", 6),
        ("supersede", 4), ("unsupersede", 4), ("rls", 3), ("horizon", 3), ("adopt", 3),
        ("unauthorized", 4), ("drop_role", 1), ("conc_edit_verify", 2), ("conc_assert_verify", 2),
        ("dump_restore", 0.4), ("conc_refute_old_txn", 1),
        ("conc_refute_adopt", 1), ("conc_assert_adopt", 1), ("truncate", 0.7),
        ("env_assert", 3), ("env_assert2", 4), ("conc_truncate_verify", 2),
        ("conc_truncate_assert", 1.5), ("conc_supersede_verify", 1.5), ("conc_refute_verify", 1.5),
        ("conc_old_assert_verify", 2), ("conc_unsupersede_verify", 1.5),
        ("conc_write_assert", 2), ("conc_assert_assert", 1.5), ("steward", 3),
        ("update_grant", 2), ("reinsert", 3), ("rebind", 0.6),
    ]
    boost = float(os.environ.get("FZ_CONC_BOOST", "1"))
    w = [(x, y * boost if x.startswith("conc_") else y) for x, y in w]
    kind = rng.choices([x for x, _ in w], [y for _, y in w])[0]
    if kind == "write":
        sub = rng.choice(["update", "update", "insert", "delete", "tenant"])
        return {"op": "write", "sub": sub, "k": k, "text": rng.choice(TEXTS),
                "tenant": rng.choice(TENANTS)}
    if kind == "assert":
        return {"op": "assert", "author": rng.choice(AUTHORS), "k": k,
                "proof": rng.choice(list(PROOFS)), "expired": rng.random() < 0.08}
    if kind in ("verify",):
        return {"op": "verify", "role": rng.choice([OWNER] + AUTHORS)}
    if kind == "verify_one":
        return {"op": "verify_one", "role": rng.choice([OWNER] + AUTHORS), "k": k}
    if kind == "refute":
        return {"op": "refute", "k": k}
    if kind == "supersede":
        return {"op": "supersede", "old": k, "new": k2}
    if kind == "unsupersede":
        return {"op": "unsupersede", "k": k}
    if kind == "rls":
        return {"op": "rls", "on": not m.rls if m else rng.random() < 0.5}
    if kind == "horizon":
        return {"op": "horizon", "tiny": rng.random() < 0.5}
    if kind == "adopt":
        return {"op": "adopt"}
    if kind == "steward":
        return {"op": "steward", "on": rng.random() < 0.6}
    if kind == "update_grant":
        return {"op": "update_grant", "on": rng.random() < 0.6}
    if kind == "reinsert":
        # another role deletes the row and writes one
        # under its key again: the same text or another, in one transaction or two
        return {"op": "reinsert", "k": k, "text": rng.choice(TEXTS), "tenant": rng.choice(TENANTS),
                "txn": rng.random() < 0.5}
    if kind == "rebind":
        return {"op": "rebind", "all": rng.random() < 0.5}
    if kind == "unauthorized":
        return {"op": "unauthorized", "role": rng.choice([READER, OUTSIDER, "fz_author_b"]),
                "what": rng.choice(["assert", "refute", "supersede", "verify", "adopt_b",
                                    "verify_one_other", "write_truth"]), "k": k}
    if kind == "drop_role":
        return {"op": "drop_role"}
    if kind == "conc_edit_verify":
        return {"op": "conc_edit_verify", "k": k, "a": rng.choice(TEXTS), "b": rng.choice(TEXTS)}
    if kind == "conc_assert_verify":
        return {"op": "conc_assert_verify", "k": k, "author": rng.choice(AUTHORS),
                "proof": rng.choice(["ok", "true", "false"])}
    if kind == "conc_refute_old_txn":
        return {"op": "conc_refute_old_txn", "k": k}
    if kind == "conc_refute_adopt":
        return {"op": "conc_refute_adopt", "k": k}
    if kind == "conc_assert_adopt":
        return {"op": "conc_assert_adopt", "k": k, "proof": rng.choice(["ok", "true", "false"])}
    if kind == "truncate":
        return {"op": "truncate"}
    if kind == "env_assert":
        via = rng.choice(["direct", "wrapper", "wrapper_local"])
        author = rng.choice(AUTHORS) if via == "direct" else "fz_author"
        caller = author if via == "direct" else rng.choice(["fz_author", READER, "fz_author_b"])
        return {"op": "env_assert", "via": via, "author": author, "caller": caller, "k": k,
                "proof": rng.choice(list(ENV_PROOFS)), "sp": rng.choice(SP_CHOICES),
                "ds": rng.choice(DS_CHOICES), "vrole": rng.choice([OWNER] + AUTHORS),
                "vsp": rng.choice(SP_CHOICES), "vds": rng.choice(DS_CHOICES)}
    if kind == "env_assert2":
        return {"op": "env_assert2", "how": rng.choice(["set_local", "caller_fn", "role_ds",
                                                         "set_config_local", "caller_fn_definer"]),
                "fn": rng.choice(["fz_env.assert_via", "fz_env.assert_local"]),
                "caller": rng.choice(["fz_author", READER, "fz_author_b"]), "k": k,
                "proof": rng.choice(list(ENV_PROOFS)), "sp": rng.choice(SP_CHOICES),
                "ds": rng.choice([d for d in DS_CHOICES if d]),
                "vrole": rng.choice([OWNER] + AUTHORS), "vds": rng.choice(DS_CHOICES)}
    if kind == "conc_truncate_verify":
        return {"op": "conc_truncate_verify", "texts": [rng.choice(TEXTS + [None]) for _ in KEYS],
                "via": rng.choice(["verify", "verify_one"]), "k": k,
                "vrole": rng.choice([OWNER] + AUTHORS), "commit": rng.random() < 0.8}
    if kind == "conc_truncate_assert":
        return {"op": "conc_truncate_assert", "texts": [rng.choice(TEXTS + [None]) for _ in KEYS],
                "k": k, "author": rng.choice(AUTHORS), "proof": rng.choice(["ok", "true", "false"])}
    if kind == "conc_supersede_verify":
        return {"op": "conc_supersede_verify", "old": k, "new": k2,
                "via": rng.choice(["verify", "verify_one"])}
    if kind == "conc_refute_verify":
        return {"op": "conc_refute_verify", "k": k, "via": rng.choice(["verify", "verify_one"]),
                "reassert": rng.random() < 0.5, "proof": rng.choice(["ok", "true", "false"])}
    if kind in ("conc_old_assert_verify", "conc_unsupersede_verify"):
        return {"op": kind, "k": k, "author": rng.choice(AUTHORS),
                "proof": rng.choice(["ok", "true", "false"]),
                "via": rng.choice(["verify", "verify_one"]), "lead": rng.choice([0.05, 0.2, 0.5])}
    if kind == "conc_write_assert":
        return {"op": kind, "k": k, "author": rng.choice(AUTHORS), "text": rng.choice(TEXTS),
                "proof": rng.choice(["ok", "true", "false"]), "commit": rng.random() < 0.8}
    if kind == "conc_assert_assert":
        return {"op": kind, "k": k, "p1": rng.choice(["ok", "true", "false"]),
                "p2": rng.choice(["ok", "true", "false"]), "verify": rng.random() < 0.5}
    return {"op": "dump_restore"}


def gen_v19_op(rng):
    k = rng.choice(KEYS)
    kind = rng.choices(["assert", "refute", "verify", "write", "supersede"], [5, 4, 2, 3, 1])[0]
    if kind == "assert":
        return {"op": "v19_assert", "k": k, "proof": rng.choice(["ok", "true", "false"])}
    if kind == "refute":
        return {"op": "refute", "k": k}
    if kind == "verify":
        return {"op": "v19_verify"}
    if kind == "supersede":
        return {"op": "supersede", "old": k, "new": rng.choice(KEYS)}
    return {"op": "write", "sub": rng.choice(["update", "insert", "delete"]), "k": k,
            "text": rng.choice(TEXTS), "tenant": rng.choice(TENANTS)}


def gen_sequence(rng, steps, upgrade_p):
    seq = []
    if rng.random() < upgrade_p:
        seq.append({"op": "start", "version": "0.19.0"})
        seq += [gen_v19_op(rng) for _ in range(rng.randint(2, 8))]
        # half of them move the 0.19.0 database by pg_dump/pg_restore where
        # 0.20.0 is installed, then phasevec.migrate(): the model is the update's
        seq.append({"op": "upgrade" if rng.random() < 0.5 else "restore_upgrade"})
    else:
        seq.append({"op": "start", "version": "0.20.0"})
    seq += [gen_op(rng, None) for _ in range(steps)]
    return seq


# -------------------------------------------------------------------------------- runner --
class Violation(Exception):
    """inv is "INVARIANT/cause": findings are told apart (and skipped) by both."""

    def __init__(self, inv, detail):
        super().__init__(f"{inv}: {detail}")
        self.inv = inv
        self.detail = detail


class Runner:
    def __init__(self, cl, skip=(), log=None):
        self.cl = cl
        self.skip = set(skip)
        self.log = log
        self.m = None
        self.last_va = {}
        self.texts_by_hash = {}

    def skipped(self, inv):
        return any(inv == x or inv.startswith(x + "/") for x in self.skip)

    def fail(self, inv, detail):
        if not self.skipped(inv):
            raise Violation(inv, detail)

    # --- setup ---
    def templates(self):
        for ver, name in (("", "fz_t20"), (" VERSION '0.19.0'", "fz_t19")):
            self.cl.must(OWNER, f"CREATE DATABASE {name};", db="postgres")
            self.cl.must(OWNER, TEMPLATE_SQL.format(ver=ver, cols=RECIPE_COLS, recipe=RECIPE),
                         db=name)
            if not ver:
                self.cl.must(OWNER, "UPDATE phasevec.watches SET max_age = interval '1 day';",
                             db=name)

    def reset(self, version):
        self.cl.must(OWNER, "DROP DATABASE IF EXISTS fz WITH (FORCE);", db="postgres")
        self.cl.must(OWNER, "DROP DATABASE IF EXISTS fz_r WITH (FORCE);", db="postgres")
        self.cl.must(OWNER, "".join(f"DROP ROLE IF EXISTS {r};" for r in ROLES), db="postgres")
        self.cl.must(OWNER, "".join(f"CREATE ROLE {r} LOGIN;" for r in ROLES), db="postgres")
        tmpl = "fz_t20" if version == "0.20.0" else "fz_t19"
        self.cl.must(OWNER, f"CREATE DATABASE fz TEMPLATE {tmpl};", db="postgres")
        if version == "0.20.0":
            self.cl.must(OWNER, GRANTS_SQL)
        else:
            self.cl.must(OWNER, "GRANT USAGE ON SCHEMA phasevec TO fz_writer;"
                                "GRANT SELECT, INSERT, UPDATE, DELETE ON public.notes "
                                "TO fz_writer;")
        self.m = Model()
        self.m.version = version
        self.last_va = {}

    # --- one step ---
    def step(self, op):
        m, cl = self.m, self.cl
        o = op["op"]
        expect_ok = True
        sql, role = None, OWNER
        if o == "start":
            self.reset(op["version"])
            return
        if o == "write":
            k, t, ten = op["k"], op["text"], op["tenant"]
            # 0.19.0's watch trigger is PL/pgSQL calling _note(), which a writer may not execute
            role = WRITER if m.version == "0.20.0" else OWNER
            if op["sub"] == "insert":
                sql = (f"INSERT INTO public.notes VALUES ({k}, {q(t)}, {q(ten)}) "
                       "ON CONFLICT (id) DO NOTHING;")
                if k not in m.rows:
                    m.rows[k] = (t, ten)
                    m.reborn.add(k)
            elif op["sub"] == "update":
                sql = f"UPDATE public.notes SET body = {q(t)} WHERE id = {k};"
                if k in m.rows:
                    m.rows[k] = (t, m.rows[k][1])
            elif op["sub"] == "tenant":
                sql = f"UPDATE public.notes SET tenant = {q(ten)} WHERE id = {k};"
                if k in m.rows:
                    m.rows[k] = (m.rows[k][0], ten)
                    # under RLS a tenant change is a policy change for this row: the text (what a
                    # verdict binds) is the same, but who sees the row is not, so a proof may read
                    # it differently until the next verify() or the horizon, as after an RLS toggle
                    # (spec.md 5.2; seed 31337059)
                    if m.rls and k in m.claims:
                        m.claims[k].rls_at = -1
            else:
                sql = f"DELETE FROM public.notes WHERE id = {k};"
                m.rows.pop(k, None)
        elif o == "v19_assert":
            pr = PROOFS[op["proof"]].format(k=op["k"])
            sql = f"SELECT phasevec.assert('notes', {q(op['k'])}, {q(pr)});"
            c = m.claims.get(op["k"])
            n = c.copy() if c else Claim()
            n.proof = op["proof"]
            n.verdict = "replaced" if (c and c.verdict == "replaced") else "unproven"
            n.retired, n.refuted_text, n.reason19 = False, None, False
            m.claims[op["k"]] = n
        elif o == "v19_verify":
            sql = "SELECT count(*) FROM phasevec.verify('notes', p_every => interval '0');"
            for k, c in m.claims.items():
                m.judge(OWNER, k, c)
        elif o == "upgrade":
            sql = ("ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0';"
                   "UPDATE phasevec.watches SET max_age = interval '1 day';" + GRANTS_SQL)
            m.upgrade()
        elif o == "restore_upgrade":
            return self.restore_upgrade()
        elif o == "assert":
            pr = PROOFS[op["proof"]]
            pr = pr.format(k=op["k"]) if pr else None
            exp = "now() - interval '1 day'" if op["expired"] else "NULL"
            role = op["author"]
            sql = f"SELECT phasevec.assert('notes', {q(op['k'])}, {q(pr)}, NULL, NULL, {exp});"
            # another author's claim, or a row it does not see: refused,
            # and phasevec.truth unchanged (INV-AUTHOR)
            if m.may_change(role, op["k"]):
                m.assert_(role, op["k"], op["proof"], op["expired"])
                self.last_va.pop(op["k"], None)
            else:
                expect_ok = False
        elif o == "verify":
            role = op["role"]
            sql = ("SELECT count(*) FROM phasevec.verify('notes', 100, interval '0', "
                   "interval '60 s', 2000);")
            for k, c in sorted(m.claims.items()):
                m.judge(role, k, c)
        elif o == "verify_one":
            role, k = op["role"], op["k"]
            sql = f"SELECT phasevec.verify_one('notes', {q(k)});"
            c = m.claims.get(k)
            # verify_one() refuses: no claim, no proof, no author, an author the caller is not
            ok = (c is not None and c.proof is not None and c.verdict != "replaced"
                  and c.author is not None
                  and (not m.author_alive(c, k) or m.privs(role, c.author)))
            expect_ok = None  # it also refuses what it could not judge: checked by the model below
            if ok:
                m.judge(role, k, c)
        elif o == "refute":
            sql = f"SELECT phasevec.refute('notes', {q(op['k'])}, 'fuzz');"
            role = OWNER if m.version != "0.20.0" else "fz_author"
            if m.may_change(role, op["k"]):
                m.refute(op["k"], role)
            else:
                expect_ok = False
        elif o == "supersede":
            old, new = op["old"], op["new"]
            role = OWNER if m.version != "0.20.0" else "fz_author"
            sql = f"SELECT phasevec.supersede('notes', {q(old)}, {q(new)}, 'fuzz');"
            if old == new or new not in m.rows or not m.may_change(role, old) \
                    or (m.version == "0.20.0" and m.closes_cycle(old, new)):
                expect_ok = False
            else:
                m.supersede(old, new, role)
        elif o == "unsupersede":
            role = "fz_author"
            sql = f"SELECT phasevec.unsupersede('notes', {q(op['k'])});"
            if m.may_change(role, op["k"]):
                m.unsupersede(op["k"])
                self.last_va.pop(op["k"], None)
            else:
                expect_ok = False
        elif o == "rls":
            onoff = 'ENABLE' if op['on'] else 'DISABLE'
            sql = f"ALTER TABLE public.notes {onoff} ROW LEVEL SECURITY;"
            m.rls = op["on"]
            m.rls_epoch += 1
        elif o == "horizon":
            sql = ("UPDATE phasevec.watches SET max_age = interval "
                   f"{q('1 microsecond' if op['tiny'] else '1 day')};")
            m.horizon = op["tiny"]
        elif o == "adopt":
            role = "fz_author"
            sql = "SELECT count(*) FROM phasevec.adopt('notes', 'fz_author');"
            if m.adopt("fz_author"):
                self.last_va = {}
            else:
                expect_ok = False
        elif o == "steward":
            # the table's owner names fz_author a steward of the watch, or
            # no longer; 0.19.0 has no stewards
            if m.version != "0.20.0":
                return
            role = OWNER
            on = "true" if op["on"] else "false"
            sql = f"SELECT phasevec.steward('notes', 'fz_author', {on});"
            if op["on"]:
                m.stewards.add("fz_author")
            else:
                m.stewards.discard("fz_author")
        elif o == "update_grant":
            # fz_author holds UPDATE on the table, or no longer: what lets
            # it claim a row first (a reader does not)
            role = OWNER
            sql = ("GRANT UPDATE ON public.notes TO fz_author;" if op["on"]
                   else "REVOKE UPDATE ON public.notes FROM fz_author;")
            if op["on"]:
                m.updaters.add("fz_author")
            else:
                m.updaters.discard("fz_author")
        elif o == "reinsert":
            # the writer deletes the row and writes it again: another row
            if m.version != "0.20.0":
                return
            k, t, ten = op["k"], op["text"], op["tenant"]
            role = WRITER
            sql = (("BEGIN; " if op["txn"] else "")
                   + f"DELETE FROM public.notes WHERE id = {k}; "
                   + f"INSERT INTO public.notes VALUES ({k}, {q(t)}, {q(ten)});"
                   + (" COMMIT;" if op["txn"] else ""))
            m.rows[k] = (t, ten)
            m.reborn.add(k)
        elif o == "rebind":
            # the table's owner cuts what a copy would have inherited
            if m.version != "0.20.0":
                return
            role = OWNER
            sql = ("SELECT count(*) FROM phasevec.rebind();" if op["all"]
                   else "SELECT count(*) FROM phasevec.rebind('notes');")
            m.rebind()
        elif o == "truncate":
            # F9 (3910404): the watch's TRUNCATE trigger forgets every row it noted, so
            # nothing of a gone row is served or counted (the update gives old watches the trigger)
            sql = "TRUNCATE public.notes;"
            m.rows.clear()
        elif o == "drop_role":
            sql = ("DROP OWNED BY fz_author_b; DROP ROLE fz_author_b; "
                   "CREATE ROLE fz_author_b LOGIN;" + GRANTS_B)
            m.gen["fz_author_b"] += 1
            m.updaters.add("fz_author_b")
        elif o == "unauthorized":
            return self.unauthorized(op)
        elif o == "conc_edit_verify":
            return self.conc_edit_verify(op)
        elif o == "conc_assert_verify":
            return self.conc_assert_verify(op)
        elif o == "dump_restore":
            return self.dump_restore()
        elif o == "conc_refute_old_txn":
            return self.conc_refute_old_txn(op)
        elif o in ("conc_refute_adopt", "conc_assert_adopt"):
            return self.conc_adopt(op)
        elif o == "env_assert":
            return self.env_assert(op)
        elif o == "env_assert2":
            return self.env_assert2(op)
        elif o in ("conc_truncate_verify", "conc_truncate_assert", "conc_supersede_verify",
                   "conc_refute_verify", "conc_old_assert_verify", "conc_unsupersede_verify",
                   "conc_write_assert", "conc_assert_assert"):
            return getattr(self, o)(op)
        if sql is None:
            raise SystemExit(f"unknown op {o!r} in {op}")
        before = self.truth_digest() if expect_ok is False and m.version == "0.20.0" else None
        rc, out, err = cl.sql(role, sql)
        if expect_ok is True and rc != 0:
            raise Violation("MODEL-ERROR", f"{op} failed: {err.strip()[:300]}")
        if expect_ok is False and rc == 0:
            inv = ("INV-AUTHOR" if o in ("assert", "refute", "unsupersede", "supersede", "adopt")
                   else "MODEL-ERROR")
            raise Violation(inv, f"{op} should have failed and did not")
        if before is not None and self.truth_digest() != before:
            raise Violation("INV-AUTHOR", f"{op} was refused and changed phasevec.truth")
        if o == "verify_one" and rc != 0:
            # it could not judge (lock, stale...): the model learns from the database
            self.resync([op["k"]])

    # --- adversarial and concurrent steps ---
    def allowed(self, a, k):
        """The author a step that asserts key k runs as: `a` when it may
        change the claim, else the claim's own author (one of AUTHORS, still known), else None:
        the step is skipped (a race step expects its writes to go through)."""
        m = self.m
        if m.may_change(a, k):
            return a
        c = m.claims.get(k)
        if c is not None and c.author in AUTHORS and m.may_change(c.author, k):
            return c.author
        return None

    def truth_digest(self):
        return self.cl.must(OWNER, "SELECT md5(coalesce(string_agg(t::text, ',' ORDER BY key), "
                                   "'')) FROM phasevec.truth t;").strip()

    def unauthorized(self, op):
        role, k, w = op["role"], op["k"], op["what"]
        sqls = {
            "assert": f"SELECT phasevec.assert('notes', {q(k)}, 'SELECT true');",
            "refute": f"SELECT phasevec.refute('notes', {q(k)}, 'evil');",
            "supersede": f"SELECT phasevec.supersede('notes', {q(k)}, '1', 'evil');",
            "verify": "SELECT count(*) FROM phasevec.verify('notes', p_every => interval '0');",
            "adopt_b": "SELECT count(*) FROM phasevec.adopt('notes', 'fz_author');",
            "verify_one_other": f"SELECT phasevec.verify_one('notes', {q(k)});",
            "write_truth": f"UPDATE phasevec.truth SET verdict = 'verified' WHERE key = {q(k)};",
        }
        if role == "fz_author_b" and w in ("assert", "verify"):
            w = "refute"        # fz_author_b may assert and verify its own: not unauthorized
        if role == "fz_author_b" and w == "verify_one_other":
            c = self.m.claims.get(k)
            # a claim with no proof runs nothing: verify_one() answers NULL and changes nothing
            # (seed 20261238, on 8902c9b and on 6068555 alike), not a breach;
            # nor does a replaced one: _truth_of() has no row for it, and verify_one() answers
            # NULL before it asks for the author's rights (U:515-524, T:3803-3811 at 8902c9b;
            # seed 47130021)
            if (c is None or c.proof is None or c.verdict == "replaced" or c.author == "fz_author_b"
                    or c.author is None or not self.m.author_alive(c, k)):
                w = "refute"
        before = self.truth_digest()
        rc, out, err = self.cl.sql(role, sqls[w])
        after = self.truth_digest()
        if rc == 0:
            raise Violation("INV-PRIV", f"{role} ran {w} on key {k} without the right: "
                                        f"{out.strip()}")
        if before != after:
            raise Violation("INV-PRIV", f"{role} {w} on key {k} changed phasevec.truth")

    def env_assert(self, op):
        """Assert under one session's settings (directly, or through fz_author's wrapper with a SET
        clause, or with SET LOCAL in its body), then verify() from a session with others. The model
        follows the README: a claim records what is in effect where assert() is called, as its
        author has it there; a wrapper's SET clause is the author's; a caller without the author's
        privileges lends nothing; DateStyle, which a SET merges into the value it replaces, is the
        author's only when what it was built on is too , else the author's own."""
        m = self.m
        k, kind, via, author, caller = op["k"], op["proof"], op["via"], op["author"], op["caller"]
        if not m.may_change(author, k):
            # not this author's claim: directly, its author asserts it;
            # through fz_author's wrapper, the step is skipped
            author = self.allowed(author, k) if via == "direct" else None
            if author is None:
                return
            caller = author
        sets = env_sets(op["sp"], op["ds"])
        p = ENV_PROOFS[kind]
        if via == "direct":
            sql = sets + f"SELECT phasevec.assert('notes', {q(k)}, {q(p)});"
            sp, ds = op["sp"] or DEFAULT_SP, op["ds"]
        else:
            fn = "fz_env.assert_via" if via == "wrapper" else "fz_env.assert_local"
            sql = sets + f"SELECT {fn}({q(k)}, {q(p)});"
            sp = WRAPPER_SP[via]
            # the wrapper sets the style only: the order is the caller's, when the caller is one
            # whose settings the author's are (here: the author itself); otherwise not recorded
            ds = op["ds"] if m.privs(caller, author) and caller != OWNER else None
        rc, out, err = self.cl.sql(caller, sql)
        if rc != 0:
            raise Violation("MODEL-ERROR", f"{op} failed: {err.strip()[:300]}")
        m.assert_(author, k, kind, False)
        m.claims[k].env_set(kind, sp, ds)
        self.last_va.pop(k, None)
        vsets = env_sets(op["vsp"], op["vds"])
        rc, out, err = self.cl.sql(op["vrole"], vsets + "SELECT count(*) FROM phasevec.verify("
                                   "'notes', 100, interval '0', interval '60 s', 2000);")
        if rc != 0:
            raise Violation("MODEL-ERROR", f"verify() after {op} failed: {err.strip()[:300]}")
        for kk, c in sorted(m.claims.items()):
            m.judge(op["vrole"], kk, c)

    def env_assert2(self, op):
        """More ways a caller reaches the author's wrapper with its own
        DateStyle: SET LOCAL in its transaction, the SET clause of the caller's own function
        (invoker or definer), ALTER ROLE caller SET, set_config(..., true). The README: the
        caller's settings count only when the caller has the author's privileges; the wrapper's
        SET clause (search_path, the DateStyle style) is the author's; a DateStyle merged over a
        caller's value is not recorded at all (the proof has the author's own: ISO, MDY)."""
        m = self.m
        k, kind, how, caller, fn = op["k"], op["proof"], op["how"], op["caller"], op["fn"]
        author = "fz_author"
        if not m.may_change(author, k):
            return
        ds = op["ds"]
        p = ENV_PROOFS[kind]
        call = f"SELECT {fn}({q(k)}, {q(p)});"
        spset = f"SET search_path = {op['sp']};" if op["sp"] else ""
        pre, post = "", ""
        if how == "set_local":
            sql = f"BEGIN; SET LOCAL DateStyle = {q(ds)}; {spset} {call} COMMIT;"
        elif how == "set_config_local":
            sql = f"BEGIN; SELECT set_config('datestyle', {q(ds)}, true); {spset} {call} COMMIT;"
        elif how in ("caller_fn", "caller_fn_definer"):
            name = f"fz_c.f_{caller}"
            sec = "SECURITY DEFINER" if how == "caller_fn_definer" else ""
            sql = (f"CREATE OR REPLACE FUNCTION {name}(k text, p text) RETURNS void LANGUAGE sql "
                   f"{sec} SET DateStyle = {q(ds)} AS $f$ SELECT {fn}(k, p) $f$; "
                   f"{spset} SELECT {name}({q(k)}, {q(p)});")
        else:  # role_ds
            pre = f"ALTER ROLE {caller} SET DateStyle = {q(ds)};"
            post = f"ALTER ROLE {caller} RESET DateStyle;"
            sql = f"{spset} {call}"
        if pre:
            self.cl.must(OWNER, pre)
        try:
            rc, out, err = self.cl.sql(caller, sql)
        finally:
            if post:
                self.cl.must(OWNER, post)
        if rc != 0:
            raise Violation("MODEL-ERROR", f"{op} failed: {err.strip()[:300]}")
        m.assert_(author, k, kind, False)
        m.claims[k].env_set(kind, WRAPPER_SP["wrapper" if fn == "fz_env.assert_via" else
                                             "wrapper_local"],
                            ds if m.privs(caller, author) else None)
        self.last_va.pop(k, None)
        vsets = env_sets(None, op["vds"])
        rc, out, err = self.cl.sql(op["vrole"], vsets + "SELECT count(*) FROM phasevec.verify("
                                   "'notes', 100, interval '0', interval '60 s', 2000);")
        if rc != 0:
            raise Violation("MODEL-ERROR", f"verify() after {op} failed: {err.strip()[:300]}")
        for kk, c in sorted(m.claims.items()):
            m.judge(op["vrole"], kk, c)

    def _truncate_sql(self, texts, commit=True, sleep=0.5):
        ins = [f"({k}, {q(t)}, {q(TENANTS[i % 2])})" for i, (k, t) in enumerate(zip(KEYS, texts))
               if t is not None]
        sql = "BEGIN; TRUNCATE public.notes; "
        if ins:
            sql += "INSERT INTO public.notes VALUES " + ", ".join(ins) + "; "
        sql += f"SELECT pg_sleep({sleep}); " + ("COMMIT;" if commit else "ROLLBACK;")
        return sql

    def _apply_truncate(self, texts):
        self.m.rows = {k: (t, TENANTS[i % 2]) for i, (k, t) in enumerate(zip(KEYS, texts))
                       if t is not None}
        self.m.reborn |= set(self.m.rows)

    def conc_truncate_verify(self, op):
        """TRUNCATE and the rows written again in one transaction, while a
        verify() or verify_one() waits for the table. Model-free invariants judge it."""
        w = self.cl.popen(WRITER, self._truncate_sql(op["texts"], op["commit"]))
        time.sleep(0.15)
        if op["via"] == "verify":
            self.cl.sql(op["vrole"], "SELECT count(*) FROM phasevec.verify('notes', 100, "
                                     "interval '0', interval '60 s', 2000);")
        else:
            self.cl.sql(op["vrole"], f"SELECT phasevec.verify_one('notes', {q(op['k'])});")
        w.communicate(timeout=60)
        if op["commit"]:
            self._apply_truncate(op["texts"])
        self.resync(KEYS, keep_meta=True)

    def conc_truncate_assert(self, op):
        k, a = op["k"], self.allowed(op["author"], op["k"])
        # under RLS who sees the row changes with the TRUNCATE and the rows written again
        if a is None or self.m.rls:
            return
        pr = PROOFS[op["proof"]].format(k=k)
        w = self.cl.popen(WRITER, self._truncate_sql(op["texts"], True, 0.3))
        loop = "".join(f"SELECT phasevec.assert('notes', {q(k)}, {q(pr)}); SELECT pg_sleep(0.1);"
                       for _ in range(5))
        p = self.cl.popen(a, loop + "SELECT count(*) FROM phasevec.verify('notes', 100, "
                             "interval '0', interval '60 s', 2000);")
        w.communicate(timeout=60)
        p.communicate(timeout=60)
        self._apply_truncate(op["texts"])
        self.m.assert_(a, k, op["proof"], False)
        self.last_va.pop(k, None)
        self.resync([k], keep_meta=True)
        self.resync([x for x in KEYS if x != k], keep_meta=True)

    def conc_supersede_verify(self, op):
        old, new = op["old"], op["new"]
        p = self.cl.popen("fz_author", f"BEGIN; SELECT phasevec.supersede('notes', {q(old)}, "
                                       f"{q(new)}, 'conc'); SELECT pg_sleep(0.4); COMMIT;")
        time.sleep(0.1)
        if op["via"] == "verify":
            self.cl.sql(OWNER, "SELECT count(*) FROM phasevec.verify('notes', 100, interval '0', "
                               "interval '60 s', 2000);")
        else:
            self.cl.sql(OWNER, f"SELECT phasevec.verify_one('notes', {q(old)});")
        p.communicate(timeout=60)
        self.resync(KEYS, keep_meta=True)

    def _verify_sql(self, via, k):
        if via == "verify":
            return ("SELECT count(*) FROM phasevec.verify('notes', 100, interval '0', "
                    "interval '60 s', 2000);")
        return f"SELECT phasevec.verify_one('notes', {q(k)});"

    def conc_old_assert_verify(self, op):
        """assert() of a new proof in a transaction that began before a
        verifier took the claim, waiting for its row and committing after the verdict."""
        k, a = op["k"], self.allowed(op["author"], op["k"])
        if a is None:
            return
        pr = PROOFS[op["proof"]].format(k=k)
        p = self.cl.popen(a, f"BEGIN; SELECT now(); SELECT pg_sleep({op['lead']}); "
                             f"SELECT phasevec.assert('notes', {q(k)}, {q(pr)}); "
                             f"SELECT pg_sleep(0.3); COMMIT;")
        time.sleep(0.02)
        self.cl.sql(OWNER, self._verify_sql(op["via"], k))
        p.communicate(timeout=60)
        self.m.assert_(a, k, op["proof"], False)
        self.last_va.pop(k, None)
        self.resync([k], keep_meta=True)
        self.resync([x for x in KEYS if x != k], keep_meta=True)

    def conc_unsupersede_verify(self, op):
        """unsupersede() racing a verifier, then a verifier again."""
        k = op["k"]
        p = self.cl.popen("fz_author", f"BEGIN; SELECT pg_sleep({op['lead']}); "
                                       f"SELECT phasevec.unsupersede('notes', {q(k)}); "
                                       f"SELECT pg_sleep(0.3); COMMIT;")
        time.sleep(0.02)
        self.cl.sql(OWNER, self._verify_sql(op["via"], k))
        p.communicate(timeout=60)
        self.cl.sql(OWNER, self._verify_sql(op["via"], k))
        self.resync(KEYS, keep_meta=True)

    def conc_write_assert(self, op):
        """a row write held open while assert() reads the row; then verify."""
        k, a = op["k"], op["author"]
        if k not in self.m.rows:
            return
        pr = PROOFS[op["proof"]].format(k=k)
        w = self.cl.popen(WRITER, f"BEGIN; UPDATE public.notes SET body = {q(op['text'])} "
                                  f"WHERE id = {k}; SELECT pg_sleep(0.4); "
                                  + ("COMMIT;" if op["commit"] else "ROLLBACK;"))
        time.sleep(0.1)
        rc, out, err = self.cl.sql(a, f"SELECT phasevec.assert('notes', {q(k)}, {q(pr)});")
        w.communicate(timeout=60)
        if rc == 0:
            self.m.assert_(a, k, op["proof"], False)
        if op["commit"]:
            self.m.rows[k] = (op["text"], self.m.rows[k][1])
        self.cl.sql(OWNER, self._verify_sql("verify", k))
        self.last_va.pop(k, None)
        self.resync(KEYS, keep_meta=True)

    def conc_assert_assert(self, op):
        """two authors assert one key at once; a verifier may run between."""
        k = op["k"]
        p1 = self.cl.popen("fz_author", f"BEGIN; SELECT phasevec.assert('notes', {q(k)}, "
                                        f"{q(PROOFS[op['p1']].format(k=k))}); "
                                        "SELECT pg_sleep(0.3); COMMIT;")
        time.sleep(0.05)
        p2 = self.cl.popen("fz_author_b", f"SELECT phasevec.assert('notes', {q(k)}, "
                                      f"{q(PROOFS[op['p2']].format(k=k))});")
        if op["verify"]:
            self.cl.sql(OWNER, self._verify_sql("verify", k))
        p1.communicate(timeout=60)
        p2.communicate(timeout=60)
        rc, out, _ = self.cl.sql(OWNER, f"SELECT asserted_by, proof FROM phasevec.truth "
                                        f"WHERE key = {q(k)};")
        if rc == 0 and out.strip():
            who, pr = out.rstrip("\n").split(SEP, 1)
            kind = next((x for x in ("ok", "true", "false") if PROOFS[x].format(k=k) == pr), None)
            # (seed 28100098) a row whose author name matches but whose role
            # is gone (DROP ROLE, then CREATE ROLE again) is the old claim, left as it was because
            # both asserts were refused: it is not the new role's assert
            known = self.snapshot()["truth"].get(k, {}).get("known") == "true"
            # (seed 3008282) both asserts refused (an orphan after rebind()): the old claim stays
            if kind and who in AUTHORS and known and self.m.may_change(who, k):
                self.m.assert_(who, k, kind, False)
        self.cl.sql(OWNER, self._verify_sql("verify", k))
        self.last_va.pop(k, None)
        self.resync(KEYS, keep_meta=True)

    def conc_refute_verify(self, op):
        k = op["k"]
        if not self.m.may_change("fz_author", k):
            return
        w = f"SELECT phasevec.refute('notes', {q(k)}, 'conc');"
        if op["reassert"]:
            w += f"SELECT phasevec.assert('notes', {q(k)}, {q(PROOFS[op['proof']].format(k=k))});"
        p = self.cl.popen("fz_author", f"BEGIN; {w} SELECT pg_sleep(0.4); COMMIT;")
        time.sleep(0.1)
        if op["via"] == "verify":
            self.cl.sql(OWNER, "SELECT count(*) FROM phasevec.verify('notes', 100, interval '0', "
                               "interval '60 s', 2000);")
        else:
            self.cl.sql(OWNER, f"SELECT phasevec.verify_one('notes', {q(k)});")
        p.communicate(timeout=60)
        rc, out, err = self.cl.sql(OWNER, "SELECT 1;")
        self.m.refute(k)
        if op["reassert"]:
            self.m.assert_("fz_author", k, op["proof"], False)
            self.last_va.pop(k, None)
        self.resync([k], keep_meta=True)
        self.resync([x for x in KEYS if x != k], keep_meta=True)

    def conc_edit_verify(self, op):
        k = op["k"]
        if k not in self.m.rows:
            return
        orig = self.m.rows[k][0]
        loop = "".join(f"UPDATE public.notes SET body = {q(op['a'] if i % 2 == 0 else op['b'])} "
                       f"WHERE id = {k}; SELECT pg_sleep(0.01);" for i in range(8))
        loop += f"UPDATE public.notes SET body = {q(orig)} WHERE id = {k};"
        p = self.cl.popen(WRITER, loop)
        self.cl.sql(OWNER, "SELECT count(*) FROM phasevec.verify('notes', 100, interval '0', "
                           "interval '60 s', 2000);")
        p.communicate(timeout=60)
        self.resync(KEYS)

    def conc_assert_verify(self, op):
        k, a = op["k"], self.allowed(op["author"], op["k"])
        if a is None:
            return
        pr = PROOFS[op["proof"]].format(k=k)
        loop = "".join(f"SELECT phasevec.assert('notes', {q(k)}, {q(pr)}); SELECT pg_sleep(0.01);"
                       for _ in range(6))
        p = self.cl.popen(a, loop)
        self.cl.sql(OWNER, "SELECT count(*) FROM phasevec.verify('notes', 100, interval '0', "
                           "interval '60 s', 2000);")
        p.communicate(timeout=60)
        # the claim is whatever the last assert made it, possibly judged afterwards; every other
        # claim was judged by the verify() as the model would, but in an order it cannot know
        self.m.assert_(a, k, op["proof"], False)
        self.last_va.pop(k, None)
        self.resync([k], keep_meta=True)
        self.resync([x for x in KEYS if x != k])

    def conc_adopt(self, op):
        """adopt() while fz_author holds the claim's row in an open
        transaction (refute(), or assert() of a new proof) that commits while adopt() waits.
        The write that committed first must stand: adopt() takes only orphans, so a retired
        claim, or one fz_author has asserted again, is not adopted."""
        k = op["k"]
        if not self.m.may_change("fz_author", k) or not self.m.may_adopt("fz_author"):
            return
        if op["op"] == "conc_refute_adopt":
            w = f"SELECT phasevec.refute('notes', {q(k)}, 'held');"
        else:
            w = f"SELECT phasevec.assert('notes', {q(k)}, {q(PROOFS[op['proof']].format(k=k))});"
        p = self.cl.popen("fz_author", f"BEGIN; {w} SELECT pg_sleep(0.6); COMMIT;")
        time.sleep(0.25)
        self.cl.sql("fz_author", "SELECT count(*) FROM phasevec.adopt('notes', 'fz_author');")
        p.communicate(timeout=60)
        if self.m.version != "0.20.0":
            self.resync(KEYS)
            return
        if op["op"] == "conc_refute_adopt":
            self.m.refute(k)
        else:
            self.m.assert_("fz_author", k, op["proof"], False)
        self.m.adopt("fz_author")
        self.last_va = {}

    def conc_refute_old_txn(self, op):
        """refute() in a transaction that began before a verify() recorded a verdict: does
        verified_at move back? (_truth_set refuses that for verdicts; refute() writes now())."""
        k = op["k"]
        if not self.m.may_change("fz_author", k):
            return
        p = self.cl.popen("fz_author", "BEGIN; SELECT now(); SELECT pg_sleep(0.6); "
                                       f"SELECT phasevec.refute('notes', {q(k)}, 'old txn'); "
                                       "COMMIT;")
        time.sleep(0.2)
        self.cl.sql(OWNER, "SELECT count(*) FROM phasevec.verify('notes', 100, interval '0', "
                           "interval '60 s', 2000);")
        mid = self.cl.must(OWNER, "SELECT extract(epoch FROM verified_at) FROM phasevec.truth "
                                  f"WHERE key = {q(k)};").strip()
        p.communicate(timeout=60)
        end = self.cl.must(OWNER, "SELECT extract(epoch FROM verified_at) FROM phasevec.truth "
                                  f"WHERE key = {q(k)};").strip()
        for kk, c in sorted(self.m.claims.items()):
            self.m.judge(OWNER, kk, c)
        self.m.refute(k)
        self.resync(KEYS, keep_meta=True)
        if mid not in ("", NULL) and end not in ("", NULL) and float(end) < float(mid):
            self.fail("INV-MONOTONIC/refute", f"key {k}: verify() recorded verified_at {mid}, "
                                              f"then refute() wrote {end}")
        if end not in ("", NULL):
            self.last_va[k] = float(end)

    def restore_upgrade(self):
        """The 0.19.0 database by pg_dump, restored where 0.20.0 is
        installed (pg_dump names no version: CREATE EXTENSION makes 0.20.0 and the rows of 0.19.0
        come in after it). Until phasevec.migrate() a claim is not changed or judged (verify()
        and assert() refuse) and none is served 'verified'; after it, the model is the update's."""
        f = os.path.join(self.cl.base, "dump19")
        subprocess.run([self.cl.bin("pg_dump"), "-Fc", "-h", self.cl.sock, "-p", str(self.cl.port),
                        "-U", OWNER, "-f", f, "fz"], check=True, capture_output=True)
        self.cl.must(OWNER, "CREATE DATABASE fz_r TEMPLATE template0;", db="postgres")
        p = subprocess.run([self.cl.bin("pg_restore"), "-h", self.cl.sock, "-p", str(self.cl.port),
                            "-U", OWNER, "-d", "fz_r", f], capture_output=True, text=True)
        if p.returncode != 0:
            raise Violation("INV-DUMP", f"pg_restore of 0.19.0 failed: {p.stderr.strip()[:400]}")
        served = self.cl.must(OWNER, "SELECT count(*) FROM phasevec.truth t "
                                     "WHERE phasevec._verdict(t) = 'verified';", db="fz_r").strip()
        if served != "0":
            raise Violation("INV-RESTORE19",
                            f"{served} restored claims read 'verified' before migrate()")
        for s in ("SELECT count(*) FROM phasevec.verify('notes', p_every => interval '0');",
                  "SELECT phasevec.assert('notes', '1', NULL);"):
            rc, out, err = self.cl.sql(OWNER, s, db="fz_r")
            if rc == 0 or "phasevec.migrate()" not in err:
                raise Violation("INV-RESTORE19", f"{s} before migrate(): rc {rc} {out.strip()} "
                                                 f"{err.strip()[:300]}")
        self.cl.must(OWNER, "SELECT count(*) FROM phasevec.migrate();", db="fz_r")
        self.cl.must(OWNER, "DROP DATABASE fz WITH (FORCE); ALTER DATABASE fz_r RENAME TO fz;",
                     db="postgres")
        self.cl.must(OWNER, "UPDATE phasevec.watches SET max_age = interval '1 day';" + GRANTS_SQL)
        self.m.upgrade()

    def dump_restore(self):
        before = self.snapshot()
        f = os.path.join(self.cl.base, "dump")
        subprocess.run([self.cl.bin("pg_dump"), "-Fc", "-h", self.cl.sock, "-p", str(self.cl.port),
                        "-U", OWNER, "-f", f, "fz"], check=True, capture_output=True)
        self.cl.must(OWNER, "CREATE DATABASE fz_r TEMPLATE template0;", db="postgres")
        p = subprocess.run([self.cl.bin("pg_restore"), "-h", self.cl.sock, "-p", str(self.cl.port),
                            "-U", OWNER, "-d", "fz_r", f], capture_output=True, text=True)
        if p.returncode != 0:
            raise Violation("INV-DUMP", f"pg_restore failed: {p.stderr.strip()[:400]}")
        self.cl.must(OWNER, "DROP DATABASE fz WITH (FORCE); ALTER DATABASE fz_r RENAME TO fz;",
                     db="postgres")
        after = self.snapshot()
        if before["served"] != after["served"]:
            raise Violation("INV-DUMP", f"served verdicts changed: {before['served']} -> "
                                        f"{after['served']}")

    # --- reading the database ---
    def snapshot(self):
        out = self.cl.must(OWNER, """
SELECT 'T', t.key, t.verdict, coalesce(t.proof, '<NULL>'), coalesce(t.asserted_by::text, '<NULL>'),
       (r.oid IS NOT NULL)::text, coalesce(encode(t.asserted_for, 'hex'), '<NULL>'),
       coalesce(extract(epoch FROM t.verified_at)::text, '<NULL>'),
       coalesce(phasevec._verdict(t), '<NULL>'),
       (t.verified_for IS NOT DISTINCT FROM
            phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid, t.proof_env))::text,
       (t.verified_at + w.max_age > clock_timestamp())::text, t.halted::text,
       coalesce(t.replaced_by, '<NULL>'), (t.expires_at <= clock_timestamp())::text,
       coalesce(t.asserted_row::text, '<NULL>'), t.by_steward::text,
       phasevec._from_here(t.asserted_in, t.asserted_cluster)::text
  FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch
  LEFT JOIN pg_roles r ON r.oid = t.asserted_by_oid AND r.rolname = t.asserted_by
 ORDER BY t.key;
SELECT 'R', key, encode(text_hash, 'hex'), body FROM phasevec._render('notes', NULL) ORDER BY key;
SELECT 'S', key, encode(text_hash, 'hex'), born FROM phasevec.sources s
 WHERE s.watch = (SELECT id FROM phasevec.watches WHERE name = 'notes') ORDER BY key;
SELECT 'N', id, body, tenant FROM public.notes ORDER BY id;
""")
        snap = {"truth": {}, "render": {}, "sources": {}, "rows": {}, "served": {}, "born": {}}
        for line in out.splitlines():
            f = line.split(SEP)
            if f[0] == "T":
                d = dict(zip(["key", "verdict", "proof", "author", "known", "afor", "va", "served",
                              "bound", "fresh", "halted", "rby", "expired", "row",
                              "by_steward", "here"], f[1:]))
                snap["truth"][d["key"]] = d
                snap["served"][d["key"]] = d["served"]
            elif f[0] == "R":
                snap["render"][f[1]] = f[2]
                # with FZ_RECIPE_TS the rendered text carries ' @ <timestamp>': the model's is
                # the body
                self.texts_by_hash[f[2]] = f[3].split(' @ ')[0] if RECIPE_COLS else f[3]
            elif f[0] == "S":
                snap["sources"][f[1]] = f[2]
                snap["born"][f[1]] = f[3]
            elif f[0] == "N":
                snap["rows"][f[1]] = (f[2], f[3])
        return snap

    def reader_view(self, role):
        rc, out, err = self.cl.sql(role, """
SELECT 'B', key, verdict FROM phasevec.brief('notes', 100000) ORDER BY key;
SELECT 'V', t.key, coalesce(phasevec._verdict(t), '<NULL>') FROM phasevec.truth t ORDER BY t.key;
SELECT 'C', verdict, n FROM phasevec.truth_coverage('notes') ORDER BY verdict;
""" + "".join(f"SELECT 'P', {q(k)}, step, key FROM phasevec.replacement('notes', {q(k)});"
              for k in KEYS))
        if rc != 0:
            raise Violation("MODEL-ERROR", f"reader {role} could not read: {err.strip()[:300]}")
        v = {"brief": {}, "verdict": {}, "cov": {}, "chain": {}}
        for line in out.splitlines():
            f = line.split(SEP)
            if f[0] == "B":
                v["brief"][f[1]] = f[2]
            elif f[0] == "V":
                v["verdict"][f[1]] = f[2]
            elif f[0] == "C":
                v["cov"][f[1]] = int(f[2])
            elif f[0] == "P":
                v["chain"].setdefault(f[1], []).append(f[3])
        return v

    def resync(self, keys, keep_meta=False):
        """After a step the model cannot predict (a race), take the claim from the database."""
        s = self.snapshot()
        self.m.rows = dict(s["rows"])
        # which row is under each key is the database's after a race
        self.m.born = dict(s["born"])
        self.m.reborn.clear()
        for k in keys:
            d = s["truth"].get(k)
            if d is None:
                self.m.claims.pop(k, None)
                continue
            c = self.m.claims.get(k) or Claim()
            c.verdict = d["verdict"]
            c.halted = d["halted"] == "true"
            c.replaced_by = None if d["rby"] == NULL else d["rby"]
            c.asserted = (None if d["afor"] == NULL
                          else self.texts_by_hash.get(d["afor"], "?" + d["afor"]))
            if d["proof"] == NULL:
                c.proof = None
            # a claim the model did not make (a placeholder of a supersede()
            # in a race) has the author the database says: whose it is decides who may change it
            if (not keep_meta or c.author is None) and d["author"] != NULL \
                    and d["author"] in self.m.gen:
                c.author = d["author"]
                c.gen = self.m.gen[d["author"]] if d["known"] == "true" else -1
            # a verdict this step reached (verified_at moved) was reached under the current RLS
            # state: stamp it as judge() does, or a later RLS toggle re-runs its proof as if it
            # had been judged after the toggle (INV-VERIFIED-HOLDS/proof, seed 80412196)
            if d["va"] != NULL and float(d["va"]) != self.last_va.get(k):
                c.rls_at = self.m.rls_epoch
            c.row = None if d["row"] == NULL else d["row"]
            c.by_steward = d["by_steward"] == "true"
            c.here = d["here"] == "true" or c.author is None
            c.expired = d["expired"] == "true"
            c.uncertain = False
            self.m.claims[k] = c

    # --- invariants ---
    def check(self):
        m = self.m
        if m.version != "0.20.0":
            return
        s = self.snapshot()
        if {k: v[0] for k, v in s["rows"].items()} != {k: v[0] for k, v in m.rows.items()}:
            raise Violation("MODEL-ROWS", f"rows {s['rows']} != model {m.rows}")
        # INV-BORN : a key's row is another only when a step wrote one
        # (an INSERT of a key with no row, a delete and an insert, a TRUNCATE and inserts)
        for k in m.rows:
            old, now = m.born.get(k), s["born"].get(k)
            if k in m.reborn and old is not None and now == old \
                    and "INV-BORN" not in self.skip:
                raise Violation("INV-BORN/same", f"key {k} was written again and keeps born {old}")
            if k not in m.reborn and old is not None and now != old \
                    and "INV-BORN" not in self.skip:
                raise Violation("INV-BORN/changed", f"key {k}: born {old} -> {now} with no new row")
        m.born = dict(s["born"])
        m.reborn.clear()
        # the row, the steward's mark and the binding each claim has are the model's
        for k, c in m.claims.items():
            d = s["truth"].get(k)
            if d is None or c.uncertain:
                continue
            want = (NULL if c.row is None else c.row, str(c.by_steward).lower(),
                    "true" if (c.here or c.author is None) else "false")
            got = (d["row"], d["by_steward"], d["here"] if c.author is not None else "true")
            if want != got and "INV-MODEL" not in self.skip:
                self.fail("INV-MODEL/meta", f"key {k}: (row, by_steward, here) {got}, model {want}")
        for k, c in list(m.claims.items()):
            if c.uncertain:
                self.resync([k])
        # INV-MODEL: owner's _verdict() is the model's
        keys = set(m.claims) | set(s["truth"])
        for k in sorted(keys):
            want = m.served(k)
            d = s["truth"].get(k, {})
            got = d.get("served")
            if want != got:
                # a cause where the row shows one, so one known finding does not hide another
                # (findings are told apart by INVARIANT/cause): F5 (a gone author's verdict
                # still served), a retired claim that has a proof again (adopt() racing
                # refute(), seed 91237018), and a proof that is not the one last asserted
                # (adopt() racing assert())
                c = m.claims.get(k)
                cause = ("/author-gone" if want == "unproven" and got in ("verified", "refuted")
                         and d.get("known") == "false" and d.get("author") != NULL else
                         "/retired-has-proof" if c is not None and c.retired
                         and d.get("proof", NULL) != NULL else
                         "/proof" if c is not None and not c.uncertain and d.get("proof")
                         != (NULL if c.proof is None else proof_sql(c.proof, k)) else "")
                self.fail("INV-MODEL" + cause, f"key {k}: _verdict serves {got}, model {want}; "
                                               f"row {d or None}")
        # INV-VERIFIED-HOLDS
        proofs = []
        for k, d in s["truth"].items():
            if d["served"] != "verified":
                continue
            bad = []
            if d["known"] != "true":
                bad.append("its author is no longer that role")
            if d["afor"] != s["render"].get(k):
                bad.append("asserted text is not the row's text")
            if d["bound"] != "true":
                bad.append("verified_for is not the claim's binding")
            if d["fresh"] != "true":
                bad.append("past max_age")
            if d["expired"] == "true":
                bad.append("expired")
            if bad:
                cause = {"its author is no longer that role": "author-gone",
                         "asserted text is not the row's text": "text",
                         "verified_for is not the claim's binding": "binding",
                         "past max_age": "horizon", "expired": "expired"}[bad[0]]
                self.fail("INV-VERIFIED-HOLDS/" + cause, f"key {k} served verified but {bad}: {d}")
            # A verdict binds text, env and author, not the table's policies: after an RLS
            # toggle a proof may read its own row differently until the next verify() or the
            # horizon. That is by design (spec.md 5.2), so the live re-run skips those claims.
            mc = m.claims.get(k)
            if mc is not None and getattr(mc, "rls_at", m.rls_epoch) != m.rls_epoch:
                continue
            if d["author"] != NULL and d["known"] == "true":
                sets = ""
                if mc is not None and mc.proof in ENV_PROOFS and d["proof"] == ENV_PROOFS[mc.proof]:
                    # an env proof means what it meant under its claim's settings (the model's)
                    if mc.envval is not True:
                        continue        # INV-MODEL judges it; a re-run under them would fail
                    sets = env_sets(mc.env_sp, mc.env_ds)
                proofs.append((k, d["author"], d["proof"], sets))
        if proofs and "INV-VERIFIED-HOLDS" not in self.skip:
            sql = "".join(f"SET ROLE {a}; {e}SELECT {q(k)}, (SELECT x FROM ({p}) AS z(x)); "
                          "RESET search_path; RESET DateStyle; RESET ROLE;"
                          for k, a, p, e in proofs)
            out = self.cl.must(OWNER, sql)
            for line in out.splitlines():
                k, v = line.split(SEP)
                if v != "t":
                    self.fail("INV-VERIFIED-HOLDS/proof", f"key {k} served verified, its proof "
                                                          f"now reads {v} as its author")
        # INV-MONOTONIC: verified_at never moves back between asserts
        for k, d in s["truth"].items():
            if d["va"] == NULL:
                continue
            va = float(d["va"])
            if k in self.last_va and va < self.last_va[k] and "INV-MONOTONIC" not in self.skip:
                raise Violation("INV-MONOTONIC", f"key {k}: verified_at {self.last_va[k]} -> {va}")
            self.last_va[k] = va
        # INV-REPLACED
        for k, d in s["truth"].items():
            # a dead claim reads 'unproven', a replaced one too
            if m.dead(k, m.claims.get(k)):
                continue
            if (d["verdict"] == "replaced") != (d["served"] == "replaced"):
                raise Violation("INV-REPLACED",
                                f"key {k}: stored {d['verdict']} served {d['served']}")
        # INV-RETIRED: a retired claim (refute(), not asserted since) whose text is the refuted
        # one is served refuted (or replaced/expired), never as something to believe
        for k, c in m.claims.items():
            # only while the row is there: a gone row is served by nothing (brief(), coverage)
            if not c.retired or m.text(k) is None or m.text(k) != c.refuted_text:
                continue
            # a refutation of a row that is gone says nothing of the next
            if m.dead(k, c):
                continue
            d = s["truth"].get(k, {})
            got = d.get("served")
            if got in ("verified", "unproven"):
                cause = ("adopted" if getattr(c, "adopted_retired", False) else
                         "ignored-while-replaced" if getattr(c, "refute_ignored", False) else
                         "no-text" if d.get("afor") == NULL else
                         "proof-kept" if d.get("proof") != NULL else
                         "revived" if d.get("verdict") in ("unproven", "verified") else "other")
                self.fail("INV-RETIRED/" + cause, f"key {k} was retired by refute() with text "
                                               f"{c.refuted_text!r} and is served {got}: "
                                               f"{s['truth'].get(k)}")
        # readers
        lec = self.reader_view(READER)
        out_v = self.reader_view(OUTSIDER)
        if (out_v["brief"] or out_v["cov"] or any(v != NULL for v in out_v["verdict"].values())
                or any(out_v["chain"].values())) and "INV-ISOLATION" not in self.skip:
            raise Violation("INV-ISOLATION", f"a role with no SELECT on the table sees {out_v}")
        for k, v in lec["verdict"].items():
            shown = (not m.rls) or m.sees(READER, k)
            if not shown and v != NULL and "INV-ISOLATION" not in self.skip:
                raise Violation("INV-ISOLATION",
                                f"fz_reader reads the verdict {v} of hidden row {k}")
            if shown and v != (s["served"].get(k) or NULL) and "INV-MODEL" not in self.skip:
                raise Violation("INV-MODEL", f"fz_reader reads {v} for key {k}, "
                                             f"owner {s['served'].get(k)}")
        want_brief = {}
        for k in m.rows:
            if not m.sees(READER, k):
                continue
            sv = m.served(k) or "unproven"
            if sv in ("verified", "unproven"):
                want_brief[k] = sv
        for k in lec["brief"]:
            if not m.sees(READER, k) and "INV-ISOLATION" not in self.skip:
                raise Violation("INV-ISOLATION", f"brief() gives fz_reader hidden row {k}")
        if lec["brief"] != want_brief and "INV-MODEL" not in self.skip:
            raise Violation("INV-MODEL",
                            f"brief() for fz_reader {lec['brief']} != model {want_brief}")
        want_cov = {}
        for k in m.rows:
            if m.sees(READER, k):
                sv = m.served(k) or "unproven"
                want_cov[sv] = want_cov.get(sv, 0) + 1
        if lec["cov"] != want_cov and "INV-MODEL" not in self.skip:
            raise Violation("INV-MODEL",
                            f"truth_coverage() for fz_reader {lec['cov']} != {want_cov}")
        for k in KEYS:
            chain = lec["chain"].get(k, [])
            if m.rls and not m.sees(READER, k):
                want = []
            else:
                want, cur, seen = [k], k, {k}
                while True:
                    c = m.claims.get(cur)
                    if c is None or c.verdict != "replaced" or c.replaced_by in seen:
                        break
                    # a dead claim's replacement is not followed
                    if m.dead(cur, c):
                        break
                    if m.rls and not m.sees(READER, c.replaced_by):
                        break
                    cur = c.replaced_by
                    seen.add(cur)
                    want.append(cur)
            if chain != want:
                inv = "INV-ISOLATION" if any(not m.sees(READER, x) for x in chain[1:]) and m.rls \
                    else "INV-MODEL"
                if inv not in self.skip:
                    raise Violation(inv, f"replacement({k}) for fz_reader {chain} != {want}")

    def run(self, seq):
        """Runs seq from a fresh database. Returns (index, Violation) or None. The indexes of
        the steps that sent nothing to the server (the model's rules made them no-ops, such as
        a race step whose role may not change the claim) are left in self.noops."""
        self.noops = []
        for i, op in enumerate(seq):
            try:
                n0 = self.cl.calls
                self.step(op)
                if op["op"] != "start" and self.cl.calls == n0:
                    self.noops.append(i)
                self.check()
            except Violation as v:
                return i, v
            except subprocess.TimeoutExpired as e:
                return i, Violation("TIMEOUT", str(e))
        return None


def shrink(runner, seq, inv, deadline):
    """Greedy one-op-at-a-time removal, keeping the start op, while the same invariant fails."""
    best = list(seq)
    changed = True
    while changed and time.time() < deadline:
        changed = False
        i = 1
        while i < len(best) and time.time() < deadline:
            cand = best[:i] + best[i + 1:]
            if cand and any(o["op"] == "upgrade" for o in best) and \
                    not any(o["op"] == "upgrade" for o in cand):
                i += 1
                continue
            r = runner.run(cand)
            if r and r[1].inv == inv:
                best = cand[:r[0] + 1]
                changed = True
            else:
                i += 1
    return best


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--pg", default=None,
                    help="PostgreSQL install with pg_phasevec installed (bin/, lib/, share/);"
                         " default: the parent of `pg_config --bindir`")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--steps", type=int, default=40, help="operations per sequence")
    ap.add_argument("--minutes", type=float, default=3.0, help="stop after this long")
    ap.add_argument("--upgrade-p", type=float, default=0.25,
                    help="share of sequences that start at 0.19.0 and upgrade")
    ap.add_argument("--skip", default="", help="comma list of invariants not to check")
    ap.add_argument("--shrink-minutes", type=float, default=2.0)
    ap.add_argument("--replay", help="JSON file with a sequence to run once")
    ap.add_argument("--out", default=None, help="directory for failing sequences (JSON)")
    ap.add_argument("--port", type=int, default=65535,
                    help="names the private unix socket; no TCP port is opened")
    ap.add_argument("--max-findings", type=int, default=20)
    args = ap.parse_args()
    try:
        os.nice(19)
    except OSError:
        pass
    if args.pg is None:
        try:
            bindir = subprocess.run(["pg_config", "--bindir"], capture_output=True, text=True,
                                    check=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            raise SystemExit("no --pg given and no pg_config on PATH")
        args.pg = os.path.dirname(bindir)
    seed = args.seed if args.seed is not None else int(time.time())
    out_dir = args.out or os.path.join(os.path.dirname(os.path.abspath(__file__)), "findings")
    os.makedirs(out_dir, exist_ok=True)
    port = free_port(args.port)
    cl = Cluster(args.pg, port)
    found = {}
    t0 = time.time()
    try:
        cl.start()
        runner = Runner(cl, skip=[s for s in args.skip.split(",") if s])
        runner.templates()
        if args.replay:
            seq = json.load(open(args.replay))
            r = runner.run(seq)
            print("replay:", "ok" if r is None else f"step {r[0]} {r[1]}")
            if runner.noops:
                names = ", ".join("%d:%s" % (j, seq[j]["op"]) for j in runner.noops)
                print(f"  {len(runner.noops)} of {len(seq) - 1} steps were no-ops under the "
                      f"model's rules: {names}")
            return 1 if r else 0
        n = steps = 0
        while time.time() - t0 < args.minutes * 60 and len(found) < args.max_findings:
            s = seed + n
            rng = random.Random(s)
            seq = gen_sequence(rng, args.steps, args.upgrade_p)
            r = runner.run(seq)
            n += 1
            steps += len(seq) if r is None else r[0] + 1
            if r is None:
                continue
            i, v = r
            sig = v.inv
            if sig in found:
                found[sig]["count"] += 1
                continue
            print(f"[seed {s}] step {i}: {v}", flush=True)
            small = shrink(runner, seq[:i + 1], v.inv, time.time() + args.shrink_minutes * 60)
            r2 = runner.run(small)
            path = os.path.join(out_dir, f"{v.inv.replace('/', '.')}-seed{s}.json")
            json.dump(small, open(path, "w"), indent=1)
            found[sig] = {"seed": s, "count": 1, "detail": str(r2[1]) if r2 else str(v),
                          "minimal": small, "file": path}
            print(f"  minimal ({len(small)} ops, {path}):", flush=True)
            for op in small:
                print("   ", json.dumps(op), flush=True)
            if r2:
                print("   ->", r2[1], flush=True)
        print(f"{n} sequences, {steps} steps, {time.time() - t0:.0f} s, "
              f"seeds {seed}..{seed + n - 1}")
        for sig, f in found.items():
            print(f"FINDING {sig}: seed {f['seed']} ({f['count']} sequences) {f['file']}")
        return 1 if found else 0
    finally:
        cl.stop()


if __name__ == "__main__":
    sys.exit(main())
