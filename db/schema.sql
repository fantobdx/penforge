-- Schéma minimal pour l'historique des scans pentest.py.
-- Exécuté automatiquement par l'image officielle postgres au premier démarrage
-- (monté dans /docker-entrypoint-initdb.d/, cf. docker-compose.yml).

CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    domain TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    ok_count INT,
    fail_count INT,
    skip_count INT
);

CREATE TABLE IF NOT EXISTS scan_steps (
    id SERIAL PRIMARY KEY,
    scan_id INT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    step_id TEXT NOT NULL,
    label TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('OK', 'FAIL', 'SKIP')),
    report_path TEXT,
    report_content TEXT,
    note TEXT,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS scan_steps_scan_id_idx ON scan_steps(scan_id);

-- File d'attente : un job par domaine, consommé par le worker de pentest.py.
CREATE TABLE IF NOT EXISTS jobs (
    id SERIAL PRIMARY KEY,
    domain TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed')),
    scan_id INT REFERENCES scans(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS jobs_status_id_idx ON jobs(status, id);

-- Outil en cours d'exécution, affiché dans la file d'attente du web.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS current_step TEXT;

-- Sortie brute de chaque scan, relue en direct par la page de logs du web.
CREATE TABLE IF NOT EXISTS scan_logs (
    id BIGSERIAL PRIMARY KEY,
    scan_id INT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    line TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS scan_logs_scan_id_idx ON scan_logs(scan_id, id);

-- Contrôle depuis le web (arrêter / reprendre / relancer un outil), orchestré par Celery.
ALTER TABLE scan_steps DROP CONSTRAINT IF EXISTS scan_steps_status_check;
ALTER TABLE scan_steps ADD CONSTRAINT scan_steps_status_check
    CHECK (status IN ('OK', 'FAIL', 'SKIP', 'RUNNING', 'STOPPED'));
ALTER TABLE scan_steps ADD COLUMN IF NOT EXISTS task_id TEXT;

ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_status_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_status_check
    CHECK (status IN ('queued', 'running', 'done', 'failed', 'stopped'));

-- Pool de ports Tor partagé entre les workers Celery : une étape active = un port loué le
-- temps de son exécution. Repeuplée au démarrage du worker (TRUNCATE puis insertion des
-- ports courants), donc toujours cohérente avec SCAN_WORKERS actuel.
CREATE TABLE IF NOT EXISTS tor_instances (
    port INT PRIMARY KEY,
    locked_by_task_id TEXT
);

-- Sauter l'étape en cours sans arrêter tout le scan (web et MCP) : flag coopératif, lu par
-- pentest.run() à chaque réveil périodique comme stop_requested (jobs.status = 'stopped'), mais
-- porté par la ligne scan_steps elle-même : une nouvelle étape = une nouvelle ligne RUNNING,
-- donc toujours à false pour l'étape suivante, sans remise à zéro explicite nécessaire.
ALTER TABLE scan_steps ADD COLUMN IF NOT EXISTS skip_requested BOOLEAN NOT NULL DEFAULT false;

-- Findings automatiques extraits par pentest.py après chaque étape (wpscan, nuclei, sqlmap…).
-- Alimentée par pentest._analyze_step_output(), lue par pentest-mcp scan_findings.
CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    scan_id INT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    step_id TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    title TEXT NOT NULL,
    detail TEXT,
    recommendation TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS findings_scan_id_idx ON findings(scan_id);
