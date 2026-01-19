CREATE TABLE IF NOT EXISTS signups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    name TEXT,
    company TEXT,
    phone TEXT,
    job_title TEXT,
    use_case TEXT,
    company_size TEXT,
    industry TEXT,
    budget TEXT,
    expected_usage TEXT,
    country TEXT,
    linkedin TEXT,
    twitter TEXT,
    current_solution TEXT,
    referral_source TEXT,
    ip_address TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_signups_created_at ON signups(created_at);
CREATE INDEX IF NOT EXISTS idx_signups_email ON signups(email);