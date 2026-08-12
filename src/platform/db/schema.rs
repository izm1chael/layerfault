pub(super) const SQLITE_RELATION_MIGRATION: &str = r#"
BEGIN IMMEDIATE;
ALTER TABLE model_revisions RENAME TO model_revisions_v1;
ALTER TABLE reviews RENAME TO reviews_v1;
ALTER TABLE findings RENAME TO findings_v1;
ALTER TABLE advisories RENAME TO advisories_v1;
ALTER TABLE newsletter_publications RENAME TO newsletter_publications_v1;

CREATE TABLE model_revisions(id TEXT PRIMARY KEY,model_id TEXT NOT NULL REFERENCES models(id) ON DELETE CASCADE,revision TEXT NOT NULL,observed_at BIGINT NOT NULL,metadata_json TEXT NOT NULL,UNIQUE(model_id,revision));
CREATE TABLE reviews(id TEXT PRIMARY KEY,revision_id TEXT NOT NULL REFERENCES model_revisions(id) ON DELETE CASCADE,final_decision TEXT NOT NULL,created_at BIGINT NOT NULL,body_json TEXT NOT NULL);
CREATE TABLE findings(id TEXT PRIMARY KEY,review_id TEXT NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,rule_id TEXT NOT NULL,domain TEXT NOT NULL,status TEXT NOT NULL,confidence TEXT NOT NULL,detail_json TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE advisories(id TEXT PRIMARY KEY,review_id TEXT NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,title TEXT NOT NULL,severity TEXT NOT NULL,body_json TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE newsletter_publications(id TEXT PRIMARY KEY,weekly_review_id TEXT NOT NULL REFERENCES weekly_reviews(id) ON DELETE CASCADE,format TEXT NOT NULL,body_sha256 TEXT NOT NULL,sent_at BIGINT,UNIQUE(weekly_review_id,format));

INSERT INTO model_revisions SELECT * FROM model_revisions_v1;
INSERT INTO reviews SELECT * FROM reviews_v1;
INSERT INTO findings SELECT * FROM findings_v1;
INSERT INTO advisories SELECT * FROM advisories_v1;
INSERT INTO newsletter_publications SELECT * FROM newsletter_publications_v1;

DROP TABLE findings_v1;
DROP TABLE advisories_v1;
DROP TABLE reviews_v1;
DROP TABLE model_revisions_v1;
DROP TABLE newsletter_publications_v1;

CREATE INDEX reviews_revision_idx ON reviews(revision_id,created_at);
CREATE INDEX findings_review_idx ON findings(review_id,created_at);
INSERT OR REPLACE INTO schema_migrations(version,applied_at) VALUES(2,strftime('%s','now'));
COMMIT;
"#;

pub(super) const POSTGRES_RELATION_MIGRATION: &str = r#"
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='model_revisions_model_fk' AND conrelid='model_revisions'::regclass) THEN
    ALTER TABLE model_revisions ADD CONSTRAINT model_revisions_model_fk FOREIGN KEY(model_id) REFERENCES models(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='reviews_revision_fk' AND conrelid='reviews'::regclass) THEN
    ALTER TABLE reviews ADD CONSTRAINT reviews_revision_fk FOREIGN KEY(revision_id) REFERENCES model_revisions(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='findings_review_fk' AND conrelid='findings'::regclass) THEN
    ALTER TABLE findings ADD CONSTRAINT findings_review_fk FOREIGN KEY(review_id) REFERENCES reviews(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='advisories_review_fk' AND conrelid='advisories'::regclass) THEN
    ALTER TABLE advisories ADD CONSTRAINT advisories_review_fk FOREIGN KEY(review_id) REFERENCES reviews(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='newsletter_weekly_review_fk' AND conrelid='newsletter_publications'::regclass) THEN
    ALTER TABLE newsletter_publications ADD CONSTRAINT newsletter_weekly_review_fk FOREIGN KEY(weekly_review_id) REFERENCES weekly_reviews(id) ON DELETE CASCADE;
  END IF;
END $$;
INSERT INTO schema_migrations(version,applied_at) VALUES(2,EXTRACT(EPOCH FROM NOW())::BIGINT) ON CONFLICT(version) DO NOTHING;
"#;

pub(super) const SQLITE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY,applied_at BIGINT NOT NULL);
INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(1,strftime('%s','now'));
CREATE TABLE IF NOT EXISTS models(id TEXT PRIMARY KEY,canonical_name TEXT NOT NULL UNIQUE,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS model_revisions(id TEXT PRIMARY KEY,model_id TEXT NOT NULL REFERENCES models(id) ON DELETE CASCADE,revision TEXT NOT NULL,observed_at BIGINT NOT NULL,metadata_json TEXT NOT NULL,UNIQUE(model_id,revision));
CREATE TABLE IF NOT EXISTS reviews(id TEXT PRIMARY KEY,revision_id TEXT NOT NULL REFERENCES model_revisions(id) ON DELETE CASCADE,final_decision TEXT NOT NULL,created_at BIGINT NOT NULL,body_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS reviews_revision_idx ON reviews(revision_id,created_at);
CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY,review_id TEXT NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,rule_id TEXT NOT NULL,domain TEXT NOT NULL,status TEXT NOT NULL,confidence TEXT NOT NULL,detail_json TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE INDEX IF NOT EXISTS findings_review_idx ON findings(review_id,created_at);
CREATE TABLE IF NOT EXISTS advisories(id TEXT PRIMARY KEY,review_id TEXT NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,title TEXT NOT NULL,severity TEXT NOT NULL,body_json TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,kind TEXT NOT NULL,idempotency_key TEXT NOT NULL UNIQUE,state TEXT NOT NULL,priority BIGINT NOT NULL,attempts BIGINT NOT NULL,max_attempts BIGINT NOT NULL,lease_owner TEXT,lease_until BIGINT,lease_token TEXT,payload_json TEXT NOT NULL,last_error TEXT,created_at BIGINT NOT NULL,started_at BIGINT,finished_at BIGINT);
CREATE INDEX IF NOT EXISTS jobs_ready_idx ON jobs(state,priority,created_at);
CREATE TABLE IF NOT EXISTS crawl_cursors(id TEXT PRIMARY KEY,cursor TEXT NOT NULL,updated_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS weekly_reviews(id TEXT PRIMARY KEY,period TEXT NOT NULL UNIQUE,generated_at BIGINT NOT NULL,body_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS newsletter_publications(id TEXT PRIMARY KEY,weekly_review_id TEXT NOT NULL REFERENCES weekly_reviews(id) ON DELETE CASCADE,format TEXT NOT NULL,body_sha256 TEXT NOT NULL,sent_at BIGINT,UNIQUE(weekly_review_id,format));
"#;
pub(super) const POSTGRES_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS schema_migrations(version BIGINT PRIMARY KEY,applied_at BIGINT NOT NULL);
INSERT INTO schema_migrations(version,applied_at) VALUES(1,EXTRACT(EPOCH FROM NOW())::BIGINT) ON CONFLICT(version) DO NOTHING;
CREATE TABLE IF NOT EXISTS models(id TEXT PRIMARY KEY,canonical_name TEXT NOT NULL UNIQUE,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS model_revisions(id TEXT PRIMARY KEY,model_id TEXT NOT NULL CONSTRAINT model_revisions_model_fk REFERENCES models(id) ON DELETE CASCADE,revision TEXT NOT NULL,observed_at BIGINT NOT NULL,metadata_json TEXT NOT NULL,UNIQUE(model_id,revision));
CREATE TABLE IF NOT EXISTS reviews(id TEXT PRIMARY KEY,revision_id TEXT NOT NULL CONSTRAINT reviews_revision_fk REFERENCES model_revisions(id) ON DELETE CASCADE,final_decision TEXT NOT NULL,created_at BIGINT NOT NULL,body_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS reviews_revision_idx ON reviews(revision_id,created_at);
CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY,review_id TEXT NOT NULL CONSTRAINT findings_review_fk REFERENCES reviews(id) ON DELETE CASCADE,rule_id TEXT NOT NULL,domain TEXT NOT NULL,status TEXT NOT NULL,confidence TEXT NOT NULL,detail_json TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE INDEX IF NOT EXISTS findings_review_idx ON findings(review_id,created_at);
CREATE TABLE IF NOT EXISTS advisories(id TEXT PRIMARY KEY,review_id TEXT NOT NULL CONSTRAINT advisories_review_fk REFERENCES reviews(id) ON DELETE CASCADE,title TEXT NOT NULL,severity TEXT NOT NULL,body_json TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,kind TEXT NOT NULL,idempotency_key TEXT NOT NULL UNIQUE,state TEXT NOT NULL,priority BIGINT NOT NULL,attempts BIGINT NOT NULL,max_attempts BIGINT NOT NULL,lease_owner TEXT,lease_until BIGINT,lease_token TEXT,payload_json TEXT NOT NULL,last_error TEXT,created_at BIGINT NOT NULL,started_at BIGINT,finished_at BIGINT);
CREATE INDEX IF NOT EXISTS jobs_ready_idx ON jobs(state,priority,created_at);
CREATE TABLE IF NOT EXISTS crawl_cursors(id TEXT PRIMARY KEY,cursor TEXT NOT NULL,updated_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS weekly_reviews(id TEXT PRIMARY KEY,period TEXT NOT NULL UNIQUE,generated_at BIGINT NOT NULL,body_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS newsletter_publications(id TEXT PRIMARY KEY,weekly_review_id TEXT NOT NULL CONSTRAINT newsletter_weekly_review_fk REFERENCES weekly_reviews(id) ON DELETE CASCADE,format TEXT NOT NULL,body_sha256 TEXT NOT NULL,sent_at BIGINT,UNIQUE(weekly_review_id,format));
"#;
