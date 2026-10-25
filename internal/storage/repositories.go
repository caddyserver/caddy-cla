package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrConflict indicates a stale configuration or an already-completed operation.
var ErrConflict = errors.New("the repository configuration changed; reload and try again")

// Repository contains the live agreement and exemption rules for one GitHub repository.
type Repository struct {
	// Name is the configured owner/repository identifier.
	Name string
	// GitHubID identifies the stable GitHub repository across transfers.
	GitHubID string
	// Title is displayed on signing pages and in the bot comment.
	Title string
	// Version selects an immutable agreement snapshot.
	Version string
	// GistURL is the optional public source or explicitly pinned revision.
	GistURL string
	// GistFile selects one document within the public Gist.
	GistFile string
	// Policy contains this repository's signing exemptions.
	Policy Policy
	// Generation rejects stale edits and stale bot evaluations.
	Generation int64
	// UpdatedBy identifies the administrator who last saved the configuration; zero denotes automation.
	UpdatedBy int64
	// UpdatedAt is the RFC 3339 configuration-change timestamp.
	UpdatedAt string
	// Body is the exact immutable agreement text.
	Body string
	// Source records the agreement snapshot's original location.
	Source string
}

// HistoryEvent describes a user action or a repository agreement change without storing credentials.
type HistoryEvent struct {
	// GitHubID identifies the account whose history contains this event.
	GitHubID int64
	// ActorID identifies the account that performed the action; zero denotes automation.
	ActorID int64
	// Repo identifies the repository affected by the action.
	Repo string
	// Version selects an immutable agreement snapshot.
	Version string
	// Kind identifies the recorded action.
	Kind string
	// OccurredAt is the RFC 3339 action timestamp.
	OccurredAt string
	// Details contains non-secret audit context.
	Details string
}

// BootstrapRepositories migrates the original shared settings once; restarts never overwrite live edits.
func (s *Store) BootstrapRepositories(names []string, githubID, version, source string, defaults Policy) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var initialized string
	err = tx.QueryRow("SELECT value FROM settings WHERE key='repositories_initialized'").Scan(&initialized)
	if err == nil {
		return tx.Commit()
	}
	if err != sql.ErrNoRows {
		return err
	}
	var saved string
	if err = tx.QueryRow("SELECT value FROM settings WHERE key='policy'").Scan(&saved); err == nil {
		if err = json.Unmarshal([]byte(saved), &defaults); err != nil {
			return err
		}
	} else if err != sql.ErrNoRows {
		return err
	}
	policy, err := json.Marshal(defaults)
	if err != nil {
		return err
	}
	for _, name := range names {
		if _, err = tx.Exec("INSERT INTO repositories(name,github_id,title,version,gist_url,policy,updated_at) VALUES(?,?,?,?,?,?,?)", name, githubID, "Contributor License Agreement", version, source, string(policy), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
		// Prior releases intentionally treated every signature as shared across bootstrap repositories.
		if _, err = tx.Exec("INSERT OR IGNORE INTO signature_repositories(signature_id,repo) SELECT id,? FROM signatures", name); err != nil {
			return err
		}
		if _, err = tx.Exec("INSERT OR IGNORE INTO legacy_repositories SELECT key,? FROM legacy_signatures", name); err != nil {
			return err
		}
	}
	if _, err = tx.Exec("INSERT INTO settings VALUES('repositories_initialized','1')"); err != nil {
		return err
	}
	return tx.Commit()
}

// Repository loads a live repository configuration and its immutable agreement snapshot.
func (s *Store) Repository(name string) (Repository, error) {
	var r Repository
	var policy string
	err := s.QueryRow(`SELECT r.name,r.github_id,r.title,r.version,r.gist_url,r.gist_file,r.policy,r.generation,r.updated_by,r.updated_at,a.body,a.source FROM repositories r JOIN agreements a ON a.version=r.version WHERE r.name=?`, name).Scan(&r.Name, &r.GitHubID, &r.Title, &r.Version, &r.GistURL, &r.GistFile, &policy, &r.Generation, &r.UpdatedBy, &r.UpdatedAt, &r.Body, &r.Source)
	if err != nil {
		return r, err
	}
	err = json.Unmarshal([]byte(policy), &r.Policy)
	return r, err
}

// Repositories lists configured repository names in a stable order.
func (s *Store) Repositories() ([]string, error) {
	rows, err := s.Query("SELECT name FROM repositories ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	names := []string{}
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// SaveRepository publishes a snapshot and rules atomically, retaining old agreements and queueing affected PRs.
// Generation must match the version the administrator reviewed; zero creates a new configuration.
func (s *Store) SaveRepository(r Repository, actor int64) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = agreementTx(tx, r.Version, r.Body, r.Source); err != nil {
		return err
	}
	policy, err := json.Marshal(r.Policy)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if r.Generation == 0 {
		_, err = tx.Exec("INSERT INTO repositories(name,github_id,title,version,gist_url,gist_file,auto_update,policy,updated_by,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)", r.Name, r.GitHubID, r.Title, r.Version, r.GistURL, r.GistFile, false, string(policy), actor, now)
	} else {
		var result sql.Result
		result, err = tx.Exec(`UPDATE repositories SET github_id=?,title=?,version=?,gist_url=?,gist_file=?,auto_update=?,policy=?,generation=generation+1,updated_by=?,updated_at=? WHERE name=? AND generation=?`, r.GitHubID, r.Title, r.Version, r.GistURL, r.GistFile, false, string(policy), actor, now, r.Name, r.Generation)
		if err == nil {
			n, _ := result.RowsAffected()
			if n != 1 {
				return ErrConflict
			}
		}
	}
	if err != nil {
		return err
	}
	if err = queueRepository(tx, r.Name); err != nil {
		return err
	}
	if err = eventTx(tx, HistoryEvent{ActorID: actor, Repo: r.Name, Version: r.Version, Kind: "agreement-configured", OccurredAt: now}); err != nil {
		return err
	}
	return tx.Commit()
}

// SaveRepositoryPolicy changes exemptions without changing the selected agreement.
func (s *Store) SaveRepositoryPolicy(name string, p Policy, actor int64) error {
	r, err := s.Repository(name)
	if err != nil {
		return err
	}
	r.Policy = p
	return s.SaveRepository(r, actor)
}

// queueRepository refreshes reconciliation jobs in the caller's transaction.
func queueRepository(tx *sql.Tx, repo string) error {
	if _, err := tx.Exec(`INSERT INTO jobs(repo,number,installation) SELECT repo,number,installation FROM prs WHERE repo=? ON CONFLICT(repo,number) DO UPDATE SET next=0,attempts=0,error='',generation=jobs.generation+1`, repo); err != nil {
		return err
	}
	_, err := tx.Exec("UPDATE merge_groups SET pending=1,next=0,attempts=0,error='',generation=generation+1 WHERE repo=?", repo)
	return err
}

// eventTx appends an audit event in the same transaction as its state change.
func eventTx(tx *sql.Tx, e HistoryEvent) error {
	if e.OccurredAt == "" {
		e.OccurredAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	_, err := tx.Exec("INSERT INTO history_events(github_id,actor_id,repo,version,kind,occurred_at,details) VALUES(?,?,?,?,?,?,?)", e.GitHubID, e.ActorID, e.Repo, e.Version, e.Kind, e.OccurredAt, e.Details)
	return err
}

// UserHistory lists actions concerning the authenticated identity, most recent first.
func (s *Store) UserHistory(id int64) ([]HistoryEvent, error) {
	rows, err := s.Query("SELECT github_id,actor_id,repo,version,kind,occurred_at,details FROM history_events WHERE github_id=? ORDER BY id DESC", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HistoryEvent{}
	for rows.Next() {
		var e HistoryEvent
		if err = rows.Scan(&e.GitHubID, &e.ActorID, &e.Repo, &e.Version, &e.Kind, &e.OccurredAt, &e.Details); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CurrentAgreement rejects form submissions for an agreement changed while the page was open.
func currentAgreement(tx *sql.Tx, repo, version string) error {
	var current string
	if err := tx.QueryRow("SELECT version FROM repositories WHERE name=?", repo).Scan(&current); err != nil {
		return err
	}
	if current != version {
		return fmt.Errorf("agreement changed; review the current version before signing")
	}
	return nil
}
