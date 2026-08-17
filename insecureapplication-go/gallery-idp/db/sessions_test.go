package db

import (
	"path/filepath"
	"testing"
	"time"
)

// newTestDB opens a fresh, migrated, unseeded SQLite database for direct
// db-package tests.
func newTestDB(t *testing.T) *DB {
	t.Helper()
	database, err := Open(filepath.Join(t.TempDir(), "test.sqlite3"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := database.RunMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	return database
}

func TestPendingAuthz_AwaitingLoginValid(t *testing.T) {
	tests := []struct {
		name string
		p    PendingAuthz
		want bool
	}{
		{
			name: "not awaiting login at all",
			p:    PendingAuthz{AwaitingLogin: false, StashedAt: time.Now()},
			want: false,
		},
		{
			name: "awaiting login but never stashed (zero StashedAt)",
			p:    PendingAuthz{AwaitingLogin: true},
			want: false,
		},
		{
			name: "stashed well within the 10-minute TTL",
			p:    PendingAuthz{AwaitingLogin: true, StashedAt: time.Now().Add(-5 * time.Minute)},
			want: true,
		},
		{
			name: "stashed just now",
			p:    PendingAuthz{AwaitingLogin: true, StashedAt: time.Now()},
			want: true,
		},
		{
			name: "stashed well past the 10-minute TTL",
			p:    PendingAuthz{AwaitingLogin: true, StashedAt: time.Now().Add(-15 * time.Minute)},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.AwaitingLoginValid(); got != tt.want {
				t.Errorf("AwaitingLoginValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

// backdateSession directly rewrites created_at/updated_at for a session row,
// bypassing the normal datetime('now') defaults, so tests don't have to
// sleep for real wall-clock time to exercise timeout behavior.
func backdateSession(t *testing.T, d *DB, id string, createdAgo, updatedAgo time.Duration) {
	t.Helper()
	created := time.Now().Add(-createdAgo).UTC().Format(time.DateTime)
	updated := time.Now().Add(-updatedAgo).UTC().Format(time.DateTime)
	if _, err := d.Exec(`UPDATE sessions SET created_at = ?, updated_at = ? WHERE id = ?`, created, updated, id); err != nil {
		t.Fatalf("backdate session: %v", err)
	}
}

func TestGetSession_LoginSessionIdleTimeout(t *testing.T) {
	d := newTestDB(t)

	if err := d.CreateSession("sess-idle"); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := d.SetSessionUser("sess-idle", "user-1"); err != nil {
		t.Fatalf("set session user: %v", err)
	}

	// Fresh login session: well within both idle and absolute limits.
	backdateSession(t, d, "sess-idle", 1*time.Minute, 1*time.Minute)
	sess, err := d.GetSession("sess-idle")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if sess == nil {
		t.Fatal("expected fresh login session to be returned, got nil")
	}

	// Idle just under the 30-minute limit: still valid.
	backdateSession(t, d, "sess-idle", 1*time.Hour, 29*time.Minute)
	sess, err = d.GetSession("sess-idle")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if sess == nil {
		t.Fatal("expected session idle for 29m to still be valid, got nil")
	}

	// Idle past the 30-minute limit: expired, treated as not-found.
	backdateSession(t, d, "sess-idle", 1*time.Hour, 31*time.Minute)
	sess, err = d.GetSession("sess-idle")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if sess != nil {
		t.Errorf("expected session idle for 31m to be expired (nil), got %+v", sess)
	}
}

func TestGetSession_LoginSessionAbsoluteTimeout(t *testing.T) {
	d := newTestDB(t)

	if err := d.CreateSession("sess-abs"); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := d.SetSessionUser("sess-abs", "user-1"); err != nil {
		t.Fatalf("set session user: %v", err)
	}

	// Created just under the 8-hour absolute limit, freshly active: still valid.
	backdateSession(t, d, "sess-abs", 7*time.Hour, 0)
	sess, err := d.GetSession("sess-abs")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if sess == nil {
		t.Fatal("expected session created 7h ago to still be valid, got nil")
	}

	// Created past the 8-hour absolute limit, even though it was just
	// touched (updated_at fresh) -- absolute timeout is not sliding.
	backdateSession(t, d, "sess-abs", 9*time.Hour, 0)
	sess, err = d.GetSession("sess-abs")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if sess != nil {
		t.Errorf("expected session created 9h ago to be expired (nil) regardless of fresh updated_at, got %+v", sess)
	}
}

func TestGetSession_AnonymousRowNeverTimesOut(t *testing.T) {
	d := newTestDB(t)

	if err := d.CreateSession("sess-anon"); err != nil {
		t.Fatalf("create session: %v", err)
	}
	// Deliberately never call SetSessionUser: this row stays anonymous
	// (user_id NULL). Backdate it well past both the idle and absolute
	// login-session limits -- it must still come back, since timeout
	// enforcement only applies to actual login sessions.
	backdateSession(t, d, "sess-anon", 100*time.Hour, 100*time.Hour)

	sess, err := d.GetSession("sess-anon")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if sess == nil {
		t.Fatal("expected anonymous (pre-login) session row to never expire via GetSession, got nil")
	}
}

func TestTouchSession_SlidesIdleWindow(t *testing.T) {
	d := newTestDB(t)

	if err := d.CreateSession("sess-touch"); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := d.SetSessionUser("sess-touch", "user-1"); err != nil {
		t.Fatalf("set session user: %v", err)
	}
	backdateSession(t, d, "sess-touch", 1*time.Hour, 25*time.Minute)

	if err := d.TouchSession("sess-touch"); err != nil {
		t.Fatalf("touch session: %v", err)
	}

	var updatedAt string
	row := d.QueryRow(`SELECT updated_at FROM sessions WHERE id = ?`, "sess-touch")
	if err := row.Scan(&updatedAt); err != nil {
		t.Fatalf("scan updated_at: %v", err)
	}
	updated, err := time.Parse(time.DateTime, updatedAt)
	if err != nil {
		t.Fatalf("parse updated_at %q: %v", updatedAt, err)
	}
	if age := time.Since(updated); age > 10*time.Second {
		t.Errorf("TouchSession did not slide updated_at forward: age = %v, want close to 0", age)
	}
}
