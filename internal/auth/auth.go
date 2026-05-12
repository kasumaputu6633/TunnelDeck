// Package auth handles login, sessions, CSRF, and login rate limiting.
// Sessions are server-side rows looked up from a Secure+HttpOnly cookie;
// CSRF uses a per-session token embedded in forms.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/kasumaputu6633/tunneldeck/internal/db"
)

const (
	SessionCookie = "td_session"
	SessionTTL    = 12 * time.Hour
	BcryptCost    = 12
	MaxFailPerMin = 5
	RateWindow    = time.Minute
)

type Service struct {
	DB *db.DB
}

func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), BcryptCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// EnsureAdmin creates the admin account on first boot. Returns the generated
// password if created, "" if the user already existed.
// Also writes /etc/tunneldeck/credentials (or stateDir/credentials on non-Linux)
// so the login page can display it without requiring journalctl.
func (s *Service) EnsureAdmin(ctx context.Context, username, credentialsPath string) (string, error) {
	var count int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return "", err
	}
	if count > 0 {
		return "", nil
	}
	pw := "tunneldeck" // default password shown on login page
	hash, err := HashPassword(pw)
	if err != nil {
		return "", err
	}
	_, err = s.DB.ExecContext(ctx, `
		INSERT INTO users (username, pwhash, must_change_password, created_at) VALUES (?, ?, 1, ?)
	`, username, hash, time.Now().Unix())
	if err != nil {
		return "", err
	}

	// Write credentials file so the login page can display them without
	// requiring the user to run journalctl.
	if credentialsPath != "" {
		_ = os.MkdirAll(filepath.Dir(credentialsPath), 0o750)
		content := fmt.Sprintf("username: %s\npassword: %s\n", username, pw)
		_ = os.WriteFile(credentialsPath, []byte(content), 0o640)
	}
	return pw, nil
}

// Login verifies credentials, creates a session, and returns session ID +
// CSRF token.
func (s *Service) Login(ctx context.Context, username, password, ip string) (string, string, error) {
	if err := s.checkRate(ctx, ip); err != nil {
		return "", "", err
	}

	var userID int64
	var hash string
	var mustChange int
	err := s.DB.QueryRowContext(ctx, `SELECT id, pwhash, must_change_password FROM users WHERE username=?`, username).Scan(&userID, &hash, &mustChange)
	if err != nil {
		s.recordAttempt(ctx, ip, false)
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$12$......................................................"), []byte(password))
		return "", "", errors.New("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		s.recordAttempt(ctx, ip, false)
		return "", "", errors.New("invalid credentials")
	}
	s.recordAttempt(ctx, ip, true)

	sid, err := randomHex(32)
	if err != nil {
		return "", "", err
	}
	csrf, err := randomHex(16)
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	_, err = s.DB.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, csrf_token, expires_at, created_at) VALUES (?, ?, ?, ?, ?)
	`, sid, userID, csrf, now.Add(SessionTTL).Unix(), now.Unix())
	if err != nil {
		return "", "", err
	}
	_, _ = s.DB.ExecContext(ctx, `UPDATE users SET last_login=? WHERE id=?`, now.Unix(), userID)
	return sid, csrf, nil
}

type Session struct {
	ID                 string
	UserID             int64
	Username           string
	CSRFToken          string
	ExpiresAt          time.Time
	MustChangePassword bool
}

// Lookup resolves a session cookie value. Returns (nil, nil) for missing or
// expired sessions; handlers treat that as "not logged in".
func (s *Service) Lookup(ctx context.Context, sid string) (*Session, error) {
	if sid == "" {
		return nil, nil
	}
	var sess Session
	var expires int64
	var mustChange int
	err := s.DB.QueryRowContext(ctx, `
		SELECT s.id, s.user_id, u.username, s.csrf_token, s.expires_at, u.must_change_password
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.id=?
	`, sid).Scan(&sess.ID, &sess.UserID, &sess.Username, &sess.CSRFToken, &expires, &mustChange)
	if err != nil {
		return nil, nil
	}
	sess.ExpiresAt = time.Unix(expires, 0)
	if time.Now().After(sess.ExpiresAt) {
		_, _ = s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE id=?`, sid)
		return nil, nil
	}
	sess.MustChangePassword = mustChange != 0
	return &sess, nil
}

// ChangePassword updates the user's password and clears must_change_password.
// Also deletes the credentials file if it exists.
func (s *Service) ChangePassword(ctx context.Context, userID int64, newPW, credentialsPath string) error {
	if len(newPW) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	hash, err := HashPassword(newPW)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `
		UPDATE users SET pwhash=?, must_change_password=0 WHERE id=?
	`, hash, userID)
	if err != nil {
		return err
	}
	// Remove the credentials file — it's no longer needed.
	if credentialsPath != "" {
		_ = os.Remove(credentialsPath)
	}
	return nil
}

func (s *Service) Logout(ctx context.Context, sid string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE id=?`, sid)
	return err
}

// SetCookie writes the session cookie. tlsOn=false drops Secure so the cookie
// works on plain HTTP over localhost in dev.
func SetCookie(w http.ResponseWriter, sid string, tlsOn bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   tlsOn,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(SessionTTL.Seconds()),
	})
}

func ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

// checkRate fails if the IP has exceeded MaxFailPerMin recent failures.
// A DB hiccup doesn't block login — we prefer availability.
func (s *Service) checkRate(ctx context.Context, ip string) error {
	cutoff := time.Now().Add(-RateWindow).Unix()
	var fails int
	err := s.DB.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM login_attempts WHERE ip=? AND ts>=? AND success=0
	`, ip, cutoff).Scan(&fails)
	if err != nil {
		return nil
	}
	if fails >= MaxFailPerMin {
		return errors.New("too many attempts, slow down")
	}
	return nil
}

func (s *Service) recordAttempt(ctx context.Context, ip string, ok bool) {
	success := 0
	if ok {
		success = 1
	}
	_, _ = s.DB.ExecContext(ctx, `
		INSERT INTO login_attempts (ip, ts, success) VALUES (?, ?, ?)
	`, ip, time.Now().Unix(), success)
	_, _ = s.DB.ExecContext(ctx, `DELETE FROM login_attempts WHERE ts < ?`, time.Now().Add(-time.Hour).Unix())
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ClientIP returns the remote address stripped of its port. X-Forwarded-For
// is deliberately ignored; the default localhost bind doesn't need it, and
// a reverse proxy can be handled explicitly later.
func ClientIP(r *http.Request) string {
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return addr[:i]
	}
	return addr
}
