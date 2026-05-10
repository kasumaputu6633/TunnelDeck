// Package auth handles login, sessions, CSRF, and login rate limiting.
// Sessions are server-side rows looked up from a Secure+HttpOnly cookie;
// CSRF uses a per-session token embedded in forms.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/tunneldeck/tunneldeck/internal/db"
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
func (s *Service) EnsureAdmin(ctx context.Context, username string) (string, error) {
	var count int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return "", err
	}
	if count > 0 {
		return "", nil
	}
	pw, err := randomHex(12)
	if err != nil {
		return "", err
	}
	hash, err := HashPassword(pw)
	if err != nil {
		return "", err
	}
	_, err = s.DB.ExecContext(ctx, `
		INSERT INTO users (username, pwhash, created_at) VALUES (?, ?, ?)
	`, username, hash, time.Now().Unix())
	if err != nil {
		return "", err
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
	err := s.DB.QueryRowContext(ctx, `SELECT id, pwhash FROM users WHERE username=?`, username).Scan(&userID, &hash)
	if err != nil {
		s.recordAttempt(ctx, ip, false)
		// Dummy compare to reduce timing-based user enumeration.
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
	ID        string
	UserID    int64
	Username  string
	CSRFToken string
	ExpiresAt time.Time
}

// Lookup resolves a session cookie value. Returns (nil, nil) for missing or
// expired sessions; handlers treat that as "not logged in".
func (s *Service) Lookup(ctx context.Context, sid string) (*Session, error) {
	if sid == "" {
		return nil, nil
	}
	var sess Session
	var expires int64
	err := s.DB.QueryRowContext(ctx, `
		SELECT s.id, s.user_id, u.username, s.csrf_token, s.expires_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.id=?
	`, sid).Scan(&sess.ID, &sess.UserID, &sess.Username, &sess.CSRFToken, &expires)
	if err != nil {
		return nil, nil
	}
	sess.ExpiresAt = time.Unix(expires, 0)
	if time.Now().After(sess.ExpiresAt) {
		_, _ = s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE id=?`, sid)
		return nil, nil
	}
	return &sess, nil
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
