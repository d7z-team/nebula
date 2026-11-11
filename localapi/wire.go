package localapi

import (
	"context"
	"errors"
	"log/slog"

	"github.com/slackhq/nebula/commands"
	"github.com/slackhq/nebula/config"
)

// WireControl brings up the control socket, serving reg, and keeps it following the
// config across reloads: pointed at the configured path, or down when the config turns
// it off.
//
// Every failure below is a warning, bar one. Nebula is expected to keep forwarding
// packets whether or not anyone can reach it; but a name that another process holds is
// not a misconfiguration, it is a process that will be answering nebula ctl in the
// daemon's place, and that is logged as an error.
func WireControl(ctx context.Context, l *slog.Logger, c *config.C, reg *commands.Registry) *Server {
	return wireControl(ctx, l.With("subsystem", "localapi"), c, reg)
}

// wireControl brings up the control socket and keeps it pointed at the configured path.
func wireControl(ctx context.Context, l *slog.Logger, c *config.C, reg *commands.Registry) *Server {
	srv := NewServer(l, reg)

	// Registered before the first attempt, so that a path or bind that is bad at startup
	// can be fixed with a config edit and a reload, the same as one that goes bad later,
	// and so that a HUP landing in between is harmless: Rebind on a server already at
	// the path is a no-op.
	reconcile := controlReconciler(ctx, l, c, srv)
	reconcile(c)
	if !ControlEnabled(c) {
		l.Info("Local control socket is disabled", "key", CtlEnabledKey)
	}
	return srv
}

// controlReconciler returns the function that brings the control socket into the state
// the config asks for, and registers it to run on every reload. Every reload is
// reconciled, not only one that changes a key: Rebind with nothing changed is a no-op,
// and a bind that failed for a reason outside the config, a runtime directory not there
// yet, say, is then retried without an edit to the config.
func controlReconciler(ctx context.Context, l *slog.Logger, c *config.C, srv *Server) func(*config.C) {
	reconcile := func(c *config.C) {
		if !ControlEnabled(c) {
			if srv.Path() != "" {
				srv.Stop()
				l.Info("Stopped the local control socket, it is disabled in the reloaded config")
			}
			return
		}

		want, err := SocketPathFromConfig(c)
		if err != nil {
			warnUnusable(l, "local control socket", srv.Path(), err)
			return
		}

		acc, err := controlAccessFrom(c)
		if err != nil {
			warnUnusable(l, "local control socket", srv.Path(), err)
			return
		}

		old := srv.Path()
		err = srv.Rebind(ctx, want, acc)
		reportRebind(l, "local control socket", old, want, err, srv.Path())
	}

	onReload(l, c, "local control socket", reconcile)
	return reconcile
}

// onReload registers fn to run on every reload. The callback recovers from its own
// panics rather than relying on the config package, whose callback loop has no isolation
// of its own: a panic there would take the daemon down and skip every callback queued
// behind this one.
func onReload(l *slog.Logger, c *config.C, what string, fn func(*config.C)) {
	c.RegisterReloadCallback(func(c *config.C, _ *config.Reload) {
		defer func() {
			if r := recover(); r != nil {
				l.Error("Recovered from panic reloading the "+what, "panic", r)
			}
		}()
		fn(c)
	})
}

// warnUnusable logs a config the endpoint cannot follow: with nothing serving, the
// endpoint is not available; with something serving, it is kept as it is.
func warnUnusable(l *slog.Logger, what, current string, err error) {
	if current == "" {
		l.Warn("The "+what+" is not available, its config is unusable", "error", err)
		return
	}
	l.Warn("Ignoring unusable "+what+" config from the reload, keeping the current endpoint", "error", err, "current", current)
}

// reportRebind logs what a Rebind did beyond the listening line the bind itself writes:
// nothing for an endpoint left where it was, a move with both paths, and a failure with
// what the operator is left with. old is the path served before the call, "" for none,
// want the one asked for, and now the path served after it, which after a failed move
// is still old.
//
// Nearly every failure is the operator's environment, a missing runtime directory or a
// bad path, and a warning; a name held by another process is an error, since nothing
// else will say that something is sitting where the daemon should be.
func reportRebind(l *slog.Logger, what, old, want string, err error, now string) {
	level := l.Warn
	if errors.Is(err, errEndpointHeld) {
		level = l.Error
	}

	switch {
	case err == nil:
		if old != "" && !samePath(old, want) {
			l.Info("Moved the "+what, "from", old, "to", want)
		}
	case old == "":
		level("Could not start the "+what+", it will not be available until a reload binds it", "error", err, "path", want)
	default:
		level("Could not bind the "+what+" at the requested path", "error", err, "requested", want, "serving", now)
	}
}

// errEndpointHeld is returned by listen when the endpoint's name is already held by
// some other process, which nebula will not serve alongside: whoever holds it would be
// answering the endpoint's clients. It is only raised on windows, where the default
// name can be held by another administrator's process and an override outside the
// protected namespace by any account's; on unix a path that is still being served is an
// earlier nebula, which clearStale reports as in use. The log line that carries it names
// the endpoint, so the sentence does not.
var errEndpointHeld = errors.New("the pipe's name is held by another process")
