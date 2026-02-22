package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"fastpos/internal/chain"
)

const stateMigrateCommand = "migrate-state"

func maybeRunStateMigration(args []string, logf func(format string, v ...any)) (bool, error) {
	if len(args) < 2 || strings.TrimSpace(args[1]) != stateMigrateCommand {
		return false, nil
	}

	fs := flag.NewFlagSet(stateMigrateCommand, flag.ContinueOnError)
	fromBackend := fs.String("from-backend", stateBackendSnapshot, "source backend: snapshot or sqlite")
	fromPath := fs.String("from", "", "source state path")
	toBackend := fs.String("to-backend", stateBackendSnapshot, "target backend: snapshot or sqlite")
	toPath := fs.String("to", "", "target state path")
	if err := fs.Parse(args[2:]); err != nil {
		return true, err
	}

	*fromBackend = normalizeStateBackend(*fromBackend)
	*toBackend = normalizeStateBackend(*toBackend)
	if !isSupportedStateBackend(*fromBackend) {
		return true, fmt.Errorf("unsupported from-backend %q (supported: %s, %s)", *fromBackend, stateBackendSnapshot, stateBackendSQLite)
	}
	if !isSupportedStateBackend(*toBackend) {
		return true, fmt.Errorf("unsupported to-backend %q (supported: %s, %s)", *toBackend, stateBackendSnapshot, stateBackendSQLite)
	}
	if strings.TrimSpace(*fromPath) == "" {
		return true, errors.New("-from is required")
	}
	if strings.TrimSpace(*toPath) == "" {
		return true, errors.New("-to is required")
	}

	var (
		c   *chain.Chain
		err error
	)
	switch *fromBackend {
	case stateBackendSnapshot:
		c, err = chain.LoadSnapshot(*fromPath, chain.Config{})
	case stateBackendSQLite:
		c, err = chain.LoadSQLiteSnapshot(*fromPath, chain.Config{})
	default:
		err = fmt.Errorf("unsupported from-backend %q", *fromBackend)
	}
	if err != nil {
		return true, fmt.Errorf("load source state: %w", err)
	}

	switch *toBackend {
	case stateBackendSnapshot:
		err = c.SaveSnapshot(*toPath)
	case stateBackendSQLite:
		err = c.SaveSQLiteSnapshot(*toPath)
	default:
		err = fmt.Errorf("unsupported to-backend %q", *toBackend)
	}
	if err != nil {
		return true, fmt.Errorf("save target state: %w", err)
	}

	if logf != nil {
		logf(
			"state migration completed from=%s(%s) to=%s(%s) height=%d",
			*fromBackend,
			*fromPath,
			*toBackend,
			*toPath,
			c.GetStatus().Height,
		)
	}
	return true, nil
}
