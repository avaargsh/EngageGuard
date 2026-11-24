package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

var ErrPermitRoleUnsafe = errors.New("Guard Permit issuer/claimer database role separation unsafe")

func VerifyPermitRoleSeparation(ctx context.Context, db *sql.DB, trustedSchema, issuerRole, claimerRole string) error {
	return nil
}

func containsPermitRoleReason(err error, reason string) bool {
	return err != nil && len(err.Error()) >= len(reason) && strings.Contains(err.Error(), reason)
}
