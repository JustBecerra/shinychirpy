-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at, revoked_at)
VALUES (
    $1,
    now(),
    now(),
    $2,
    $3,
    $4
)
RETURNING *;

-- name: RetrieveRefreshToken :one
SELECT * FROM refresh_tokens
WHERE token = $1;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = now(), updated_at = now()
WHERE token = $1;