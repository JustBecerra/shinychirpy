-- name: CreateChirps :one
INSERT INTO chirps (id, created_at, updated_at, body, user_id)
VALUES (
    gen_random_uuid(),
    now(),
    now(),
    $1,
    $2
)
RETURNING *;

-- name: RetrieveChirps :many
SELECT * FROM chirps;

-- name: RetrieveChirpsByAuthorId :many
SELECT * FROM chirps WHERE user_id = $1 ORDER BY created_at $2;

-- name: RetrieveSingleChirp :one
SELECT * FROM chirps WHERE id = $1 LIMIT 1;

-- name: DeleteChirp :exec
DELETE FROM chirps WHERE id = $1 AND user_id = $2;