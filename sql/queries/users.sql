-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    now(),
    now(),
    $1,
    $2
)
RETURNING *;

-- name: RetrieveUserByEmail :one
SELECT id, created_at, updated_at, email, hashed_password FROM users WHERE email = $1;


-- name: DeleteAllUsers :exec
DELETE FROM users;

