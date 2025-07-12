package database

import (
	"context"
	"medods/models"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Database struct {
	pool *pgxpool.Pool
}

func NewDatabase(pool *pgxpool.Pool) Database {
	return Database{
		pool,
	}
}

func (d *Database) Initialize() bool {
	_, err := d.pool.Exec(context.Background(), `create table if not exists "tokens" (
		id SERIAL primary key,
		guid TEXT not null,
		token TEXT not null,
		useragent TEXT not null,
		ip INET not null
	)`)
	return err == nil
}

func (d *Database) CreateToken(guid, token, useragent, ip string) (int, bool) {
	var token_id int
	err := d.pool.QueryRow(
		context.Background(),
		"insert into tokens(guid, token, useragent, ip) values ($1, $2, $3, $4) returning (id)",
		guid, token, useragent, ip,
	).Scan(&token_id)
	if err != nil {
		return 0, false
	}
	return token_id, true
}

func (d *Database) GetToken(token_id int) (models.DatabaseToken, bool) {
	var token models.DatabaseToken
	token.ID = token_id
	err := d.pool.QueryRow(
		context.Background(),
		"select guid, token, useragent, ip from tokens where id = $1",
		token_id,
	).Scan(&token.GUID, &token.HashedRefreshToken, &token.UserAgent, &token.IP)
	return token, err == nil
}

func (d *Database) DeleteToken(token_id int) bool {
	_, err := d.pool.Exec(context.Background(), "delete from tokens where id = $1", token_id)
	return err == nil
}

func (d *Database) TokenExists(token_id int) bool {
	var exists bool
	err := d.pool.QueryRow(
		context.Background(),
		"select exists(select 1 from tokens where id = $1)",
		token_id,
	).Scan(&exists)
	return err == nil && exists
}
