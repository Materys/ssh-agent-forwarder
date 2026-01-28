// ssh-agent-forwarder, a code to authenticate ssh connections using an agent on a different machine
// Copyright (C) 2026 Riccardo Bertossa (MATERYS SRL), Sebastiano Bisacchi (MATERYS SRL)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
package common

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisClient struct {
	client *redis.Client
}

func NewRedisClient(addr, password string, db int) *RedisClient {
	return &RedisClient{
		client: redis.NewClient(&redis.Options{
			Addr:         addr,
			Password:     password,
			DB:           db,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		}),
	}
}

func (r *RedisClient) GetToken(ctx context.Context, uuid string) (string, error) {
	return r.client.Get(ctx, "token:"+uuid).Result()
}

func (r *RedisClient) SetToken(ctx context.Context, uuid, token string) error {
	return r.client.Set(ctx, "token:"+uuid, token, 0).Err()
}

// RedisFromConfig creates a RedisClient using the config struct
func RedisFromConfig(cfg *Config) *RedisClient {
	addr := cfg.RedisAddr
	pass := cfg.RedisPass
	db := cfg.RedisDb
	return NewRedisClient(addr, pass, db)
}
