package bin

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type UsersBin struct {
	client *redis.Client
	ctx    context.Context
	ttl    time.Duration
}

func NewUsersBin(redisAddr, redisPassword string, db int, ttl time.Duration) *UsersBin {
	client := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
		DB:       db,
	})

	return &UsersBin{
		client: client,
		ctx:    context.Background(),
		ttl:    ttl,
	}
}

func (b *UsersBin) Add(key string, sessionID string) error {
	err := b.client.SAdd(b.ctx, key, sessionID).Err()
	if err != nil {
		return err
	}

	err = b.client.Expire(b.ctx, key, b.ttl).Err()
	if err != nil {
		return err
	}

	return nil
}

func (b *UsersBin) GetAll(key string) ([]string, error) {
	IDs, err := b.client.SMembers(b.ctx, key).Result()
	if err != nil {
		return nil, err
	}

	return IDs, nil
}

func (b *UsersBin) GetAccess(key string, sessionID string) (bool, error) {
	result, err := b.client.SIsMember(b.ctx, key, sessionID).Result()
	if err != nil {
		return false, err
	}

	return result, nil
}

func (b *UsersBin) Remove(key string, sessionID string) error {
	err := b.client.SRem(b.ctx, key, sessionID).Err()
	if err != nil {
		return err
	}
	return nil
}
