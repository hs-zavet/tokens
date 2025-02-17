package bin

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type UsersBin struct {
	client *redis.Client
	tlt    time.Duration
}

func NewUsersBin(redisAddr, redisPassword string, db int, tlt time.Duration) *UsersBin {
	client := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
		DB:       db,
	})

	return &UsersBin{
		client: client,
		tlt:    tlt,
	}
}

func (b *UsersBin) Add(ctx context.Context, key string, sessionID string) error {
	pipe := b.client.TxPipeline()
	pipe.SAdd(ctx, key, sessionID)
	pipe.Expire(ctx, key, b.tlt)
	_, err := pipe.Exec(ctx)
	return err
}

func (b *UsersBin) GetAll(ctx context.Context, key string) ([]string, error) {
	IDs, err := b.client.SMembers(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	if len(IDs) == 0 {
		return nil, nil
	}
	return IDs, nil
}

func (b *UsersBin) GetAccess(ctx context.Context, key string, sessionID string) (bool, error) {
	result, err := b.client.SIsMember(ctx, key, sessionID).Result()
	if err != nil {
		return false, err
	}
	return result, nil
}

func (b *UsersBin) Remove(ctx context.Context, key string, sessionID string) (int64, error) {
	count, err := b.client.SRem(ctx, key, sessionID).Result()
	if err != nil {
		return 0, err
	}
	return count, nil
}
