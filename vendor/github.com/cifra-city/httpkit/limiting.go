package httpkit

import (
	"net/http"
	"sync"
	"time"

	"github.com/cifra-city/httpkit/problems"
)

// visitor хранит данные о запросах конкретного пользователя
type visitor struct {
	lastAccess time.Time
	requests   int
}

// RateLimiter хранит состояние пользователей для ограничения запросов
type RateLimiter struct {
	mu         sync.Mutex
	visitors   map[string]*visitor
	rate       int           // Лимит запросов
	interval   time.Duration // Интервал времени для проверки запросов
	expiration time.Duration // Время жизни записи о пользователе
}

// NewRateLimiter создает новый экземпляр RateLimiter
func NewRateLimiter(rate int, interval, expiration time.Duration) *RateLimiter {
	rl := &RateLimiter{
		visitors:   make(map[string]*visitor),
		rate:       rate,
		interval:   interval,
		expiration: expiration,
	}
	go rl.cleanup()
	return rl
}

// cleanup удаляет устаревшие записи о пользователях
func (rl *RateLimiter) cleanup() {
	for {
		time.Sleep(rl.expiration)
		rl.mu.Lock()
		for ip, v := range rl.visitors {
			if time.Since(v.lastAccess) > rl.expiration {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// Middleware возвращает middleware для ограничения запросов
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr // Используйте реальный IP пользователя, если используется прокси
		rl.mu.Lock()
		defer rl.mu.Unlock()

		v, exists := rl.visitors[ip]
		if !exists {
			rl.visitors[ip] = &visitor{
				lastAccess: time.Now(),
				requests:   1,
			}
			next.ServeHTTP(w, r)
			return
		}

		if time.Since(v.lastAccess) > rl.interval {
			// Сброс счетчика запросов, если интервал истек
			v.requests = 1
			v.lastAccess = time.Now()
			next.ServeHTTP(w, r)
			return
		}

		// Увеличиваем счетчик запросов
		v.requests++
		v.lastAccess = time.Now()

		if v.requests > rl.rate {
			// Превышен лимит запросов
			RenderErr(w, problems.TooManyRequests("rate limit exceeded"))
			return
		}

		next.ServeHTTP(w, r)
	})
}
