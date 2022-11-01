package connect

import (
	"github.com/go-redis/redis/v8"
	"time"
	"golang.zx2c4.com/wireguard/config"
)

var Cluster *redis.ClusterClient

func init() {
	Cluster = redis.NewClusterClient(&redis.ClusterOptions{
		Addrs:              config.Config.Hosts,
		Password:           config.Config.Auth,
		DialTimeout:        100 * time.Microsecond,
		ReadTimeout:        100 * time.Microsecond,
		WriteTimeout:       100 * time.Microsecond,
	})
}
