package redis

import (
	"context"
	"fmt"

	oauth2 "github.com/Bifang-Bird/goOauth2"
	"github.com/Bifang-Bird/goOauth2/models"
	"github.com/go-redis/redis/v8"
)

var (
	_ oauth2.ClientStore = &ClientStore{}
)

// NewRedisStore create an instance of a redis store
func NewClientStore(opts *redis.Options, keyNamespace ...string) *ClientStore {
	if opts == nil {
		panic("options cannot be nil")
	}
	return NewClientStoreWithCli(redis.NewClient(opts), keyNamespace...)
}

// NewRedisStoreWithCli create an instance of a redis store
func NewClientStoreWithCli(cli *redis.Client, keyNamespace ...string) *ClientStore {
	store := &ClientStore{
		cli: cli,
	}

	if len(keyNamespace) > 0 {
		store.ns = keyNamespace[0]
	}
	return store
}

// NewRedisClusterStore create an instance of a redis cluster store
func NewClientClusterStore(opts *redis.ClusterOptions, keyNamespace ...string) *ClientStore {
	if opts == nil {
		panic("options cannot be nil")
	}
	return NewClientClusterStoreWithCli(redis.NewClusterClient(opts), keyNamespace...)
}

// NewRedisClusterStoreWithCli create an instance of a redis cluster store
func NewClientClusterStoreWithCli(cli *redis.ClusterClient, keyNamespace ...string) *ClientStore {
	store := &ClientStore{
		cli: cli,
	}

	if len(keyNamespace) > 0 {
		store.ns = keyNamespace[0]
	}
	return store
}

// TokenStore redis token store
type ClientStore struct {
	cli clienter
	ns  string
}

// Close close the store
func (s *ClientStore) Close() error {
	return s.cli.Close()
}

func (s *ClientStore) wrapperKey(key string) string {
	return fmt.Sprintf("%s%s", s.ns, key)
}

func (s *ClientStore) checkError(result redis.Cmder) (bool, error) {
	if err := result.Err(); err != nil {
		if err == redis.Nil {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

// remove
func (s *ClientStore) remove(ctx context.Context, key string) error {
	result := s.cli.Del(ctx, s.wrapperKey(key))
	_, err := s.checkError(result)
	return err
}

// Create Create and store the new client information
func (s *ClientStore) CreateClient(ctx context.Context, info oauth2.ClientInfo) error {
	jv, err := jsonMarshal(info)
	if err != nil {
		return err
	}

	pipe := s.cli.TxPipeline()

	if code := info.GetID(); code != "" {
		key := CLIENT_INFO + code
		pipe.Set(ctx, s.wrapperKey(key), jv, 0)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return err
	}
	return nil
}

func (s *ClientStore) GetByID(ctx context.Context, key string) (oauth2.ClientInfo, error) {
	result := s.cli.Get(ctx, s.wrapperKey(CLIENT_INFO+key))
	return s.parseClient(result)
}

func (s *ClientStore) parseClient(result *redis.StringCmd) (oauth2.ClientInfo, error) {
	if ok, err := s.checkError(result); err != nil {
		return nil, err
	} else if ok {
		return nil, nil
	}

	buf, err := result.Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}

	var token models.Client
	if err := jsonUnmarshal(buf, &token); err != nil {
		return nil, err
	}
	if token.GrantType == oauth2.PasswordCredentials {
		return &models.ClientPassword{
			ID:        token.ID,
			Secret:    token.Secret,
			Domain:    token.Domain,
			Public:    token.Public,
			UserID:    token.UserID,
			Password:  token.Password,
			Account:   token.Account,
			GrantType: token.GetGrantType(),
		}, nil
	}
	return &token, nil
}

func (s *ClientStore) RemoveClientInfoById(ctx context.Context, clientId string) error {
	err := s.remove(ctx, CLIENT_INFO+clientId)
	if err != nil {
		return err
	}
	return nil
}

func (s *ClientStore) CreateClientPermission(ctx context.Context, clientId string, info []oauth2.ClientPermissionInfo) error {
	jv, err := jsonMarshal(info)
	if err != nil {
		return err
	}

	pipe := s.cli.TxPipeline()

	if code := clientId; code != "" {
		pipe.Set(ctx, s.wrapperKey(CLIENT_PERMISSIONS+code), jv, 0)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return err
	}
	return nil
}

func (s *ClientStore) GetPermissionByID(ctx context.Context, key string) ([]oauth2.ClientPermissionInfo, error) {
	result := s.cli.Get(ctx, s.wrapperKey(CLIENT_PERMISSIONS+key))
	if ok, err := s.checkError(result); err != nil {
		return nil, err
	} else if ok {
		return nil, nil
	}
	buf, err := result.Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}
	var clientPermission []oauth2.ClientPermissionInfo
	var permissions []models.ClientPermission
	if err := jsonUnmarshal(buf, &permissions); err != nil {
		return nil, err
	}
	for _, s := range permissions {
		clientPermission = append(clientPermission, s)
	}
	return clientPermission, nil
}
