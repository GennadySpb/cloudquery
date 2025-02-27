package client

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudquery/cq-provider-sdk/serve"
	"github.com/fsnotify/fsnotify"

	"github.com/cloudquery/cloudquery/internal/test/provider"

	"github.com/cloudquery/cloudquery/pkg/config"
	"github.com/cloudquery/cloudquery/pkg/plugin/registry"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestClient_FetchTimeout(t *testing.T) {
	cancelServe := setupTestPlugin(t)
	defer cancelServe()

	cfg, diags := config.NewParser(nil).LoadConfigFromSource("config.hcl", []byte(testConfig))
	assert.Nil(t, diags)

	c, err := New(cfg, func(options *Client) {
		options.Hub = &MockRegistry{}
	})
	assert.Nil(t, err)
	if c == nil {
		assert.FailNow(t, "failed to create client")
	}

	err = c.Initialize(context.Background())
	assert.Nil(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	err = c.Fetch(ctx, FetchRequest{
		Providers: []*config.Provider{
			{
				Name:      "test",
				Resources: []string{"slow_resource"},
			},
		},
	})
	_, ok := ctx.Deadline()
	assert.EqualError(t, err, "rpc error: code = DeadlineExceeded desc = context deadline exceeded")
	assert.True(t, ok)
}

func TestClient_Fetch(t *testing.T) {
	cancelServe := setupTestPlugin(t)
	defer cancelServe()

	cfg, diags := config.NewParser(nil).LoadConfigFromSource("config.hcl", []byte(testConfig))
	assert.Nil(t, diags)

	c, err := New(cfg, func(c *Client) {
		c.Hub = &MockRegistry{}
	})

	assert.Nil(t, err)
	if c == nil {
		assert.FailNow(t, "failed to create client")
	}

	err = c.Initialize(context.Background())
	assert.Nil(t, err)

	ctx := context.Background()
	err = c.Fetch(ctx, FetchRequest{
		Providers: []*config.Provider{
			{
				Name:      "test",
				Resources: []string{"slow_resource", "very_slow_resource"},
			},
		},
	})
	assert.Nil(t, err)
}

func TestClient_GetProviderSchema(t *testing.T) {
	cancelServe := setupTestPlugin(t)
	defer cancelServe()

	cfg, diags := config.NewParser(nil).LoadConfigFromSource("config.hcl", []byte(testConfig))
	assert.Nil(t, diags)

	c, err := New(cfg, func(c *Client) {
		c.Hub = &MockRegistry{}
	})

	assert.Nil(t, err)
	if c == nil {
		assert.FailNow(t, "failed to create client")
	}

	err = c.Initialize(context.Background())
	assert.Nil(t, err)

	ctx := context.Background()
	schema, err := c.GetProviderSchema(ctx, "test")
	if schema == nil {
		t.FailNow()
	}
	assert.Equal(t, "test", schema.Name)
	assert.Equal(t, "v0.0.0", schema.Version)
	assert.Equal(t, 3, len(schema.ResourceTables))
	assert.Nil(t, err)
}

func TestClient_GetProviderConfig(t *testing.T) {
	cancelServe := setupTestPlugin(t)
	defer cancelServe()

	cfg, diags := config.NewParser(nil).LoadConfigFromSource("config.hcl", []byte(testConfig))
	assert.Nil(t, diags)

	c, err := New(cfg, func(c *Client) {
		c.Hub = &MockRegistry{}
	})
	assert.Nil(t, err)
	if c == nil {
		assert.FailNow(t, "failed to create client")
	}

	err = c.Initialize(context.Background())
	assert.Nil(t, err)

	ctx := context.Background()
	pConfig, err := c.GetProviderConfiguration(ctx, "test")
	if pConfig == nil {
		t.FailNow()
	}
	assert.NotNil(t, pConfig)
	assert.Equal(t, string(pConfig.Config), expectedProviderConfig)
	_, diags = hclparse.NewParser().ParseHCL(pConfig.Config, "testConfig.hcl")
	assert.Nil(t, diags)
}

func TestClient_ExecutePolicy(t *testing.T) {
	cfg, diags := config.NewParser(nil).LoadConfigFromSource("config.hcl", []byte(testConfig))
	assert.Nil(t, diags)

	c, err := New(cfg, func(c *Client) {
		c.Hub = &MockRegistry{}
	})
	assert.Nil(t, err)
	if c == nil {
		assert.FailNow(t, "failed to create client")
	}
	ctx := context.Background()
	conn, err := c.pool.Acquire(ctx)
	defer conn.Release()
	_, err = conn.Exec(ctx, `Truncate public.slow_resource`)
	if !assert.Nil(t, err) {
		t.FailNow()
	}
	resp, err := c.ExecutePolicy(ctx, ExecutePolicyRequest{
		PolicyPath:    "../../internal/test/provider/test_policy_success.yml",
		StopOnFailure: false,
	})
	assert.NotNil(t, resp)
	assert.False(t, resp.Passed)
	_, err = conn.Exec(ctx, `INSERT INTO public.slow_resource(id, some_bool) VALUES (uuid_in(md5(random()::text || clock_timestamp()::text)::cstring), true);`)
	assert.Nil(t, err)
	resp, err = c.ExecutePolicy(ctx, ExecutePolicyRequest{
		PolicyPath:    "../../internal/test/provider/test_policy_success.yml",
		StopOnFailure: false,
	})
	assert.NotNil(t, resp)
	assert.True(t, resp.Passed)
}

type MockRegistry struct{}

func (m MockRegistry) VerifyProvider(_ context.Context, _, _, _ string) bool {
	return true
}
func (m MockRegistry) GetProvider(_ context.Context, organization, providerName, providerVersion string) (registry.ProviderDetails, error) {
	return registry.ProviderDetails{
		Name:         providerName,
		Version:      providerVersion,
		Organization: organization,
	}, nil
}

const testConfig = `cloudquery {
  connection {
    dsn =  "host=localhost user=postgres password=pass DB.name=postgres port=5432"
  }
  provider "test" {
    source = "cloudquery"
    version = "v0.0.0"
  }
}

provider "test" {
  configuration {
	account "dev" {
	    id = 123
		regions = ["us-east1"]
		resources = ["ec2"]
	}
  }
  resources = ["slow_resource"]
}`

const expectedProviderConfig = `
provider "test" {

  configuration {
    account "1" {
      regions   = ["asdas"]
      resources = ["ab", "c"]
    }

    regions = ["adsa"]
  }
  resources = [
    "slow_resource",
    "very_slow_resource",
    "error_resource"
  ]
}`

func setupTestPlugin(t *testing.T) context.CancelFunc {
	debugCtx, cancelServe := context.WithCancel(context.Background())
	dir, _ := os.Getwd()
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.Add(dir); err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()

	go provider.ServeTestPlugin(debugCtx)
	_ = os.Setenv("CQ_REATTACH_PROVIDERS", filepath.Join(dir, ".cq_reattach"))
	viper.AutomaticEnv()
	viper.SetEnvPrefix("CQ")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	_ = <-watcher.Events

	unmanaged, err := serve.ParseReattachProviders(os.Getenv("CQ_REATTACH_PROVIDERS"))
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range unmanaged {
		_, err := net.DialTimeout(u.Addr.Network(), u.Addr.String(), time.Second*5)
		if err != nil {
			t.Fatal(err)
		}
	}

	return cancelServe
}
