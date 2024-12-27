package opcua

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/ua"
	"github.com/rulego/rulego"
	opcuaClient "github.com/rulego/rulego-components-iot/pkg/opcua_client"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/maps"
)

// 注册节点
func init() {
	_ = rulego.Registry.Register(&ReadNode{})
}

// Configuration 节点配置
type Configuration struct {
	//OPC UA Server Endpoint, eg. opc.tcp://localhost:4840
	Server string
	//Security Policy URL or one of None, Basic128Rsa15, Basic256, Basic256Sha256
	Policy string
	//Security Mode: one of None, Sign, SignAndEncrypt
	Mode string
	//Authentication Mode: one of Anonymous, UserName, Certificate
	Auth     string
	Username string
	Password string
	//OPC UA Server CertFile Path
	CertFile string
	//OPC UA Server CertKeyFile Path
	CertKeyFile string
}

func (c Configuration) GetServer() string {
	return c.Server
}
func (c Configuration) GetPolicy() string {
	return c.Policy
}
func (c Configuration) GetMode() string {
	return c.Mode
}
func (c Configuration) GetAuth() string {
	return c.Auth
}
func (c Configuration) GetUsername() string {
	return c.Username
}
func (c Configuration) GetPassword() string {
	return c.Password
}
func (c Configuration) GetCertFile() string {
	return c.CertFile
}
func (c Configuration) GetCertKeyFile() string {
	return c.CertKeyFile
}

type ReadNode struct {
	base.SharedNode[*opcua.Client]
	//节点配置
	Config WriteNodeConfiguration
	client *opcua.Client
}

func (x *ReadNode) New() types.Node {
	return &ReadNode{
		Config: WriteNodeConfiguration{
			Server: "opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer",
			Policy: "none",
			Mode:   "none",
			Auth:   "anonymous",
		},
	}
}

// Type 返回组件类型
func (x *ReadNode) Type() string {
	return "x/opcuaRead"
}

func (x *ReadNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	x.RuleConfig = ruleConfig
	_ = x.SharedNode.Init(x.RuleConfig, x.Type(), x.Config.Server, true, func() (*opcua.Client, error) {
		return x.initClient()
	})
	return err
}

// OnMsg 实现 Node 接口，处理消息
func (x *ReadNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.Get()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}

	nodeIds := make([]string, 0)
	err = json.Unmarshal([]byte(msg.Data), &nodeIds)
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}

	data, resp, err := opcuaClient.Read(client, nodeIds)
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	succ := false
	errs := make([]string, 0)
	for i, result := range resp.Results {
		if result != nil && result.Status != ua.StatusOK {
			x.RuleConfig.Logger.Printf("Error reading node %s: %s", data[i].NodeId, result.Status.Error())
			errs = append(errs, result.Status.Error())
		} else {
			d := opcuaClient.Data{
				DisplayName: data[i].DisplayName,
				NodeId:      data[i].NodeId,
				RecordTime:  result.ServerTimestamp,
				SourceTime:  result.SourceTimestamp,
				Value:       result.Value.Value(),
				Quality:     uint32(result.Status),
				Timestamp:   time.Now(),
			}
			_, _ = d.ParseValue()
			data[i] = d
			succ = true
		}
	}
	dbyte, err := json.Marshal(data)
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	msg.Data = string(dbyte)
	if succ {
		ctx.TellSuccess(msg)
	} else {
		ctx.TellFailure(msg, fmt.Errorf("read failed: %q ", errs))
	}
}

// Destroy 清理资源
func (x *ReadNode) Destroy() {
	if x.client != nil {
		_ = x.client.Close(context.Background())
		x.client = nil
	}
}

func (x *ReadNode) initClient() (*opcua.Client, error) {
	if x.client != nil {
		return x.client, nil
	} else {
		_, cancel := context.WithTimeout(context.TODO(), 4*time.Second)
		x.Locker.Lock()
		defer func() {
			cancel()
			x.Locker.Unlock()
		}()
		if x.client != nil {
			return x.client, nil
		}

		client, err := opcuaClient.DefaultHolder(x.Config).NewOpcUaClient()
		if err != nil {
			return nil, err
		}
		x.client = client
		return x.client, err
	}
}
