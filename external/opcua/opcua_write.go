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
	_ = rulego.Registry.Register(&WriteNode{})
}

// WriteNodeConfiguration  节点配置
type WriteNodeConfiguration struct {
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

func (c WriteNodeConfiguration) GetServer() string {
	return c.Server
}
func (c WriteNodeConfiguration) GetPolicy() string {
	return c.Policy
}
func (c WriteNodeConfiguration) GetMode() string {
	return c.Mode
}
func (c WriteNodeConfiguration) GetAuth() string {
	return c.Auth
}
func (c WriteNodeConfiguration) GetUsername() string {
	return c.Username
}
func (c WriteNodeConfiguration) GetPassword() string {
	return c.Password
}
func (c WriteNodeConfiguration) GetCertFile() string {
	return c.CertFile
}
func (c WriteNodeConfiguration) GetCertKeyFile() string {
	return c.CertKeyFile
}

type WriteNode struct {
	base.SharedNode[*opcua.Client]
	//节点配置
	Config WriteNodeConfiguration
	client *opcua.Client
}

func (x *WriteNode) New() types.Node {
	return &WriteNode{
		Config: WriteNodeConfiguration{
			Server: "opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer",
			Policy: "none",
			Mode:   "none",
			Auth:   "anonymous",
		},
	}
}

// Type 返回组件类型
func (x *WriteNode) Type() string {
	return "x/opcuaWrite"
}

func (x *WriteNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	x.RuleConfig = ruleConfig
	_ = x.SharedNode.Init(x.RuleConfig, x.Type(), x.Config.Server, true, func() (*opcua.Client, error) {
		return x.initClient()
	})
	return err
}

// OnMsg 实现 Node 接口，处理消息
func (x *WriteNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.Get()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}

	data := make([]opcuaClient.Data, 0)
	err = json.Unmarshal([]byte(msg.Data), &data)
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}

	nodesToWrite := make([]*ua.WriteValue, 0)

	for _, d := range data {
		id, err := ua.ParseNodeID(d.NodeId)
		if err != nil {
			break
		}

		v, err := ua.NewVariant(d.Value)
		if err != nil {
			break
		}
		nodesToWrite = append(nodesToWrite, &ua.WriteValue{
			NodeID:      id,
			AttributeID: ua.AttributeIDValue,
			Value: &ua.DataValue{
				EncodingMask: ua.DataValueValue,
				Value:        v,
			},
		})
	}

	req := &ua.WriteRequest{
		NodesToWrite: nodesToWrite,
	}

	resp, err := client.Write(context.Background(), req)
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	succ := false
	errs := make([]string, 0)
	if resp != nil {
		for _, result := range resp.Results {
			if result == ua.StatusOK {
				succ = true
			} else {
				errs = append(errs, result.Error())
			}
		}
	}
	if succ {
		ctx.TellSuccess(msg)
	} else {
		ctx.TellFailure(msg, fmt.Errorf("read failed: %q ", errs))
	}
}

// Destroy 清理资源
func (x *WriteNode) Destroy() {
	if x.client != nil {
		_ = x.client.Close(context.Background())
		x.client = nil
	}
}

func (x *WriteNode) initClient() (*opcua.Client, error) {
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
