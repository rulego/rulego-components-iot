/*
 * Copyright 2026 The RuleGo Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package opengemini

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/openGemini/opengemini-client-go/opengemini"
	"github.com/rulego/rulego"
	"github.com/rulego/rulego-components-iot/pkg/tsdb"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/el"
	"github.com/rulego/rulego/utils/maps"
)

func init() {
	_ = rulego.Registry.Register(&WriteNode{})
}

// WriteConfig OpenGemini write connection configuration.
type WriteConfig struct {
	Server   string `json:"server" label:"Server" desc:"OpenGemini server address, format: host:port" required:"true" ref:"primary"`
	Database string `json:"database" label:"Database" desc:"Database name" required:"true"`
	Username string `json:"username" label:"Username" desc:"Authentication username" ref:"shared"`
	Password string `json:"password" label:"Password" desc:"Authentication password" ref:"shared"`
	Token    string `json:"token" label:"Token" desc:"Authentication token" ref:"shared"`
	// Acquisition point array → SeriesPoint optional mapping (after configuring measurement, directly receive x/iotRead output)
	tsdb.AcquisitionMapping `json:",squash"`
}

// WriteNode receives msg.Data (JSON SeriesPoint array or line protocol text), writes to OpenGemini.
type WriteNode struct {
	base.SharedNode[opengemini.Client]
	Config           WriteConfig
	opengeminiConfig *opengemini.Config
	databaseTemplate el.Template
}

func (x *WriteNode) New() types.Node {
	return &WriteNode{
		Config: WriteConfig{
			Server:   "127.0.0.1:8086",
			Database: "db0",
		},
	}
}

func (x *WriteNode) Type() string {
	return "x/opengeminiWrite"
}

func (x *WriteNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	if err := maps.Map2Struct(configuration, &x.Config); err != nil {
		return err
	}
	if opengeminiConfig, err := x.CreateOpengeminiConfig(); err != nil {
		return err
	} else {
		x.opengeminiConfig = opengeminiConfig
	}
	x.databaseTemplate, _ = el.NewTemplate(x.Config.Database)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (opengemini.Client, error) {
		return opengemini.NewClient(x.opengeminiConfig)
	}, func(client opengemini.Client) error {
		return client.Close()
	})
	return nil
}

func (x *WriteNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	database := x.Config.Database
	env := base.NodeUtils.GetEvnAndMetadata(ctx, msg)
	if x.databaseTemplate.HasVar() {
		database = x.databaseTemplate.ExecuteAsString(env)
	}
	if mapped, ok := x.Config.MapData(msg.GetData(), env); ok {
		msg.SetDataType(types.JSON)
		msg.SetData(mapped)
	}
	points, err := tsdb.ParsePoints(msg.GetData(), msg.DataType == types.JSON)
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	if err = newDriver(client).WritePoints(ctx.GetContext(), database, points); err != nil {
		ctx.TellFailure(msg, err)
	} else {
		ctx.TellSuccess(msg)
	}
}

func (x *WriteNode) GetInstance() (interface{}, error) {
	return x.SharedNode.GetInstance()
}

func (x *WriteNode) Destroy() {
	_ = x.SharedNode.Close()
}

func (x *WriteNode) Desc() string {
	return "OpenGemini client for writing time-series data. Routes to Success/Failure"
}

// CreateOpengeminiConfig parses Server (comma-separated multi-address) and authentication method.
func (x *WriteNode) CreateOpengeminiConfig() (*opengemini.Config, error) {
	var addresses []opengemini.Address
	for _, server := range strings.Split(x.Config.Server, ",") {
		addr := strings.Split(server, ":")
		if len(addr) < 2 {
			return nil, fmt.Errorf("must host:port format")
		}
		port, err := strconv.ParseInt(addr[1], 10, 64)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, opengemini.Address{Host: addr[0], Port: int(port)})
	}
	config := opengemini.Config{Addresses: addresses}
	if x.Config.Token != "" {
		config.AuthConfig = &opengemini.AuthConfig{
			AuthType: opengemini.AuthTypeToken,
			Token:    x.Config.Token,
		}
	} else if x.Config.Username != "" {
		config.AuthConfig = &opengemini.AuthConfig{
			AuthType: opengemini.AuthTypePassword,
			Username: x.Config.Username,
			Password: x.Config.Password,
		}
	}
	return &config, nil
}
