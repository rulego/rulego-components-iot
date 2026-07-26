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
	"context"
	"encoding/json"

	"github.com/rulego/rulego"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/el"
	"github.com/rulego/rulego/utils/maps"
)

func init() {
	_ = rulego.Registry.Register(&QueryNode{})
}

// QueryConfig OpenGemini 查询配置（连接字段与 WriteConfig 一致，额外带 Command）。
type QueryConfig struct {
	Server   string `json:"server" label:"Server" desc:"OpenGemini server address, format: host:port" required:"true" ref:"primary"`
	Database string `json:"database" label:"Database" desc:"Database name" required:"true"`
	Username string `json:"username" label:"Username" desc:"Authentication username" ref:"shared"`
	Password string `json:"password" label:"Password" desc:"Authentication password" ref:"shared"`
	Token    string `json:"token" label:"Token" desc:"Authentication token" ref:"shared"`
	Command  string `json:"command" label:"Query" desc:"SQL query, supports ${metadata.key} and ${msg.key} substitution" required:"true"`
}

// QueryNode 执行 SQL 查询，结果以通用 QueryResult（列+行）写入 msg.Data。
// 连接复用 WriteNode 的 SharedNode client。
type QueryNode struct {
	*WriteNode
	Config          QueryConfig
	commandTemplate el.Template
	commandHasVar   bool
}

func (x *QueryNode) New() types.Node {
	return &QueryNode{
		Config: QueryConfig{
			Server:   "127.0.0.1:8086",
			Database: "db0",
			Command:  "select * from cpu_load",
		},
	}
}

func (x *QueryNode) Type() string {
	return "x/opengeminiQuery"
}

func (x *QueryNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	if err := maps.Map2Struct(configuration, &x.Config); err != nil {
		return err
	}
	// 复用 WriteNode 建立连接
	x.WriteNode = &WriteNode{}
	if err := x.WriteNode.Init(ruleConfig, configuration); err != nil {
		return err
	}
	x.commandTemplate, _ = el.NewTemplate(x.Config.Command)
	x.commandHasVar = x.commandTemplate.HasVar()
	return nil
}

func (x *QueryNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	database := x.Config.Database
	command := x.Config.Command
	if x.databaseTemplate.HasVar() || x.commandHasVar {
		env := base.NodeUtils.GetEvnAndMetadata(ctx, msg)
		database = x.databaseTemplate.ExecuteAsString(env)
		command = x.commandTemplate.ExecuteAsString(env)
	}
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	res, err := newDriver(client).Query(context.Background(), database, command)
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	data, _ := json.Marshal(res)
	msg.DataType = types.JSON
	msg.SetData(string(data))
	ctx.TellSuccess(msg)
}

func (x *QueryNode) Destroy() {
	_ = x.SharedNode.Close()
}

func (x *QueryNode) Desc() string {
	return "OpenGemini client for querying time-series data. Routes to Success/Failure"
}
