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

package tdengine

import (
	"context"
	"database/sql"

	_ "github.com/taosdata/driver-go/v3/taosRestful"

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

// WriteConfig TDengine write connection configuration.
type WriteConfig struct {
	DSN string `json:"dsn" label:"DSN" desc:"TDengine DSN, format: root:taosdata@http(localhost:6041)/" required:"true" ref:"primary"`
	DB  string `json:"db" label:"DB" desc:"Database name" required:"true"`
	// 采集点数组 → SeriesPoint 可选映射（配置 measurement 后直接接收 x/iotRead 输出）
	tsdb.AcquisitionMapping `json:",squash"`
}

// WriteNode receives msg.Data (JSON SeriesPoint array or line protocol text) and writes to TDengine.
type WriteNode struct {
	base.SharedNode[*sql.DB]
	Config     WriteConfig
	dbTemplate el.Template
}

func (x *WriteNode) New() types.Node {
	return &WriteNode{
		Config: WriteConfig{
			DSN: "root:taosdata@http(localhost:6041)/",
			DB:  "db0",
		},
	}
}

func (x *WriteNode) Type() string {
	return "x/tdengineWrite"
}

func (x *WriteNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	if err := maps.Map2Struct(configuration, &x.Config); err != nil {
		return err
	}
	x.dbTemplate, _ = el.NewTemplate(x.Config.DB)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.DSN, ruleConfig.NodeClientInitNow, func() (*sql.DB, error) {
		db, err := sql.Open("taosRestful", x.Config.DSN)
		if err != nil {
			return nil, err
		}
		// 执行真实查询验证连接可用性
		rows, err := db.QueryContext(context.Background(), "SELECT SERVER_VERSION()")
		if err != nil {
			_ = db.Close()
			return nil, err
		}
		_ = rows.Close()
		return db, nil
	}, func(db *sql.DB) error {
		return db.Close()
	})
	return nil
}

func (x *WriteNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	dbConn, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	db := x.Config.DB
	env := base.NodeUtils.GetEvnAndMetadata(ctx, msg)
	if x.dbTemplate.HasVar() {
		db = x.dbTemplate.ExecuteAsString(env)
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
	if err = newDriver(dbConn).WritePoints(context.Background(), db, points); err != nil {
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
	return "TDengine client for writing time-series data. Routes to Success/Failure"
}
