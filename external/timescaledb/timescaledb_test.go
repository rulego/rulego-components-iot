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

package timescaledb

import (
	"testing"

	"github.com/rulego/rulego-components-iot/pkg/tsdb"
	"github.com/stretchr/testify/assert"
)

// TestBuildInsertSQLTagsFieldsTime verifies tags, fields and time column are all present.
func TestBuildInsertSQLTagsFieldsTime(t *testing.T) {
	point := tsdb.SeriesPoint{
		Measurement: "cpu",
		Tags:        map[string]string{"host": "srv1"},
		Fields:      map[string]interface{}{"value": 72.5},
		Timestamp:   1700000000000000000,
	}
	sqlStr := buildInsertSQL("public", point)
	assert.Equal(t, "INSERT INTO \"public\".\"cpu\" (\"host\",\"value\",\"time\") VALUES ('srv1',72.5,to_timestamp(1700000000000000000/1000000000.0))", sqlStr)
}

// TestBuildInsertSQLZeroTimestamp verifies ts=0 uses NOW().
func TestBuildInsertSQLZeroTimestamp(t *testing.T) {
	point := tsdb.SeriesPoint{
		Measurement: "cpu",
		Fields:      map[string]interface{}{"value": 1},
	}
	sqlStr := buildInsertSQL("public", point)
	assert.Contains(t, sqlStr, "NOW()")
	assert.NotContains(t, sqlStr, "to_timestamp")
}

// TestBuildInsertSQLNonZeroTimestamp verifies ts!=0 uses to_timestamp.
func TestBuildInsertSQLNonZeroTimestamp(t *testing.T) {
	point := tsdb.SeriesPoint{
		Measurement: "cpu",
		Fields:      map[string]interface{}{"value": 1},
		Timestamp:   1700000000000000000,
	}
	sqlStr := buildInsertSQL("public", point)
	assert.Contains(t, sqlStr, "to_timestamp(1700000000000000000/1000000000.0)")
	assert.NotContains(t, sqlStr, "NOW()")
}

// TestBuildInsertSQLEscapesStrings verifies single quotes in string values are escaped.
func TestBuildInsertSQLEscapesStrings(t *testing.T) {
	point := tsdb.SeriesPoint{
		Measurement: "cpu",
		Tags:        map[string]string{"note": "O'Neil"},
		Fields:      map[string]interface{}{"value": 1},
	}
	sqlStr := buildInsertSQL("public", point)
	assert.Contains(t, sqlStr, "'O''Neil'")
}
