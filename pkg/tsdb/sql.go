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

package tsdb

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// EscapeString 转义 SQL 字符串字面量。backslashEscape=true 时反斜杠翻倍且单引号转为 \'，否则单引号翻倍。
func EscapeString(s string, backslashEscape bool) string {
	if backslashEscape {
		s = strings.ReplaceAll(s, "\\", "\\\\")
		return strings.ReplaceAll(s, "'", "\\'")
	}
	return strings.ReplaceAll(s, "'", "''")
}

// QuoteIdentifier 用指定引号字符包裹标识符并翻倍内部引号（TDengine 用反引号，PostgreSQL 用双引号）。
func QuoteIdentifier(s string, quote byte) string {
	q := string(quote)
	return q + strings.ReplaceAll(s, q, q+q) + q
}

// ValidFieldValue 字段值是否可落盘（非 nil、非 NaN/±Inf）。
func ValidFieldValue(v interface{}) bool {
	switch val := v.(type) {
	case nil:
		return false
	case float64:
		return !math.IsNaN(val) && !math.IsInf(val, 0)
	case float32:
		return !math.IsNaN(float64(val)) && !math.IsInf(float64(val), 0)
	}
	return true
}

// FormatValue 生成 SQL 值字面量：字符串按方言转义，浮点用固定小数表示法，nil 为 NULL，嵌套结构序列化为 JSON 字符串。
func FormatValue(v interface{}, backslashEscape bool) string {
	switch val := v.(type) {
	case nil:
		return "NULL"
	case string:
		return fmt.Sprintf("'%s'", EscapeString(val, backslashEscape))
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(val), 'f', -1, 32)
	case int:
		return strconv.FormatInt(int64(val), 10)
	case int64:
		return strconv.FormatInt(val, 10)
	case int32:
		return strconv.FormatInt(int64(val), 10)
	case int16:
		return strconv.FormatInt(int64(val), 10)
	case int8:
		return strconv.FormatInt(int64(val), 10)
	case uint:
		return strconv.FormatUint(uint64(val), 10)
	case uint64:
		return strconv.FormatUint(val, 10)
	case uint32:
		return strconv.FormatUint(uint64(val), 10)
	case uint16:
		return strconv.FormatUint(uint64(val), 10)
	case uint8:
		return strconv.FormatUint(uint64(val), 10)
	case bool:
		if val {
			return "TRUE"
		}
		return "FALSE"
	default:
		b, _ := json.Marshal(val)
		return fmt.Sprintf("'%s'", EscapeString(string(b), backslashEscape))
	}
}

// ScanRows 扫描 database/sql 查询结果为 QueryResult（[]byte 列转为 string）。
func ScanRows(rows *sql.Rows) (*QueryResult, error) {
	result := &QueryResult{Rows: []map[string]interface{}{}}
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	result.Columns = cols
	for rows.Next() {
		values := make([]interface{}, len(cols))
		valuePtrs := make([]interface{}, len(cols))
		for i := range cols {
			valuePtrs[i] = &values[i]
		}
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}
		row := make(map[string]interface{}, len(cols))
		for i, col := range cols {
			if b, ok := values[i].([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = values[i]
			}
		}
		result.Rows = append(result.Rows, row)
	}
	return result, rows.Err()
}
