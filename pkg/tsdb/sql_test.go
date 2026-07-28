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
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEscapeString(t *testing.T) {
	// PostgreSQL 标准模式：单引号翻倍，反斜杠原样
	assert.Equal(t, "O''Neil", EscapeString("O'Neil", false))
	assert.Equal(t, "C:\\new", EscapeString("C:\\new", false))
	// 反斜杠转义方言（TDengine）：先翻倍反斜杠再转义单引号
	assert.Equal(t, "O\\'Neil", EscapeString("O'Neil", true))
	assert.Equal(t, "C:\\\\new", EscapeString("C:\\new", true))
	assert.Equal(t, "dir\\\\", EscapeString("dir\\", true))
	assert.Equal(t, "\\\\\\'", EscapeString("\\'", true))
}

func TestQuoteIdentifier(t *testing.T) {
	assert.Equal(t, "`a``b`", QuoteIdentifier("a`b", '`'))
	assert.Equal(t, `"a""b"`, QuoteIdentifier(`a"b`, '"'))
	assert.Equal(t, "`ts`", QuoteIdentifier("ts", '`'))
}

func TestValidFieldValue(t *testing.T) {
	assert.False(t, ValidFieldValue(nil))
	assert.False(t, ValidFieldValue(math.NaN()))
	assert.False(t, ValidFieldValue(math.Inf(1)))
	assert.False(t, ValidFieldValue(math.Inf(-1)))
	assert.True(t, ValidFieldValue(1.0))
	assert.True(t, ValidFieldValue(0.0))
	assert.True(t, ValidFieldValue("s"))
	assert.True(t, ValidFieldValue(1))
	assert.True(t, ValidFieldValue(false))
}

func TestFormatValue(t *testing.T) {
	assert.Equal(t, "NULL", FormatValue(nil, true))
	assert.Equal(t, "1000000", FormatValue(float64(1000000), true))
	assert.Equal(t, "123", FormatValue(123, true))
	assert.Equal(t, "TRUE", FormatValue(true, false))
	assert.Equal(t, "FALSE", FormatValue(false, false))
	assert.Equal(t, "'O\\'Neil'", FormatValue("O'Neil", true))
	assert.Equal(t, "'O''Neil'", FormatValue("O'Neil", false))
	assert.Equal(t, "'{\"a\":1}'", FormatValue(map[string]interface{}{"a": 1}, false))
}
