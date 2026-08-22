// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bench

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// A run's client-side latencies say what an agent experienced; the servers'
// own counters say what they did to produce it, including the flows they
// refused, which never appear as a latency at all. A report needs both, so
// this reads the exposition format directly.
//
// It is deliberately a few lines rather than the upstream parser: that would
// promote a transitive dependency to a direct one for the sake of splitting
// on a brace.

// Series is one exported sample: a metric name, its labels, and its value.
type Series struct {
	Name   string
	Labels map[string]string
	Value  float64
}

// Snapshot is everything one process exported at one instant.
type Snapshot struct {
	Source string    `json:"source"`
	Taken  time.Time `json:"taken"`
	Series []Series  `json:"-"`
}

// Value returns the first sample of name whose labels include match, and
// whether one existed. A missing series and a zero one mean different things:
// a counter that was never incremented is absent from the exposition entirely.
func (s *Snapshot) Value(name string, match map[string]string) (float64, bool) {
	for _, series := range s.Series {
		if series.Name != name {
			continue
		}
		found := true
		for k, v := range match {
			if series.Labels[k] != v {
				found = false
				break
			}
		}
		if found {
			return series.Value, true
		}
	}
	return 0, false
}

// Sum adds every sample of name, ignoring labels. It is how a counter split
// across label sets, such as flows by route, becomes one total.
func (s *Snapshot) Sum(name string) float64 {
	var total float64
	for _, series := range s.Series {
		if series.Name == name {
			total += series.Value
		}
	}
	return total
}

// Flatten renders the snapshot as canonical "name{k=v,...}" keys, which is
// what gets recorded in a result file. Keeping every series rather than a
// chosen few means a question nobody thought to ask before the run can still
// be answered from the record afterwards.
func (s *Snapshot) Flatten() map[string]float64 {
	out := make(map[string]float64, len(s.Series))
	for _, series := range s.Series {
		out[series.Key()] = series.Value
	}
	return out
}

// Key renders a series as a stable, sorted identifier.
func (s Series) Key() string {
	if len(s.Labels) == 0 {
		return s.Name
	}

	keys := make([]string, 0, len(s.Labels))
	for k := range s.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString(s.Name)
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(s.Labels[k])
	}
	b.WriteByte('}')
	return b.String()
}

// Scrape reads one process's metrics endpoint.
func Scrape(ctx context.Context, url string) (*Snapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("scrape %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scrape %s: HTTP %d", url, resp.StatusCode)
	}

	series, err := parseExposition(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("scrape %s: %w", url, err)
	}
	return &Snapshot{Source: url, Taken: time.Now(), Series: series}, nil
}

// parseExposition reads the Prometheus text format, ignoring HELP and TYPE.
func parseExposition(r interface{ Read([]byte) (int, error) }) ([]Series, error) {
	var out []Series

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// A sample is "name[{labels}] value [timestamp]". Splitting on the
		// last space would break on a label value containing one, so the
		// name and labels are taken from the front instead.
		name, rest, ok := splitSample(line)
		if !ok {
			continue
		}

		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		value, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			// NaN and +Inf are legal values that carry no information here.
			continue
		}

		labels, err := parseLabels(line)
		if err != nil {
			return nil, err
		}
		out = append(out, Series{Name: name, Labels: labels, Value: value})
	}
	return out, scanner.Err()
}

// splitSample separates the metric name from everything after its labels.
func splitSample(line string) (name, rest string, ok bool) {
	if open := strings.IndexByte(line, '{'); open >= 0 {
		close := strings.LastIndexByte(line, '}')
		if close < open {
			return "", "", false
		}
		return line[:open], line[close+1:], true
	}
	name, rest, found := strings.Cut(line, " ")
	return name, rest, found
}

// parseLabels reads the label set of a sample, if it has one.
func parseLabels(line string) (map[string]string, error) {
	open := strings.IndexByte(line, '{')
	if open < 0 {
		return nil, nil
	}
	close := strings.LastIndexByte(line, '}')
	if close < open {
		return nil, fmt.Errorf("unterminated label set: %q", line)
	}

	labels := map[string]string{}
	for _, pair := range splitLabelPairs(line[open+1 : close]) {
		key, value, found := strings.Cut(pair, "=")
		if !found {
			continue
		}
		unquoted, err := strconv.Unquote(strings.TrimSpace(value))
		if err != nil {
			unquoted = strings.Trim(strings.TrimSpace(value), `"`)
		}
		labels[strings.TrimSpace(key)] = unquoted
	}
	return labels, nil
}

// splitLabelPairs splits on commas that are not inside a quoted value.
func splitLabelPairs(s string) []string {
	var (
		pairs  []string
		start  int
		quoted bool
	)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			quoted = !quoted
		case ',':
			if !quoted {
				pairs = append(pairs, s[start:i])
				start = i + 1
			}
		}
	}
	if start < len(s) {
		pairs = append(pairs, s[start:])
	}
	return pairs
}
