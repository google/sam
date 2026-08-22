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

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// Reading a directory of observations by eye is how a result gets quoted
// wrongly. This turns them into one table, ordered by the condition that was
// varied, so a trend is visible rather than asserted.

func newReportCmd() *cobra.Command {
	var (
		by      string
		metrics []string
		gauges  []string
	)

	cmd := &cobra.Command{
		Use:   "report <observation.json>...",
		Short: "Turn recorded observations into a table",
		Long: "Reads observations written by `sam-bench run` and renders them as a Markdown\n" +
			"table, ordered by the label that was varied across the runs.",
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			observations, err := load(args)
			if err != nil {
				return err
			}
			sortBy(observations, by)
			_, err = fmt.Fprint(cmd.OutOrStdout(), render(observations, by, metrics, gauges))
			return err
		},
	}

	cmd.Flags().StringVar(&by, "by", "agents", "Label the runs varied, used to order the rows")
	cmd.Flags().StringArrayVar(&metrics, "metric", nil, "Counter to include as a column, as the difference across the run; repeatable")
	cmd.Flags().StringArrayVar(&gauges, "gauge", nil, "Gauge to include as total and per-source columns, as read after the run; repeatable")
	return cmd
}

func load(paths []string) ([]observation, error) {
	out := make([]observation, 0, len(paths))
	for _, path := range paths {
		raw, err := os.ReadFile(path) // #nosec G304 -- the operator names their own result files
		if err != nil {
			return nil, err
		}
		var obs observation
		if err := json.Unmarshal(raw, &obs); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if obs.Report == nil {
			return nil, fmt.Errorf("%s: no report in observation", path)
		}
		out = append(out, obs)
	}
	return out, nil
}

// sortBy orders rows by the varied label, numerically where it is a number so
// that 8 agents comes before 64 rather than after it.
func sortBy(observations []observation, label string) {
	sort.SliceStable(observations, func(i, j int) bool {
		a, b := observations[i].Labels[label], observations[j].Labels[label]
		na, aerr := strconv.ParseFloat(a, 64)
		nb, berr := strconv.ParseFloat(b, 64)
		if aerr == nil && berr == nil {
			return na < nb
		}
		return a < b
	})
}

func render(observations []observation, by string, metrics, gauges []string) string {
	header := []string{by, "requests", "conc", "ok", "failed", "rps", "ttfb p50", "ttfb p95", "ttfb p99", "ttfb max"}
	header = append(header, metrics...)
	for _, g := range gauges {
		header = append(header, g+" total", g+" each")
	}

	rows := make([][]string, 0, len(observations))
	for _, obs := range observations {
		r := obs.Report
		row := []string{
			obs.Labels[by],
			strconv.Itoa(r.Requests),
			strconv.Itoa(r.Concurrency),
			strconv.Itoa(r.Succeeded),
			strconv.Itoa(r.Failed),
			fmt.Sprintf("%.0f", r.Throughput),
			ms(r.TTFB.P50),
			ms(r.TTFB.P95),
			ms(r.TTFB.P99),
			ms(r.TTFB.Max),
		}
		for _, m := range metrics {
			row = append(row, fmt.Sprintf("%.0f", delta(obs, m)))
		}
		for _, g := range gauges {
			total, sources := gauge(obs, g)
			row = append(row, fmt.Sprintf("%.0f", total))
			if sources == 0 {
				row = append(row, "-")
				continue
			}
			row = append(row, fmt.Sprintf("%.0f", total/float64(sources)))
		}
		rows = append(rows, row)
	}

	var b strings.Builder
	b.WriteString("| " + strings.Join(header, " | ") + " |\n")
	b.WriteString("|" + strings.Repeat(" --- |", len(header)) + "\n")
	for _, row := range rows {
		b.WriteString("| " + strings.Join(row, " | ") + " |\n")
	}
	return b.String()
}

// gauge totals a series across sources as read after the run, and says how
// many sources reported it. A gauge is a level rather than an accumulation, so
// unlike a counter its difference across the run means nothing.
func gauge(obs observation, series string) (total float64, sources int) {
	for _, after := range obs.After {
		value, ok := after[series]
		if !ok {
			continue
		}
		total += value
		sources++
	}
	return total, sources
}

// delta is how much a series moved across the run, summed over every scrape
// source. Counters are cumulative, so the difference is the only figure that
// describes the run rather than the process's whole life.
func delta(obs observation, series string) float64 {
	var total float64
	for source, after := range obs.After {
		total += after[series] - obs.Before[source][series]
	}
	return total
}

func ms(v float64) string { return strconv.FormatFloat(v, 'f', 2, 64) }
