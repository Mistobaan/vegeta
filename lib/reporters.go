package vegeta

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"text/tabwriter"
	"text/template"
)

// Reporter is an interface defining Report computation.
type Reporter interface {
	Report(Results) ([]byte, error)
}

// ReporterFunc is an adapter to allow the use of ordinary functions as
// Reporters. If f is a function with the appropriate signature, ReporterFunc(f)
// is a Reporter object that calls f.
type ReporterFunc func(Results) ([]byte, error)

// Report implements the Reporter interface.
func (f ReporterFunc) Report(r Results) ([]byte, error) { return f(r) }

// ReportText returns a computed Metrics struct as aligned, formatted text.
var ReportText ReporterFunc = func(r Results) ([]byte, error) {
	m := NewMetrics(r)
	out := &bytes.Buffer{}

	w := tabwriter.NewWriter(out, 0, 8, 2, '\t', tabwriter.StripEscape)
	fmt.Fprintf(w, "Requests\t[total]\t%d\n", m.Requests)
	fmt.Fprintf(w, "Duration\t[total, attack, wait]\t%s, %s, %s\n", m.Duration+m.Wait, m.Duration, m.Wait)
	fmt.Fprintf(w, "Latencies\t[mean, 50, 95, 99, max]\t%s, %s, %s, %s, %s\n",
		m.Latencies.Mean, m.Latencies.P50, m.Latencies.P95, m.Latencies.P99, m.Latencies.Max)
	fmt.Fprintf(w, "Bytes In\t[total, mean]\t%d, %.2f\n", m.BytesIn.Total, m.BytesIn.Mean)
	fmt.Fprintf(w, "Bytes Out\t[total, mean]\t%d, %.2f\n", m.BytesOut.Total, m.BytesOut.Mean)
	fmt.Fprintf(w, "Success\t[ratio]\t%.2f%%\n", m.Success*100)
	fmt.Fprintf(w, "Status Codes\t[code:count]\t")
	for code, count := range m.StatusCodes {
		fmt.Fprintf(w, "%s:%d  ", code, count)
	}
	fmt.Fprintln(w, "\nError Set:")
	for _, err := range m.Errors {
		fmt.Fprintln(w, err)
	}

	if err := w.Flush(); err != nil {
		return []byte{}, err
	}
	return out.Bytes(), nil
}

// ReportJSON writes a computed Metrics struct to as JSON
var ReportJSON ReporterFunc = func(r Results) ([]byte, error) {
	return json.Marshal(NewMetrics(r))
}

// ReportPlot builds up a self contained HTML page with an interactive plot
// of the latencies of the requests. Built with http://dygraphs.com/
var ReportPlot ReporterFunc = func(r Results) ([]byte, error) {
	series := &bytes.Buffer{}
	for i, point := 0, ""; i < len(r); i++ {
		point = "[" + strconv.FormatFloat(
			r[i].Timestamp.Sub(r[0].Timestamp).Seconds(), 'f', -1, 32) + ","

		if r[i].Error == "" {
			point += "NaN," + strconv.FormatFloat(r[i].Latency.Seconds()*1000, 'f', -1, 32) + "],"
		} else {
			point += strconv.FormatFloat(r[i].Latency.Seconds()*1000, 'f', -1, 32) + ",NaN],"
		}

		series.WriteString(point)
	}
	// Remove trailing commas
	if series.Len() > 0 {
		series.Truncate(series.Len() - 1)
	}

	var out bytes.Buffer

	ctx := struct {
		JsSrc   string
		Series  string
		Results Results
	}{
		JsSrc:   string(dygraphJSLibSrc()),
		Series:  series.String(),
		Results: r,
	}

	err := plotsTemplate.Execute(&out, ctx)
	if err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

var plotsTemplate *template.Template = template.Must(template.New("plot").Parse(`<!doctype>
<html>
<head>
  <title>Vegeta Plots</title>
</head>
<body>
  <div id="latencies" style="font-family: Courier; width: 100%%; height: 600px"></div>
  <a href="#" download="vegetaplot.png" onclick="this.href = document.getElementsByTagName('canvas')[0].toDataURL('image/png').replace(/^data:image\/[^;]/, 'data:application/octet-stream')">Download as PNG</a>
  <script>
	{{.JsSrc}}
  </script>
  <script>
  var g = new Dygraph(
    document.getElementById("latencies"),
    [{{.Series}}],
    {
      title: 'Vegeta Plot',
      labels: ['Seconds', 'ERR', 'OK'],
      ylabel: 'Latency (ms)',
      xlabel: 'Seconds elapsed',
      showRoller: true,
      colors: ['#FA7878', '#8AE234'],
      legend: 'always',
      logscale: true,
      strokeWidth: 1.3,
      showRangeSelector: true,
      rangeSelectorHeight: 30,
      zoomCallback: function(minX, maxX, yRanges) {
        var table = document.getElementsByTagName('table')[0];
        filterTable("flash", table)
      }
    }
  );

  g.ready(function() {
    console.log("Data loaded. x-axis range is:", g.xAxisRange());
  });

  function filterTable(term, table) {

    var terms = term.toLowerCase().split(" ");
    for (var r = 1; r < table.rows.length; r++) {
      var display = '';
      for (var i = 0; i < terms.length; i++) {
        if (table.rows[r].innerHTML.replace(/<[^>]+>/g, "").toLowerCase().indexOf(terms[i]) < 0) {
          display = 'none';
        }
        table.rows[r].style.display = display;
      }
    }
  }

  </script>
</body>
<table style="text:align-center">
  <tr>
    <th>Timestamp</th>
    <th>Return Code</th>
    <th>Method </th>
    <th>URL </th>
    <th>In (bytes)</th>
    <th>Out (bytes)</th>
  </tr>
  {{range .Results}}
    <tr bgcolor="{{ if eq .Code 200 }} #8AE234 {{else}} #FA7878 {{end}}" >
    <td align="center" valign="middle">{{.Timestamp}}</td>
    <td align="center" valign="middle">{{.Code}}</td>
    <td align="center" valign="middle">{{.Request.Method}}</td>
    <td align="left" valign="middle"><a href="{{.Request.URL}}">{{.Request.URL}}</a></td>
    <td align="center" valign="middle">{{.BytesIn}}</td>
    <td align="center" valign="middle">{{.BytesOut}}</td>
    </tr>
  {{ else }}
   <tr><b>No Results found</b></tr>
  {{end}}
  </table>
</html>`))
