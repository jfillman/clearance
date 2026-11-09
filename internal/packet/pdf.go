package packet

import (
	"bytes"
	"fmt"
	"strings"
	"unicode/utf8"
)

// A deliberately small PDF writer: text pages in the two standard fixed-width fonts, nothing else, standard library
// only. PDF 1.4 (ISO 32000-1) defines Courier and Courier-Bold as standard 14 fonts that every conforming reader has,
// so no font is embedded; because every glyph is 600 units wide, line wrapping is exact with no metrics table. The
// output is deterministic (no creation date, no random ids), so the same packet renders to the same bytes. Text is
// WinAnsi: Latin-1 passes through and any other rune is written as "?".
//
// A packet is a record, not a brochure: the PDF is its legible presentation, and the JSON is canonical.

const (
	pageW, pageH = 595.28, 841.89 // A4 in points
	margin       = 40.0
	bodySize     = 8.0
	lead         = 10.0
	charW        = 0.6 // Courier glyph width in em
)

// cols is how many characters fit on a line at bodySize.
var cols = func() int { w, f := pageW-2*margin, bodySize*charW; return int(w / f) }()

type line struct {
	text string
	bold bool
	size float64
}

type pdfDoc struct {
	title  string
	lines  []line
	pageOf []int
}

func newPDF(title string) *pdfDoc { return &pdfDoc{title: title} }

func (d *pdfDoc) emit(text string, bold bool, size float64) {
	d.lines = append(d.lines, line{text, bold, size})
}

// wrap breaks s into lines of at most width runes, on spaces where it can.
func wrap(s string, width int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		para = strings.TrimRight(para, " \t\r")
		if para == "" {
			out = append(out, "")
			continue
		}
		indent := len(para) - len(strings.TrimLeft(para, " "))
		pad := strings.Repeat(" ", min(indent, width/2))
		for utf8.RuneCountInString(para) > width {
			r := []rune(para)
			cut := width
			if i := strings.LastIndex(string(r[:width+1]), " "); i > indent {
				cut = utf8.RuneCountInString(string(r[:width+1])[:i])
			}
			out = append(out, string(r[:cut]))
			para = pad + strings.TrimLeft(string(r[cut:]), " ")
		}
		out = append(out, para)
	}
	return out
}

func (d *pdfDoc) h1(s string) {
	d.blank()
	d.emit(strings.ToUpper(s), true, 11)
	d.emit(strings.Repeat("=", cols), false, bodySize)
}
func (d *pdfDoc) h2(s string) { d.blank(); d.emit(s, true, 9) }
func (d *pdfDoc) blank()      { d.emit("", false, bodySize) }
func (d *pdfDoc) para(s string) {
	for _, l := range wrap(s, cols) {
		d.emit(l, false, bodySize)
	}
}
func (d *pdfDoc) bold(s string) {
	for _, l := range wrap(s, cols) {
		d.emit(l, true, bodySize)
	}
}

// kv prints "key: value" with the value wrapped under itself.
func (d *pdfDoc) kv(k, v string) {
	prefix := k + ": "
	w := cols - len(prefix)
	if w < 20 {
		d.para(prefix + v)
		return
	}
	for i, l := range wrap(v, w) {
		if i == 0 {
			d.emit(prefix+l, false, bodySize)
		} else {
			d.emit(strings.Repeat(" ", len(prefix))+l, false, bodySize)
		}
	}
}

// table prints rows in columns of the given widths (characters; the last takes what is left when 0), each cell wrapped.
func (d *pdfDoc) table(header []string, widths []int, rows [][]string) {
	used := 0
	for _, w := range widths {
		used += w + 1
	}
	for i, w := range widths {
		if w == 0 {
			widths[i] = max(cols-used-1, 10)
		}
	}
	row := func(cells []string, bold bool) {
		wrapped := make([][]string, len(cells))
		n := 1
		for i, c := range cells {
			wrapped[i] = wrap(c, widths[i])
			n = max(n, len(wrapped[i]))
		}
		for k := 0; k < n; k++ {
			var sb strings.Builder
			for i := range cells {
				cell := ""
				if k < len(wrapped[i]) {
					cell = wrapped[i][k]
				}
				if i < len(cells)-1 {
					sb.WriteString(fmt.Sprintf("%-*s ", widths[i], padRunes(cell, widths[i])))
				} else {
					sb.WriteString(cell)
				}
			}
			d.emit(strings.TrimRight(sb.String(), " "), bold, bodySize)
		}
	}
	row(header, true)
	d.emit(strings.Repeat("-", cols), false, bodySize)
	for _, r := range rows {
		row(r, false)
	}
	if len(rows) == 0 {
		d.emit("(none)", false, bodySize)
	}
}

func padRunes(s string, w int) string {
	if utf8.RuneCountInString(s) > w {
		return string([]rune(s)[:w])
	}
	return s
}

// winAnsi is s as WinAnsi bytes, escaped for a PDF literal string.
func winAnsi(s string) []byte {
	var b bytes.Buffer
	for _, r := range s {
		switch {
		case r == '(' || r == ')' || r == '\\':
			b.WriteByte('\\')
			b.WriteByte(byte(r))
		case r >= 0x20 && r < 0x7f, r >= 0xa0 && r <= 0xff:
			b.WriteByte(byte(r))
		default:
			if r == '\t' {
				b.WriteString("    ")
			} else {
				b.WriteByte('?')
			}
		}
	}
	return b.Bytes()
}

// bytes renders the document.
func (d *pdfDoc) bytes() []byte {
	usable := pageH - 2*margin - 14 // a footer line below the text
	perPage := int(usable / lead)
	var pages [][]line
	for i := 0; i < len(d.lines); i += perPage {
		pages = append(pages, d.lines[i:min(i+perPage, len(d.lines))])
	}
	if len(pages) == 0 {
		pages = [][]line{{}}
	}
	var out bytes.Buffer
	offs := []int{}
	obj := func(body string) {
		offs = append(offs, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", len(offs), body)
	}
	out.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	// 1 catalog, 2 pages, 3 and 4 fonts, 5 info, then a page object and a content stream per page.
	kids := make([]string, len(pages))
	for i := range pages {
		kids[i] = fmt.Sprintf("%d 0 R", 6+2*i)
	}
	obj("<< /Type /Catalog /Pages 2 0 R >>")
	obj(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(pages)))
	obj("<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")
	obj("<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold /Encoding /WinAnsiEncoding >>")
	obj("<< /Title (" + string(winAnsi(d.title)) + ") /Producer (clearance) >>")
	for i, pg := range pages {
		var cs bytes.Buffer
		y := pageH - margin - bodySize
		for _, l := range pg {
			if l.text != "" {
				f := "F1"
				if l.bold {
					f = "F2"
				}
				fmt.Fprintf(&cs, "BT /%s %.1f Tf %.2f %.2f Td (", f, l.size, margin, y)
				cs.Write(winAnsi(l.text))
				cs.WriteString(") Tj ET\n")
			}
			y -= lead
		}
		foot := fmt.Sprintf("%s - page %d of %d", d.title, i+1, len(pages))
		fmt.Fprintf(&cs, "BT /F1 7 Tf %.2f %.2f Td (", margin, margin/2)
		cs.Write(winAnsi(foot))
		cs.WriteString(") Tj ET\n")
		obj(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>",
			pageW, pageH, 7+2*i))
		obj(fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", cs.Len(), cs.String()))
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(offs)+1)
	for _, o := range offs {
		fmt.Fprintf(&out, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R /Info 5 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offs)+1, xref)
	return out.Bytes()
}
