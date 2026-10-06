package space

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

// A minimal, strict RFC 8941 (structured field values) parser and serializer,
// covering what HTTP message signatures need: dictionaries whose members are
// items or inner lists, with parameters.

type sfToken string

type sfBytes []byte

type sfParam struct {
	Key   string
	Value any // bool, int64, float64, string, sfToken, sfBytes
}

type sfParams []sfParam

func (p sfParams) get(key string) (any, bool) {
	for _, kv := range p {
		if kv.Key == key {
			return kv.Value, true
		}
	}
	return nil, false
}

type sfItem struct {
	Value  any
	Params sfParams
}

type sfInnerList struct {
	Items  []sfItem
	Params sfParams
}

// sfMember is either sfItem or sfInnerList.
type sfMember any

var errSF = errors.New("invalid structured field")

type sfParser struct {
	s   string
	pos int
}

func (p *sfParser) eof() bool  { return p.pos >= len(p.s) }
func (p *sfParser) peek() byte { return p.s[p.pos] }

func (p *sfParser) skipSP() {
	for !p.eof() && p.peek() == ' ' {
		p.pos++
	}
}

func (p *sfParser) skipOWS() {
	for !p.eof() && (p.peek() == ' ' || p.peek() == '\t') {
		p.pos++
	}
}

// parseSFDictionary parses a dictionary. Duplicate keys keep the last value,
// as RFC 8941 requires.
func parseSFDictionary(s string) (map[string]sfMember, error) {
	p := &sfParser{s: strings.Trim(s, " ")}
	out := map[string]sfMember{}
	if p.eof() {
		return out, nil
	}
	for {
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		var m sfMember
		if !p.eof() && p.peek() == '=' {
			p.pos++
			m, err = p.parseItemOrInnerList()
			if err != nil {
				return nil, err
			}
		} else {
			params, err := p.parseParams()
			if err != nil {
				return nil, err
			}
			m = sfItem{Value: true, Params: params}
		}
		out[key] = m
		p.skipOWS()
		if p.eof() {
			return out, nil
		}
		if p.peek() != ',' {
			return nil, errSF
		}
		p.pos++
		p.skipOWS()
		if p.eof() {
			return nil, errSF
		}
	}
}

func (p *sfParser) parseItemOrInnerList() (sfMember, error) {
	if !p.eof() && p.peek() == '(' {
		return p.parseInnerList()
	}
	return p.parseItem()
}

func (p *sfParser) parseInnerList() (sfInnerList, error) {
	p.pos++ // (
	var l sfInnerList
	for !p.eof() {
		p.skipSP()
		if p.eof() {
			break
		}
		if p.peek() == ')' {
			p.pos++
			params, err := p.parseParams()
			if err != nil {
				return l, err
			}
			l.Params = params
			return l, nil
		}
		it, err := p.parseItem()
		if err != nil {
			return l, err
		}
		l.Items = append(l.Items, it)
		if p.eof() || (p.peek() != ' ' && p.peek() != ')') {
			return l, errSF
		}
	}
	return l, errSF
}

func (p *sfParser) parseItem() (sfItem, error) {
	v, err := p.parseBareItem()
	if err != nil {
		return sfItem{}, err
	}
	params, err := p.parseParams()
	if err != nil {
		return sfItem{}, err
	}
	return sfItem{Value: v, Params: params}, nil
}

func (p *sfParser) parseParams() (sfParams, error) {
	var out sfParams
	for !p.eof() && p.peek() == ';' {
		p.pos++
		p.skipSP()
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		var v any = true
		if !p.eof() && p.peek() == '=' {
			p.pos++
			v, err = p.parseBareItem()
			if err != nil {
				return nil, err
			}
		}
		replaced := false
		for i := range out {
			if out[i].Key == key {
				out[i].Value = v
				replaced = true
			}
		}
		if !replaced {
			out = append(out, sfParam{Key: key, Value: v})
		}
	}
	return out, nil
}

func isLcalpha(c byte) bool { return c >= 'a' && c <= 'z' }
func isDigit(c byte) bool   { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool   { return isLcalpha(c) || (c >= 'A' && c <= 'Z') }

func (p *sfParser) parseKey() (string, error) {
	if p.eof() || !(isLcalpha(p.peek()) || p.peek() == '*') {
		return "", errSF
	}
	start := p.pos
	for !p.eof() {
		c := p.peek()
		if isLcalpha(c) || isDigit(c) || c == '_' || c == '-' || c == '.' || c == '*' {
			p.pos++
			continue
		}
		break
	}
	return p.s[start:p.pos], nil
}

func isTchar(c byte) bool {
	return isAlpha(c) || isDigit(c) || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

func (p *sfParser) parseBareItem() (any, error) {
	if p.eof() {
		return nil, errSF
	}
	c := p.peek()
	switch {
	case c == '-' || isDigit(c):
		return p.parseNumber()
	case c == '"':
		return p.parseString()
	case c == ':':
		return p.parseByteSeq()
	case c == '?':
		p.pos++
		if p.eof() {
			return nil, errSF
		}
		switch p.peek() {
		case '1':
			p.pos++
			return true, nil
		case '0':
			p.pos++
			return false, nil
		}
		return nil, errSF
	case isAlpha(c) || c == '*':
		start := p.pos
		for !p.eof() && (isTchar(p.peek()) || p.peek() == ':' || p.peek() == '/') {
			p.pos++
		}
		return sfToken(p.s[start:p.pos]), nil
	}
	return nil, errSF
}

func (p *sfParser) parseNumber() (any, error) {
	start := p.pos
	if p.peek() == '-' {
		p.pos++
	}
	digits, dec := 0, false
	for !p.eof() {
		c := p.peek()
		if isDigit(c) {
			digits++
			p.pos++
		} else if c == '.' && !dec {
			dec = true
			p.pos++
		} else {
			break
		}
	}
	num := p.s[start:p.pos]
	if digits == 0 || strings.HasSuffix(num, ".") || (!dec && digits > 15) {
		return nil, errSF
	}
	if dec {
		f, err := strconv.ParseFloat(num, 64)
		if err != nil {
			return nil, errSF
		}
		return f, nil
	}
	i, err := strconv.ParseInt(num, 10, 64)
	if err != nil {
		return nil, errSF
	}
	return i, nil
}

func (p *sfParser) parseString() (string, error) {
	p.pos++ // "
	var b strings.Builder
	for !p.eof() {
		c := p.peek()
		p.pos++
		switch {
		case c == '\\':
			if p.eof() {
				return "", errSF
			}
			n := p.peek()
			if n != '"' && n != '\\' {
				return "", errSF
			}
			b.WriteByte(n)
			p.pos++
		case c == '"':
			return b.String(), nil
		case c < 0x20 || c > 0x7e:
			return "", errSF
		default:
			b.WriteByte(c)
		}
	}
	return "", errSF
}

func (p *sfParser) parseByteSeq() (sfBytes, error) {
	p.pos++ // :
	end := strings.IndexByte(p.s[p.pos:], ':')
	if end < 0 {
		return nil, errSF
	}
	enc := p.s[p.pos : p.pos+end]
	p.pos += end + 1
	for i := 0; i < len(enc); i++ {
		c := enc[i]
		if !(isAlpha(c) || isDigit(c) || c == '+' || c == '/' || c == '=') {
			return nil, errSF
		}
	}
	// RFC 8941 lets a parser accept a missing pad.
	b, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(enc, "="))
		if err != nil {
			return nil, errSF
		}
	}
	return sfBytes(b), nil
}

func serializeSFBareItem(v any) string {
	switch x := v.(type) {
	case bool:
		if x {
			return "?1"
		}
		return "?0"
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		s := strconv.FormatFloat(x, 'f', -1, 64)
		if !strings.Contains(s, ".") {
			s += ".0"
		}
		return s
	case string:
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(x) + `"`
	case sfToken:
		return string(x)
	case sfBytes:
		return ":" + base64.StdEncoding.EncodeToString(x) + ":"
	}
	return ""
}

func serializeSFParams(ps sfParams) string {
	var b strings.Builder
	for _, kv := range ps {
		b.WriteString(";" + kv.Key)
		if t, ok := kv.Value.(bool); ok && t {
			continue
		}
		b.WriteString("=" + serializeSFBareItem(kv.Value))
	}
	return b.String()
}

func serializeSFItem(it sfItem) string {
	return serializeSFBareItem(it.Value) + serializeSFParams(it.Params)
}

func serializeSFInnerList(l sfInnerList) string {
	parts := make([]string, len(l.Items))
	for i, it := range l.Items {
		parts[i] = serializeSFItem(it)
	}
	return "(" + strings.Join(parts, " ") + ")" + serializeSFParams(l.Params)
}
